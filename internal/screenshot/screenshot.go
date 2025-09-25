// Package screenshot provides HTTP page screenshot functionality
package screenshot

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/lesydimitri/sniffl/internal/config"
	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/lesydimitri/sniffl/internal/logging"
	"github.com/lesydimitri/sniffl/internal/retry"
	"github.com/lesydimitri/sniffl/internal/shared"
)

// ScreenshotApp handles screenshot operations
type ScreenshotApp struct {
	config      *config.Config
	logger      *logging.Logger
	retryConfig retry.Config
}

// ScreenshotTarget represents a target for screenshot capture
type ScreenshotTarget struct {
	URL      string
	Host     string
	Port     int
	Protocol string // http or https
}

// ScreenshotResult represents the result of a screenshot operation
type ScreenshotResult struct {
	Target    ScreenshotTarget
	FilePath  string
	Success   bool
	Error     error
	Duration  time.Duration
	Timestamp time.Time
}

// ScreenshotOptions contains options for screenshot operations
type ScreenshotOptions struct {
	OutputDir       string
	Timeout         time.Duration
	ViewportWidth   int
	ViewportHeight  int
	FullPage        bool
	WaitTime        time.Duration
	UserAgent       string
	Concurrency     int
	Ports           []int
	DryRun          bool
	ChromePath      string
	AutoDownload    bool
	SkipPortCheck   bool
	IgnoreSSLErrors bool
}

// DefaultScreenshotOptions returns default screenshot options
func DefaultScreenshotOptions() *ScreenshotOptions {
	return &ScreenshotOptions{
		OutputDir:       "screenshots",
		Timeout:         30 * time.Second,
		ViewportWidth:   1920,
		ViewportHeight:  1080,
		FullPage:        true,
		WaitTime:        2 * time.Second,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Concurrency:     5,
		Ports:           []int{80, 443, 8080, 8443},
		DryRun:          false,
		AutoDownload:    true,
		SkipPortCheck:   false,
		IgnoreSSLErrors: true, // Default to true for network reconnaissance
	}
}

// NewScreenshotApp creates a new screenshot application instance
func NewScreenshotApp(cfg *config.Config, logger *logging.Logger) *ScreenshotApp {
	retryConfig := retry.Config{
		MaxAttempts: cfg.RetryAttempts,
		BaseDelay:   cfg.RetryDelay,
		MaxDelay:    30 * time.Second,
		Multiplier:  2.0,
		Jitter:      true,
	}

	return &ScreenshotApp{
		config:      cfg,
		logger:      logger,
		retryConfig: retryConfig,
	}
}

// ProcessTargets processes a list of targets for screenshots
func (app *ScreenshotApp) ProcessTargets(ctx context.Context, targets []ScreenshotTarget, opts *ScreenshotOptions) ([]ScreenshotResult, error) {
	if len(targets) == 0 {
		return nil, errors.NewValidationError("no targets provided")
	}

	// Ensure output directory exists
	if !opts.DryRun {
		if err := os.MkdirAll(opts.OutputDir, config.DirPermissions); err != nil {
			return nil, errors.WrapFileError("failed to create output directory", err)
		}
	}

	// Handle dry-run mode with proper output format
	if opts.DryRun {
		fmt.Println("=== DRY RUN MODE ===")
		fmt.Printf("Would take screenshots of %d target(s):\n", len(targets))

		// Show first 10 targets, then summarize if more
		maxShow := 10
		for i, target := range targets {
			if i >= maxShow {
				fmt.Printf("  ... and %d more targets\n", len(targets)-maxShow)
				break
			}
			filename := app.generateFilename(target)
			outputPath := filepath.Join(opts.OutputDir, filename)
			fmt.Printf("  %d. %s -> %s\n", i+1, target.URL, outputPath)
		}

		fmt.Printf("\nConfiguration:\n")
		fmt.Printf("  Output directory: %s\n", opts.OutputDir)
		fmt.Printf("  Timeout: %s\n", opts.Timeout)
		fmt.Printf("  Viewport: %dx%d\n", opts.ViewportWidth, opts.ViewportHeight)
		fmt.Printf("  Concurrency: %d\n", opts.Concurrency)
		fmt.Printf("  Port checking: %s\n", map[bool]string{true: "disabled", false: "enabled"}[opts.SkipPortCheck])
		fmt.Printf("  SSL errors: %s\n", map[bool]string{true: "ignored", false: "strict"}[opts.IgnoreSSLErrors])
		fmt.Println("=== END DRY RUN ===")

		// Create fake results for dry-run
		results := make([]ScreenshotResult, len(targets))
		for i, target := range targets {
			filename := app.generateFilename(target)
			results[i] = ScreenshotResult{
				Target:    target,
				FilePath:  filepath.Join(opts.OutputDir, filename),
				Success:   true,
				Duration:  0,
				Timestamp: time.Now(),
			}
		}
		return results, nil
	}

	// Always show basic progress to user
	if len(targets) == 1 {
		fmt.Printf("Taking screenshot of %s...\n", targets[0].URL)
	} else {
		fmt.Printf("Taking screenshots of %d targets", len(targets))
		if opts.Concurrency > 1 {
			fmt.Printf(" (concurrency: %d)", opts.Concurrency)
		}
		fmt.Println("...")
	}

	app.logger.Progress("Starting screenshot capture", "targets", len(targets), "concurrency", opts.Concurrency)

	// Create a semaphore to limit concurrency
	semaphore := make(chan struct{}, opts.Concurrency)
	results := make([]ScreenshotResult, len(targets))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var completed int

	// Track whether we've printed an inline progress line
	progressInline := len(targets) > 5 && !opts.DryRun
	var progressNewlineOnce sync.Once

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, tgt ScreenshotTarget) {
			defer wg.Done()

			// Fast exit if cancelled before work starts
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Acquire semaphore or exit on cancellation
			select {
			case semaphore <- struct{}{}:
				// acquired slot
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()

			result := app.captureScreenshot(ctx, tgt, opts)

			mu.Lock()
			results[idx] = result
			completed++
			currentCompleted := completed
			mu.Unlock()

			// Show progress for larger operations (>5 targets)
			if progressInline {
				fmt.Fprintf(os.Stderr, "\rProgress: %d/%d completed", currentCompleted, len(targets))
				if currentCompleted == len(targets) {
					fmt.Fprintln(os.Stderr) // New line when complete
				}
			}

			if result.Success {
				app.logger.Success("Screenshot captured", "target", tgt.URL, "file", result.FilePath, "duration", result.Duration)
			} else {
				if progressInline {
					// Ensure we break the inline progress line before logging errors
					progressNewlineOnce.Do(func() { fmt.Fprintln(os.Stderr) })
				}
				app.logger.Failure("Screenshot failed", "target", tgt.URL, "error", result.Error)
			}
		}(i, target)
	}

	wg.Wait()

	// Count successes and failures
	var successes, failures int
	for _, result := range results {
		if result.Success {
			successes++
		} else {
			failures++
		}
	}

	// Always show completion summary to user
	if failures == 0 {
		if len(targets) == 1 {
			fmt.Printf("✓ Screenshot saved to %s\n", opts.OutputDir)
		} else {
			fmt.Printf("✓ %d screenshots saved to %s\n", successes, opts.OutputDir)
		}
	} else {
		if successes > 0 {
			fmt.Printf("✓ %d screenshots saved, %d failed\n", successes, failures)
		} else {
			fmt.Printf("✗ All %d screenshots failed\n", failures)
		}
	}

	app.logger.Progress("Screenshot capture completed", "total", len(targets), "successes", successes, "failures", failures)

	return results, nil
}

// captureScreenshot captures a screenshot of a single target
func (app *ScreenshotApp) captureScreenshot(ctx context.Context, target ScreenshotTarget, opts *ScreenshotOptions) ScreenshotResult {
	start := time.Now()
	result := ScreenshotResult{
		Target:    target,
		Timestamp: start,
	}

	// Dry-run is handled at the ProcessTargets level, so this should never be reached in dry-run mode

	// Quick connectivity check first (especially important for CIDR scans)
	if !opts.SkipPortCheck && !app.isServiceReachable(target) {
		result.Error = fmt.Errorf("no service found at %s:%d", target.Host, target.Port)
		result.Success = false
		result.Duration = time.Since(start)
		app.logger.Network("Service not reachable", "target", target.URL, "duration", result.Duration)
		return result
	}

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Capture screenshot with retry logic
	err := retry.Do(timeoutCtx, app.retryConfig, app.logger, func() error {
		return app.doScreenshot(timeoutCtx, target, opts, &result)
	})

	result.Error = err
	result.Success = err == nil
	result.Duration = time.Since(start)

	return result
}

// isServiceReachable quickly checks if a service is reachable on the target host:port
func (app *ScreenshotApp) isServiceReachable(target ScreenshotTarget) bool {
	// Ultra-fast connect scan with very aggressive timeout
	// Network behavior:
	// - Closed ports: immediate RST response (~1-10ms)
	// - Open ports: immediate SYN-ACK response (~1-10ms)
	// - Filtered ports: timeout (only case that hits our limit)
	// - Unreachable hosts: ICMP unreachable (~1-50ms)

	timeout := 100 * time.Millisecond // Very aggressive for LAN scanning

	// For remote targets, use slightly longer timeout
	if !app.isLocalNetwork(target.Host) {
		timeout = 300 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// isLocalNetwork checks if the target appears to be on local network
func (app *ScreenshotApp) isLocalNetwork(host string) bool {
	// Quick heuristic: if it's an IP in private ranges or resolves quickly
	ip := net.ParseIP(host)
	if ip != nil {
		// Check for private IP ranges
		return ip.IsPrivate() || ip.IsLoopback()
	}

	// For hostnames, assume remote (could be optimized with DNS timing)
	return false
}

// doScreenshot performs the actual screenshot capture
func (app *ScreenshotApp) doScreenshot(ctx context.Context, target ScreenshotTarget, opts *ScreenshotOptions, result *ScreenshotResult) error {
	// Find Chrome executable
	var execPath string
	var err error

	if opts.ChromePath != "" {
		// Use user-specified Chrome path
		if _, err := os.Stat(opts.ChromePath); err != nil {
			return errors.WrapNetworkError("specified Chrome path not found", err)
		}
		execPath = opts.ChromePath
	} else {
		// Auto-detect Chrome
		execPath, err = FindChromeExecutableWithOptions(opts.AutoDownload)
		if err != nil {
			return errors.WrapNetworkError("Chrome/Chromium not found", err)
		}
	}

	// Build Chrome allocator options
	allocOptions := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(execPath),
		chromedp.NoSandbox,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.WindowSize(opts.ViewportWidth, opts.ViewportHeight),
		chromedp.UserAgent(opts.UserAgent),
	}

	// Add SSL-related flags if SSL errors should be ignored
	if opts.IgnoreSSLErrors {
		allocOptions = append(allocOptions,
			// Core SSL error ignoring
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.Flag("ignore-ssl-errors", true),
			chromedp.Flag("ignore-certificate-errors-spki-list", true),
			chromedp.Flag("ignore-certificate-errors-ssl-errors", true),
			chromedp.Flag("allow-running-insecure-content", true),
			chromedp.Flag("disable-web-security", true),

			// Additional SSL/TLS error handling
			chromedp.Flag("ignore-urlfetcher-cert-requests", true),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("disable-plugins", true),
			chromedp.Flag("disable-images", true),      // Reduce load, avoid mixed content issues
			chromedp.Flag("disable-javascript", false), // Keep JS for dynamic content

			// Network error tolerance
			chromedp.Flag("aggressive-cache-discard", true),
			chromedp.Flag("disable-background-networking", true),
			chromedp.Flag("disable-background-timer-throttling", true),
			chromedp.Flag("disable-renderer-backgrounding", true),
			chromedp.Flag("disable-backgrounding-occluded-windows", true),

			// SSL/TLS specific
			chromedp.Flag("allow-insecure-localhost", true),
			chromedp.Flag("disable-features", "VizDisplayCompositor"),
		)
	}

	// Create Chrome context with configured options
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, allocOptions...)
	defer cancel()

	chromeCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Generate filename
	filename := app.generateFilename(target)
	filepath := filepath.Join(opts.OutputDir, filename)
	result.FilePath = filepath

	var buf []byte

	// Navigate and capture screenshot
	tasks := chromedp.Tasks{
		chromedp.Navigate(target.URL),
		chromedp.Sleep(opts.WaitTime), // Wait for page to load
	}

	if opts.FullPage {
		tasks = append(tasks, chromedp.FullScreenshot(&buf, 90))
	} else {
		tasks = append(tasks, chromedp.CaptureScreenshot(&buf))
	}

	if err := chromedp.Run(chromeCtx, tasks); err != nil {
		// Check if this is an SSL error that we should handle gracefully
		if opts.IgnoreSSLErrors && isSSLError(err) {
			app.logger.Network("SSL error encountered, attempting fallback", "target", target.URL, "error", err.Error())

			// Try a simpler approach - just navigate and wait longer
			fallbackTasks := chromedp.Tasks{
				chromedp.Navigate(target.URL),
				chromedp.Sleep(opts.WaitTime * 2), // Wait longer for problematic sites
			}

			if opts.FullPage {
				fallbackTasks = append(fallbackTasks, chromedp.FullScreenshot(&buf, 90))
			} else {
				fallbackTasks = append(fallbackTasks, chromedp.CaptureScreenshot(&buf))
			}

			if err := chromedp.Run(chromeCtx, fallbackTasks); err != nil {
				return errors.WrapNetworkError("failed to capture screenshot after SSL fallback", err)
			}

			app.logger.Network("Screenshot captured despite SSL issues", "target", target.URL)
		} else {
			return errors.WrapNetworkError("failed to capture screenshot", err)
		}
	}

	// Save screenshot to file
	if err := os.WriteFile(filepath, buf, config.FilePermissions); err != nil {
		return errors.WrapFileError("failed to save screenshot", err)
	}

	return nil
}

// generateFilename generates a filename for the screenshot
func (app *ScreenshotApp) generateFilename(target ScreenshotTarget) string {
	// Sanitize the URL for filename
	sanitized := strings.ReplaceAll(target.Host, ".", "_")
	sanitized = strings.ReplaceAll(sanitized, ":", "_")

	timestamp := time.Now().Format("20060102_150405.000")

	return fmt.Sprintf("%s_%d_%s_%s.png", sanitized, target.Port, target.Protocol, timestamp)
}

// ParseCIDR parses a CIDR range and generates targets for specified ports
func ParseCIDR(cidr string, ports []int, protocols []string) ([]ScreenshotTarget, error) {
	if len(ports) == 0 {
		return nil, errors.NewValidationError("no ports specified for CIDR scan")
	}

	if len(protocols) == 0 {
		protocols = []string{"http", "https"}
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, errors.WrapValidationError("invalid CIDR format", err)
	}

	var targets []ScreenshotTarget

	// Iterate through all IPs in the CIDR range
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		// Skip network and broadcast addresses for /24 and smaller
		if ones, _ := ipNet.Mask.Size(); ones >= 24 {
			if ip.Equal(ipNet.IP) || ip.Equal(broadcast(ipNet)) {
				continue
			}
		}

		for _, port := range ports {
			for _, protocol := range protocols {
				// Skip invalid protocol/port combinations
				if (protocol == "http" && port == 443) || (protocol == "https" && port == 80) {
					continue
				}

				target := ScreenshotTarget{
					Host:     ip.String(),
					Port:     port,
					Protocol: protocol,
					URL:      fmt.Sprintf("%s://%s:%d", protocol, ip.String(), port),
				}
				targets = append(targets, target)
			}
		}
	}

	return targets, nil
}

// ParseTargetsFromFile parses targets from a file
func ParseTargetsFromFile(filename string) ([]ScreenshotTarget, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.WrapFileError("failed to open targets file", err)
	}
	defer file.Close()

	var screenshotTargets []ScreenshotTarget
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}

		hostPort := fields[0]
		if !shared.IsValidHostPort(hostPort) {
			continue // Skip invalid host:port entries
		}

		host, portStr, err := net.SplitHostPort(hostPort)
		if err != nil {
			continue // Skip invalid targets
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue // Skip invalid ports
		}

		// Determine protocol
		protocol := "http"
		if len(fields) > 1 {
			// Protocol specified explicitly
			specifiedProtocol := strings.ToLower(fields[1])
			if specifiedProtocol == "http" || specifiedProtocol == "https" {
				protocol = specifiedProtocol
			}
		} else {
			// Auto-detect based on port
			if port == 443 || port == 8443 {
				protocol = "https"
			}
		}

		screenshotTarget := ScreenshotTarget{
			Host:     host,
			Port:     port,
			Protocol: protocol,
			URL:      fmt.Sprintf("%s://%s:%d", protocol, host, port),
		}
		screenshotTargets = append(screenshotTargets, screenshotTarget)
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.WrapFileError("failed to read targets file", err)
	}

	return screenshotTargets, nil
}

// ParseSingleTarget parses a single target URL or host:port
func ParseSingleTarget(target string) (ScreenshotTarget, error) {
	// Try parsing as URL first
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil {
			return ScreenshotTarget{}, errors.WrapValidationError("invalid URL format", err)
		}

		host := u.Hostname()
		port := 80
		if u.Port() != "" {
			var err error
			port, err = strconv.Atoi(u.Port())
			if err != nil {
				return ScreenshotTarget{}, errors.WrapValidationError("invalid port in URL", err)
			}
		} else if u.Scheme == "https" {
			port = 443
		}

		return ScreenshotTarget{
			Host:     host,
			Port:     port,
			Protocol: u.Scheme,
			URL:      target,
		}, nil
	}

	// Try parsing as host:port
	if shared.IsValidHostPort(target) {
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			return ScreenshotTarget{}, errors.WrapValidationError("invalid host:port format", err)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return ScreenshotTarget{}, errors.WrapValidationError("invalid port number", err)
		}

		// Determine protocol based on port
		protocol := "http"
		if port == 443 || port == 8443 {
			protocol = "https"
		}

		url := fmt.Sprintf("%s://%s:%d", protocol, host, port)

		return ScreenshotTarget{
			Host:     host,
			Port:     port,
			Protocol: protocol,
			URL:      url,
		}, nil
	}

	return ScreenshotTarget{}, errors.NewValidationError("target must be a URL or host:port format")
}

// Helper functions for CIDR iteration
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func broadcast(ipNet *net.IPNet) net.IP {
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)
	for i := 0; i < len(ip); i++ {
		ip[i] |= ^ipNet.Mask[i]
	}
	return ip
}

// FindChromeExecutable attempts to find Chrome or Chromium executable with auto-download enabled
func FindChromeExecutable() (string, error) {
	return FindChromeExecutableWithOptions(true)
}

// FindChromeExecutableWithOptions attempts to find Chrome or Chromium executable with configurable auto-download
func FindChromeExecutableWithOptions(autoDownload bool) (string, error) {
	// List of possible Chrome/Chromium executable names and paths
	var candidates []string

	switch runtime.GOOS {
	case "darwin": // macOS
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
			"/usr/bin/google-chrome",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/opt/homebrew/bin/chromium",
			"/usr/local/bin/chromium",
		}
	case "linux":
		candidates = []string{
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
			"/usr/bin/google-chrome-unstable",
			"/usr/bin/google-chrome-beta",
		}
	case "windows":
		candidates = []string{
			"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
			"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
			"C:\\Program Files\\Chromium\\Application\\chromium.exe",
			"C:\\Program Files (x86)\\Chromium\\Application\\chromium.exe",
		}
	}

	// Also try to find in PATH
	pathCandidates := []string{
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"chrome",
	}

	// Check PATH first
	for _, name := range pathCandidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}

	// Check specific paths
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// If no Chrome/Chromium found, try to download portable Chromium (if enabled)
	if autoDownload {
		return downloadPortableChromium()
	}

	return "", fmt.Errorf("Chrome or Chromium executable not found. Please install Chrome/Chromium or ensure it's in your PATH. Tried: %v", append(pathCandidates, candidates...))
}

// downloadPortableChromium downloads a portable Chromium binary to the cache directory
func downloadPortableChromium() (string, error) {
	// Get cache directory
	cacheDir, err := getCacheDir()
	if err != nil {
		return "", fmt.Errorf("failed to get cache directory: %w", err)
	}

	chromiumDir := filepath.Join(cacheDir, "chromium")
	var executablePath string

	switch runtime.GOOS {
	case "linux":
		executablePath = filepath.Join(chromiumDir, "chrome-linux", "chrome")
	case "darwin":
		executablePath = filepath.Join(chromiumDir, "chrome-mac", "Chromium.app", "Contents", "MacOS", "Chromium")
	case "windows":
		executablePath = filepath.Join(chromiumDir, "chrome-win", "chrome.exe")
	default:
		return "", fmt.Errorf("unsupported platform for auto-download: %s", runtime.GOOS)
	}

	// Check if already downloaded
	if _, err := os.Stat(executablePath); err == nil {
		return executablePath, nil
	}

	// Download Chromium
	fmt.Printf("Chrome/Chromium not found. Downloading portable Chromium...\n")

	downloadURL, err := getChromiumDownloadURL()
	if err != nil {
		return "", fmt.Errorf("failed to get Chromium download URL: %w", err)
	}

	if err := downloadAndExtractChromium(downloadURL, chromiumDir); err != nil {
		return "", fmt.Errorf("failed to download Chromium: %w", err)
	}

	// Verify the executable exists after download
	if _, err := os.Stat(executablePath); err != nil {
		return "", fmt.Errorf("Chromium executable not found after download: %s", executablePath)
	}

	// Make executable on Unix systems
	if runtime.GOOS != "windows" {
		if err := os.Chmod(executablePath, 0755); err != nil {
			return "", fmt.Errorf("failed to make Chromium executable: %w", err)
		}
	}

	fmt.Printf("✓ Chromium downloaded successfully\n")
	return executablePath, nil
}

// getCacheDir returns the cache directory for sniffl
func getCacheDir() (string, error) {
	var cacheDir string

	switch runtime.GOOS {
	case "darwin":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		cacheDir = filepath.Join(homeDir, "Library", "Caches", "sniffl")
	case "linux":
		if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
			cacheDir = filepath.Join(xdgCache, "sniffl")
		} else {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			cacheDir = filepath.Join(homeDir, ".cache", "sniffl")
		}
	case "windows":
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			cacheDir = filepath.Join(localAppData, "sniffl", "cache")
		} else {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			cacheDir = filepath.Join(homeDir, "AppData", "Local", "sniffl", "cache")
		}
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache directory: %w", err)
	}

	return cacheDir, nil
}

// getChromiumDownloadURL returns the download URL for the current platform
func getChromiumDownloadURL() (string, error) {
	// These are stable Chromium download URLs from the Chromium project
	baseURL := "https://storage.googleapis.com/chromium-browser-snapshots"

	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			return baseURL + "/Linux_x64/LAST_CHANGE", nil
		}
		return "", fmt.Errorf("unsupported Linux architecture: %s", runtime.GOARCH)
	case "darwin":
		if runtime.GOARCH == "amd64" {
			return baseURL + "/Mac/LAST_CHANGE", nil
		} else if runtime.GOARCH == "arm64" {
			return baseURL + "/Mac_Arm/LAST_CHANGE", nil
		}
		return "", fmt.Errorf("unsupported macOS architecture: %s", runtime.GOARCH)
	case "windows":
		if runtime.GOARCH == "amd64" {
			return baseURL + "/Win_x64/LAST_CHANGE", nil
		} else if runtime.GOARCH == "386" {
			return baseURL + "/Win/LAST_CHANGE", nil
		}
		return "", fmt.Errorf("unsupported Windows architecture: %s", runtime.GOARCH)
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// downloadAndExtractChromium downloads and extracts Chromium to the specified directory
func downloadAndExtractChromium(lastChangeURL, targetDir string) error {
	// Create HTTP client with timeouts
	httpClient := &http.Client{Timeout: 30 * time.Second}

	// First, get the latest revision number
	resp, err := httpClient.Get(lastChangeURL)
	if err != nil {
		return fmt.Errorf("failed to get latest Chromium revision: %w", err)
	}
	defer resp.Body.Close()

	revisionBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read revision response: %w", err)
	}
	revision := strings.TrimSpace(string(revisionBytes))

	// Construct download URL
	var downloadURL string
	baseURL := "https://storage.googleapis.com/chromium-browser-snapshots"

	switch runtime.GOOS {
	case "linux":
		downloadURL = fmt.Sprintf("%s/Linux_x64/%s/chrome-linux.zip", baseURL, revision)
	case "darwin":
		if runtime.GOARCH == "arm64" {
			downloadURL = fmt.Sprintf("%s/Mac_Arm/%s/chrome-mac.zip", baseURL, revision)
		} else {
			downloadURL = fmt.Sprintf("%s/Mac/%s/chrome-mac.zip", baseURL, revision)
		}
	case "windows":
		if runtime.GOARCH == "amd64" {
			downloadURL = fmt.Sprintf("%s/Win_x64/%s/chrome-win.zip", baseURL, revision)
		} else {
			downloadURL = fmt.Sprintf("%s/Win/%s/chrome-win.zip", baseURL, revision)
		}
	}

	fmt.Printf("Downloading Chromium revision %s (~150MB)...\n", revision)

	// Download the zip file
	resp, err = httpClient.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download Chromium: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download Chromium: HTTP %d", resp.StatusCode)
	}

	// Create temporary file
	tempFile, err := os.CreateTemp("", "chromium-*.zip")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Download to temp file
	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to download Chromium archive: %w", err)
	}

	// Close temp file before extraction
	tempFile.Close()

	// Extract the zip file
	fmt.Printf("Extracting Chromium...\n")
	if err := extractZip(tempFile.Name(), targetDir); err != nil {
		return fmt.Errorf("failed to extract Chromium: %w", err)
	}

	return nil
}

// extractZip extracts a zip file to the target directory
func extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	// Create destination directory
	if err := os.MkdirAll(dest, 0755); err != nil {
		return err
	}

	// Extract files
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return err
		}

		path := filepath.Join(dest, f.Name)

		// Check for ZipSlip vulnerability
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			rc.Close()
			return fmt.Errorf("invalid file path: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.FileInfo().Mode())
			rc.Close()
			continue
		}

		// Create file directory
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			rc.Close()
			return err
		}

		// Create file
		outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.FileInfo().Mode())
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}

	return nil
}

// isSSLError checks if the error is related to SSL/TLS certificate issues
func isSSLError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	sslErrors := []string{
		"ERR_SSL_UNRECOGNIZED_NAME_ALERT",
		"ERR_CERT_AUTHORITY_INVALID",
		"ERR_CERT_COMMON_NAME_INVALID",
		"ERR_CERT_DATE_INVALID",
		"ERR_CERT_INVALID",
		"ERR_SSL_PROTOCOL_ERROR",
		"ERR_SSL_VERSION_OR_CIPHER_MISMATCH",
		"ERR_CERT_UNABLE_TO_CHECK_REVOCATION",
		"ERR_CERT_REVOKED",
		"ERR_CERT_WEAK_SIGNATURE_ALGORITHM",
		"ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN",
		"ERR_CERT_SYMANTEC_LEGACY",
		"net::ERR_CERT",
		"net::ERR_SSL",
		"certificate",
		"ssl",
		"tls",
	}

	for _, sslErr := range sslErrors {
		if strings.Contains(strings.ToLower(errStr), strings.ToLower(sslErr)) {
			return true
		}
	}

	return false
}

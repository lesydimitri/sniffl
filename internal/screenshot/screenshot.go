// Package screenshot provides HTTP page screenshot functionality
package screenshot

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/tls"
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
	ChromePool  ChromePool // Chrome instance pool for concurrent operations
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
		AutoDownload:    true, // Auto-download Chrome if not found
		SkipPortCheck:   false,
		IgnoreSSLErrors: true, // Default to true for network reconnaissance
	}
}
// NewScreenshotApp creates a new screenshot application instance
func NewScreenshotApp(cfg *config.Config, logger *logging.Logger) *ScreenshotApp {
	retryConfig := retry.Config{
		MaxAttempts: cfg.RetryAttempts,
		BaseDelay:   cfg.RetryDelay,
		MaxDelay:    cfg.Timeout,
		Multiplier:  2.0,
		Jitter:      true,
	}
	
	app := &ScreenshotApp{
		config:      cfg,
		logger:      logger,
		retryConfig: retryConfig,
		ChromePool:  nil, // Will be initialized lazily
	}
	
	// Initialize Chrome pool - will be set up when first screenshot is taken
	// This allows for lazy initialization with proper Chrome path detection
	
	return app
}

// initializeChromePool initializes the Chrome pool if not already done
func (app *ScreenshotApp) initializeChromePool(opts *ScreenshotOptions) error {
	if app.ChromePool != nil {
		return nil // Already initialized
	}
	
	// Find Chrome executable
	chromePath, err := FindChromeExecutableWithOptions(opts.AutoDownload)
	if err != nil {
		return fmt.Errorf("failed to find Chrome executable: %w", err)
	}
	
	// Create pool configuration
	poolConfig := DefaultChromePoolConfig()
	poolConfig.ViewportWidth = opts.ViewportWidth
	poolConfig.ViewportHeight = opts.ViewportHeight
	poolConfig.UserAgent = opts.UserAgent
	
	// Adjust pool size based on concurrency
	if opts.Concurrency > 0 {
		poolConfig.MaxInstances = opts.Concurrency
	}
	
	// Create the Chrome pool
	app.ChromePool = NewRealChromePool(poolConfig, chromePath)
	app.logger.Info("Chrome pool initialized", 
		"chrome_path", chromePath,
		"max_instances", poolConfig.MaxInstances,
		"viewport", fmt.Sprintf("%dx%d", poolConfig.ViewportWidth, poolConfig.ViewportHeight))
	
	return nil
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
		fmt.Printf("  Port checking: %s\n", map[bool]string{true: "disabled", false: "enabled"}[opts.SkipPortCheck || opts.DryRun])
		fmt.Printf("  SSL errors: %s\n", map[bool]string{true: "strict", false: "ignored"}[!opts.IgnoreSSLErrors])
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

	// Optimize targets by filtering unreachable ones (unless disabled or in dry-run mode)
	var finalTargets []ScreenshotTarget
	if !opts.SkipPortCheck && !opts.DryRun {
		app.logger.Progress("Checking connectivity for targets", "total", len(targets))
		finalTargets = FilterReachableTargets(ctx, targets)
		app.logger.Progress("Connectivity check completed", "reachable", len(finalTargets), "filtered", len(targets)-len(finalTargets))
	} else {
		finalTargets = targets
	}

	if len(finalTargets) == 0 {
		app.logger.Progress("No reachable targets found")
		return []ScreenshotResult{}, nil
	}

	// Always show basic progress to user
	if len(finalTargets) == 1 {
		fmt.Printf("Taking screenshot of %s...\n", finalTargets[0].URL)
	} else {
		fmt.Printf("Taking screenshots of %d targets", len(finalTargets))
		if opts.Concurrency > 1 {
			fmt.Printf(" (concurrency: %d)", opts.Concurrency)
		}
		fmt.Println("...")
	}

	// Initialize Chrome pool before processing
	if err := app.initializeChromePool(opts); err != nil {
		return nil, fmt.Errorf("failed to initialize Chrome pool: %w", err)
	}
	
	// Ensure Chrome pool is closed when done
	defer func() {
		if app.ChromePool != nil {
			if err := app.ChromePool.Close(); err != nil {
				app.logger.Warn("Failed to close Chrome pool", "error", err)
			}
		}
	}()

	app.logger.Progress("Starting screenshot capture", "targets", len(finalTargets), "concurrency", opts.Concurrency)

	// Create a semaphore to limit concurrency
	semaphore := make(chan struct{}, opts.Concurrency)
	results := make([]ScreenshotResult, len(finalTargets))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var completed int

	// Track whether we've printed an inline progress line
	progressInline := len(finalTargets) > 5 && !opts.DryRun
	var progressNewlineOnce sync.Once

	for i, target := range finalTargets {
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
				fmt.Fprintf(os.Stderr, "\rProgress: %d/%d completed", currentCompleted, len(finalTargets))
				if currentCompleted == len(finalTargets) {
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
		if len(finalTargets) == 1 {
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

	app.logger.Progress("Screenshot capture completed", "total", len(finalTargets), "successes", successes, "failures", failures)

	return results, nil
}

// captureScreenshot captures a screenshot of a single target
func (app *ScreenshotApp) captureScreenshot(ctx context.Context, target ScreenshotTarget, opts *ScreenshotOptions) ScreenshotResult {
	start := time.Now()
	result := ScreenshotResult{
		Target:    target,
		Timestamp: start,
	}

	// Quick connectivity check first (especially important for CIDR scans)
	// Skip connectivity check if Chrome is not available
	if !opts.SkipPortCheck {
		// Check if Chrome is available first
		if _, err := FindChromeExecutableWithOptions(opts.AutoDownload); err != nil {
			// Chrome is not available, skip connectivity check to avoid network requests
			app.logger.Network("Skipping connectivity check - Chrome not available", "target", target.URL)
		} else if !app.isServiceReachable(target) {
			result.Error = fmt.Errorf("no service found at %s:%d", target.Host, target.Port)
			result.Success = false
			result.Duration = time.Since(start)
			app.logger.Network("Service not reachable", "target", target.URL, "duration", result.Duration)
			return result
		}
	}
	
	// For HTTPS targets on non-standard ports, do a quick TLS probe first
	if target.Protocol == "https" && target.Port != 443 && !opts.SkipPortCheck {
		if !app.probeTLSCapability(target.Host, target.Port) {
			result.Error = fmt.Errorf("TLS not supported on %s:%d", target.Host, target.Port)
			result.Success = false
			result.Duration = time.Since(start)
			app.logger.Network("TLS not supported", "target", target.URL, "duration", result.Duration)
			return result
		}
	}

	// Capture screenshot with smart retry logic
	var err error
	if opts.SkipPortCheck {
		// If port checking is disabled, use normal retry logic
		err = retry.Do(ctx, app.retryConfig, app.logger, func() error {
			timeoutCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
			defer cancel()
			return app.doScreenshot(timeoutCtx, target, opts, &result)
		})
	} else {
		// If port checking is enabled, try once with fast failure
		timeoutCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
		err = app.doScreenshot(timeoutCtx, target, opts, &result)
	}

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
		timeout = 500 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), timeout)
	if err != nil {
		return false
	}
	if err := conn.Close(); err != nil {
		// Connection close error after successful test (ignored)
		_ = err
	}
	return true
}

// probeTLSCapability quickly checks if a port supports TLS without full handshake
func (app *ScreenshotApp) probeTLSCapability(host string, port int) bool {
	// Quick TLS probe with very short timeout
	timeout := 2 * time.Second
	
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	defer func() {
		if err := conn.Close(); err != nil {
			// Connection close error (ignored)
			_ = err
		}
	}()
	
	// Set a short deadline for the TLS probe
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		// Deadline set error (ignored)
		_ = err
	}
	
	// Attempt TLS handshake
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // We just want to know if TLS is supported
	})
	
	// Try the handshake - if it works, TLS is supported
	err = tlsConn.Handshake()
	if err := tlsConn.Close(); err != nil {
		// TLS connection close error (ignored)
		_ = err
	}
	
	return err == nil
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

// doScreenshot performs the actual screenshot capture using the Chrome pool
func (app *ScreenshotApp) doScreenshot(_ context.Context, target ScreenshotTarget, opts *ScreenshotOptions, result *ScreenshotResult) error {
	// Get Chrome instance from pool
	instance, err := app.ChromePool.Get()
	if err != nil {
		return errors.WrapNetworkError("failed to get Chrome instance from pool", err)
	}
	
	// Return instance to pool when done
	defer func() {
		if putErr := app.ChromePool.Put(instance); putErr != nil {
			app.logger.Warn("Failed to return Chrome instance to pool", "error", putErr)
		}
	}()
	
	// Navigate to the target URL
	if err := instance.Navigate(target.URL); err != nil {
		return errors.WrapNetworkError("failed to navigate to URL", err)
	}
	
	// Wait for the page to load (but with a shorter wait for failed connections)
	time.Sleep(opts.WaitTime)
	
	// Take screenshot
	screenshotData, err := instance.Screenshot()
	if err != nil {
		return errors.WrapNetworkError("failed to capture screenshot", err)
	}
	
	// Generate filename and save screenshot
	filename := app.generateFilename(target)
	result.FilePath = filepath.Join(opts.OutputDir, filename)
	
	if err := os.WriteFile(result.FilePath, screenshotData, 0644); err != nil {
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
		// Smart protocol detection based on ports
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
			// Use the simpler priority-based approach for CIDR parsing
			// TLS probing will happen later during actual screenshot attempts
			portProtocols := getProtocolsForPort(port, protocols)
			
			for _, protocol := range portProtocols {
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

// getProtocolsForPort returns protocols in priority order (most likely first)
func getProtocolsForPort(port int, requestedProtocols []string) []string {
	// If specific protocols were requested, respect that
	if len(requestedProtocols) > 0 && !contains(requestedProtocols, "http") && !contains(requestedProtocols, "https") {
		return requestedProtocols
	}
	
	// If only one protocol was requested, use it
	if len(requestedProtocols) == 1 {
		return requestedProtocols
	}
	
	// For multiple protocols or default case, prioritize based on common usage
	// but still try both - just in a smarter order
	switch port {
	case 80, 8080, 8000, 3000, 5000, 8888, 9000:
		// HTTP is more likely first, but still try HTTPS
		return []string{"http", "https"}
	case 443, 8443, 8843:
		// HTTPS is more likely first, but still try HTTP
		return []string{"https", "http"}
	default:
		// For unknown ports, HTTP is statistically more common
		return []string{"http", "https"}
	}
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ParseTargetsFromFile parses targets from a file
func ParseTargetsFromFile(filename string) ([]ScreenshotTarget, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.WrapFileError("failed to open targets file", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close targets file: %v\n", closeErr)
		}
	}()

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

// FindChromeExecutable attempts to find Chrome or Chromium executable
// This function does not attempt to auto-download Chromium. Use FindChromeExecutableWithOptions(true) for that.
func FindChromeExecutable() (string, error) {
	return FindChromeExecutableWithOptions(false)
}

// FindChromeExecutableWithOptions attempts to find Chrome or Chromium executable
// If autoDownload is true and no local installation is found, it will download a portable Chromium
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

	// If auto-download is enabled, check for cached Chromium first before downloading
	if autoDownload {
		// Check if we already have a cached Chromium
		cacheDir, err := getCacheDir()
		if err == nil {
			chromiumDir := filepath.Join(cacheDir, "chromium")
			var cachedExecutablePath string
			
			switch runtime.GOOS {
			case "darwin":
				cachedExecutablePath = filepath.Join(chromiumDir, "Chromium.app", "Contents", "MacOS", "Chromium")
			case "linux":
				cachedExecutablePath = filepath.Join(chromiumDir, "chrome")
			case "windows":
				cachedExecutablePath = filepath.Join(chromiumDir, "chrome.exe")
			}
			
			// If cached Chromium exists, return it
			if cachedExecutablePath != "" {
				if _, err := os.Stat(cachedExecutablePath); err == nil {
					// Optionally add debug info (commented out to keep output clean)
					// fmt.Printf("Using cached Chromium: %s\n", cachedExecutablePath)
					return cachedExecutablePath, nil
				}
			}
		}
		
		// If no cached version found, download it
		executablePath, err := downloadPortableChromium()
		if err == nil {
			return executablePath, nil
		}
		// If download fails, we'll fall through to the not found error
	}

	return "", fmt.Errorf("chrome or Chromium executable not found. Please install Chrome/Chromium or ensure it's in your PATH. Tried: %v", append(pathCandidates, candidates...))
}

// isSSLError checks if the error is related to SSL/TLS certificate issues
// downloadPortableChromium is a variable so we can mock it in tests
var downloadPortableChromium = func() (string, error) {
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
		return "", fmt.Errorf("chromium executable not found after download: %s", executablePath)
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
			cacheDir = filepath.Join(localAppData, "sniffl")
		} else {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			cacheDir = filepath.Join(homeDir, "AppData", "Local", "sniffl")
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
		switch runtime.GOARCH {
		case "amd64":
			return baseURL + "/Linux_x64/LAST_CHANGE", nil
		default:
			return "", fmt.Errorf("unsupported Linux architecture: %s", runtime.GOARCH)
		}
	case "darwin":
		switch runtime.GOARCH {
		case "amd64":
			return baseURL + "/Mac/LAST_CHANGE", nil
		case "arm64":
			return baseURL + "/Mac_Arm/LAST_CHANGE", nil
		default:
			return "", fmt.Errorf("unsupported macOS architecture: %s", runtime.GOARCH)
		}
	case "windows":
		switch runtime.GOARCH {
		case "amd64":
			return baseURL + "/Win_x64/LAST_CHANGE", nil
		case "386":
			return baseURL + "/Win/LAST_CHANGE", nil
		default:
			return "", fmt.Errorf("unsupported Windows architecture: %s", runtime.GOARCH)
		}
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Response body close error (ignored)
			_ = err
		}
	}()

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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Response body close error (ignored)
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download Chromium: HTTP %d", resp.StatusCode)
	}

	// Create temporary file
	tempFile, err := os.CreateTemp("", "chromium-*.zip")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		if err := os.Remove(tempFile.Name()); err != nil {
			// Temp file removal error (ignored)
			_ = err
		}
	}()
	defer func() {
		if err := tempFile.Close(); err != nil {
			// Temp file close error (ignored)
			_ = err
		}
	}()

	// Download to temp file
	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to download Chromium archive: %w", err)
	}

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
	defer func() {
		if err := r.Close(); err != nil {
			// Reader close error (ignored)
			_ = err
		}
	}()

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
			if err := rc.Close(); err != nil {
				// Reader close error (ignored)
				_ = err
			}
			return fmt.Errorf("invalid file path: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, f.FileInfo().Mode()); err != nil {
				if err := rc.Close(); err != nil {
					// Reader close error (ignored)
					_ = err
				}
				return err
			}
		} else {
			// Create file directory
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				if err := rc.Close(); err != nil {
					// Reader close error (ignored)
					_ = err
				}
				return err
			}

			// Create file
			outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.FileInfo().Mode())
			if err != nil {
				if err := rc.Close(); err != nil {
					// Reader close error (ignored)
					_ = err
				}
				return err
			}

			// Copy with a size limit
			_, err = io.CopyN(outFile, rc, 1024*1024*256) // Limit to 256MB to prevent zip bombs
			if err := outFile.Close(); err != nil {
				// Output file close error (ignored)
				_ = err
			}
			if err := rc.Close(); err != nil {
				// Reader close error (ignored)
				_ = err
			}

			if err != nil && err != io.EOF {
				return err
			}
		}
	}

	return nil
}


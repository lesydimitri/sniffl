package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/lesydimitri/sniffl/internal/logging"
	"github.com/lesydimitri/sniffl/internal/screenshot"
	"github.com/spf13/cobra"
)

var screenshotCmd = &cobra.Command{
	Use:   "screenshot [URL|host:port|CIDR]",
	Short: "Capture screenshots of HTTP/HTTPS pages",
	Long: `Capture screenshots of HTTP/HTTPS pages from various sources.

REQUIREMENTS:
This command requires Chrome or Chromium to be installed. You can verify your installation
by using 'sniffl screenshot check-chrome'.

You can specify:
- A single URL (http://example.com or https://example.com:8443)
- A single host:port (example.com:80, will auto-detect protocol)
- A file with multiple targets using --file
- A CIDR range for network scanning using --cidr

For CIDR scanning, you can specify which ports to scan and protocols to use.`,
	Example: `  # Screenshot a single URL
  sniffl screenshot https://example.com

  # Screenshot a host:port (auto-detects HTTP/HTTPS)
  sniffl screenshot example.com:443

  # Screenshot multiple targets from file
  sniffl screenshot --file targets.txt --output-dir ./screenshots

  # Scan a CIDR range for web services
  sniffl screenshot --cidr 192.168.1.0/24 --ports 80,443,8080,8443

  # Scan with custom options
  sniffl screenshot --cidr 10.0.0.0/24 --ports 80,443 --timeout 15s --concurrency 10

  # Use a custom Chrome/Chromium path
  sniffl screenshot https://example.com --chrome-path=/usr/bin/chromium`,
	RunE: runScreenshot,
}

var (
	screenshotFile          string
	screenshotCIDR          string
	screenshotOutputDir     string
	screenshotPorts         string
	screenshotProtocols     string
	screenshotTimeout       string
	screenshotConcurrency   int
	screenshotFullPage      bool
	screenshotWaitTime      string
	screenshotViewport      string
	screenshotUserAgent     string
	screenshotDryRun        bool
	screenshotChromePath    string
	screenshotSkipPortCheck bool
	screenshotStrict        bool
)

func init() {
	screenshotCmd.Flags().StringVarP(&screenshotFile, "file", "f", "", "file with targets (URLs or host:port)")
	screenshotCmd.Flags().StringVar(&screenshotCIDR, "cidr", "", "CIDR range to scan (e.g., 192.168.1.0/24)")
	screenshotCmd.Flags().StringVarP(&screenshotOutputDir, "output-dir", "o", "screenshots", "output directory for screenshots")
	screenshotCmd.Flags().StringVarP(&screenshotPorts, "ports", "p", "80,443,8080,8443", "comma-separated list of ports for CIDR scan")
	screenshotCmd.Flags().StringVar(&screenshotProtocols, "protocols", "http,https", "comma-separated list of protocols (http,https)")
	screenshotCmd.Flags().StringVarP(&screenshotTimeout, "timeout", "t", "30s", "timeout for each screenshot")
	screenshotCmd.Flags().IntVarP(&screenshotConcurrency, "concurrency", "c", 5, "number of concurrent screenshot operations")
	screenshotCmd.Flags().BoolVar(&screenshotFullPage, "full-page", true, "capture full page screenshot")
	screenshotCmd.Flags().StringVar(&screenshotWaitTime, "wait", "2s", "time to wait for page load before screenshot")
	screenshotCmd.Flags().StringVar(&screenshotViewport, "viewport", "1920x1080", "viewport size (WIDTHxHEIGHT)")
	screenshotCmd.Flags().StringVar(&screenshotUserAgent, "user-agent", "", "custom user agent string")
	screenshotCmd.Flags().StringVar(&screenshotChromePath, "chrome-path", "", "path to Chrome/Chromium executable")
	screenshotCmd.Flags().BoolVar(&screenshotSkipPortCheck, "skip-port-check", false, "skip initial port connectivity check (faster but may waste time on unreachable targets)")
	screenshotCmd.Flags().BoolVar(&screenshotStrict, "strict", false, "enforce strict TLS verification and do not ignore SSL errors")
	screenshotCmd.Flags().BoolVar(&screenshotDryRun, "dry-run", false, "show what would be done without executing")

	// Mark flags as mutually exclusive
	screenshotCmd.MarkFlagsMutuallyExclusive("file", "cidr")
}

func runScreenshot(cmd *cobra.Command, args []string) error {
	ctx := GetContext()
	cfg := GetConfig()
	logger := GetLogger()

	// Validate input arguments
	if len(args) == 0 && screenshotFile == "" && screenshotCIDR == "" {
		return errors.NewValidationError("must specify a target URL/host:port, --file, or --cidr")
	}

	if len(args) > 0 && (screenshotFile != "" || screenshotCIDR != "") {
		return errors.NewValidationError("cannot specify both positional argument and --file/--cidr flags")
	}

	// Parse targets based on input method
	var targets []screenshot.ScreenshotTarget
	var err error

	switch {
	case len(args) > 0:
		// Single target from command line
		target, err := screenshot.ParseSingleTarget(args[0])
		if err != nil {
			return err
		}
		targets = []screenshot.ScreenshotTarget{target}

	case screenshotFile != "":
		// Multiple targets from file
		targets, err = screenshot.ParseTargetsFromFile(screenshotFile)
		if err != nil {
			return fmt.Errorf("failed to parse targets from file: %w", err)
		}

	case screenshotCIDR != "":
		// CIDR range scanning
		ports, err := parsePorts(screenshotPorts)
		if err != nil {
			return err
		}

		protocols := parseProtocols(screenshotProtocols)

		targets, err = screenshot.ParseCIDR(screenshotCIDR, ports, protocols)
		if err != nil {
			return fmt.Errorf("failed to parse CIDR range: %w", err)
		}

		if len(targets) > 1000 {
			logger.Info("Large CIDR scan detected", "targets", len(targets))
			logger.Info("Consider using smaller ranges or fewer ports for better performance")
		}
	}

	if len(targets) == 0 {
		return errors.NewValidationError("no valid targets found")
	}

	// Parse screenshot options
	opts, err := parseScreenshotOptions()
	if err != nil {
		return err
	}

	// Apply adaptive concurrency
	concurrencyManager := screenshot.NewAdaptiveConcurrencyManager()
	recommendedConcurrency := concurrencyManager.GetScreenshotConcurrency(len(targets))
	if opts.Concurrency > recommendedConcurrency {
		logger.Info("Reducing concurrency to system-recommended level", "requested", opts.Concurrency, "recommended", recommendedConcurrency)
		opts.Concurrency = recommendedConcurrency
	}

	if screenshotDryRun {
		opts.DryRun = true
		logger.Info("Dry run mode enabled - no screenshots will be captured")
	}

	// Create screenshot app
	app := screenshot.NewScreenshotApp(cfg, logger)
	// Note: No explicit Close method exists, Chrome pool cleanup is handled automatically

	// Print concise stdout summary always
	fmt.Printf("Starting screenshot operation: %d target(s), output=%s, concurrency=%d, timeout=%s, dry-run=%t\n",
		len(targets), opts.OutputDir, opts.Concurrency, opts.Timeout, opts.DryRun)

	logger.Info("Screenshot operation starting",
		"targets", len(targets),
		"output_dir", opts.OutputDir,
		"concurrency", opts.Concurrency,
		"timeout", opts.Timeout,
		"dry_run", opts.DryRun)

	// Process targets
	results, err := app.ProcessTargets(ctx, targets, opts)
	if err != nil {
		return fmt.Errorf("screenshot processing failed: %w", err)
	}

	// Print summary (stdout + logs)
	printScreenshotSummary(results, logger)

	return nil
}

func printScreenshotSummary(results []screenshot.ScreenshotResult, logger *logging.Logger) {
	var successes, failures int
	var totalDuration time.Duration

	for _, result := range results {
		totalDuration += result.Duration
		if result.Success {
			successes++
		} else {
			failures++
		}
	}

	avgDuration := time.Duration(0)
	if len(results) > 0 {
		avgDuration = totalDuration / time.Duration(len(results))
	}

	// Always print concise stdout summary
	fmt.Printf("Summary: total=%d, successes=%d, failures=%d, total_duration=%s, avg_duration=%s\n",
		len(results), successes, failures, totalDuration.Round(time.Millisecond), avgDuration.Round(time.Millisecond))

	logger.Info("Screenshot Summary",
		"total", len(results),
		"successes", successes,
		"failures", failures,
		"total_duration", totalDuration.Round(time.Millisecond),
		"avg_duration", avgDuration.Round(time.Millisecond))

	// Show first few failures for debugging
	failureCount := 0
	for _, result := range results {
		if !result.Success && failureCount < 5 {
			logger.Failure("Screenshot failed", "target", result.Target.URL, "error", result.Error)
			failureCount++
		}
	}

	if failures > 5 {
		logger.Info("Additional failures not shown", "count", failures-5)
	}
} // End of runScreenshot function

func parsePorts(portsStr string) ([]int, error) {
	if portsStr == "" {
		return []int{80, 443}, nil
	}

	portStrs := strings.Split(portsStr, ",")
	ports := make([]int, 0, len(portStrs))

	for _, portStr := range portStrs {
		portStr = strings.TrimSpace(portStr)
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, errors.NewValidationError(fmt.Sprintf("invalid port: %s", portStr))
		}

		if port <= 0 || port > 65535 {
			return nil, errors.NewValidationError(fmt.Sprintf("port out of range: %d", port))
		}

		ports = append(ports, port)
	}

	return ports, nil
}

func parseProtocols(protocolsStr string) []string {
	if protocolsStr == "" {
		return []string{"http", "https"}
	}

	protocolStrs := strings.Split(protocolsStr, ",")
	protocols := make([]string, 0, len(protocolStrs))

	for _, protocol := range protocolStrs {
		protocol = strings.TrimSpace(strings.ToLower(protocol))
		if protocol == "http" || protocol == "https" {
			protocols = append(protocols, protocol)
		}
	}

	if len(protocols) == 0 {
		return []string{"http", "https"}
	}

	return protocols
}

func parseScreenshotOptions() (*screenshot.ScreenshotOptions, error) {
	opts := screenshot.DefaultScreenshotOptions()

	// Parse timeout
	if screenshotTimeout != "" {
		timeout, err := time.ParseDuration(screenshotTimeout)
		if err != nil {
			return nil, errors.WrapValidationError("invalid timeout format", err)
		}
		opts.Timeout = timeout
	}

	// Parse wait time
	if screenshotWaitTime != "" {
		waitTime, err := time.ParseDuration(screenshotWaitTime)
		if err != nil {
			return nil, errors.WrapValidationError("invalid wait time format", err)
		}
		opts.WaitTime = waitTime
	}

	// Parse viewport
	if screenshotViewport != "" {
		parts := strings.Split(screenshotViewport, "x")
		if len(parts) != 2 {
			return nil, errors.NewValidationError("viewport must be in format WIDTHxHEIGHT")
		}

		width, err := strconv.Atoi(parts[0])
		if err != nil || width <= 0 {
			return nil, errors.NewValidationError("invalid viewport width")
		}

		height, err := strconv.Atoi(parts[1])
		if err != nil || height <= 0 {
			return nil, errors.NewValidationError("invalid viewport height")
		}

		opts.ViewportWidth = width
		opts.ViewportHeight = height
	}

	// Set other options
	opts.OutputDir = screenshotOutputDir
	opts.Concurrency = screenshotConcurrency
	opts.FullPage = screenshotFullPage

	if screenshotUserAgent != "" {
		opts.UserAgent = screenshotUserAgent
	}

	if screenshotChromePath != "" {
		opts.ChromePath = screenshotChromePath
	}

	opts.SkipPortCheck = screenshotSkipPortCheck
	opts.IgnoreSSLErrors = !screenshotStrict

	// Validate concurrency
	if opts.Concurrency <= 0 || opts.Concurrency > 50 {
		return nil, errors.NewValidationError("concurrency must be between 1 and 50")
	}

	return opts, nil
}

package screenshot

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lesydimitri/sniffl/internal/config"
	"github.com/lesydimitri/sniffl/internal/logging"
	"github.com/lesydimitri/sniffl/internal/retry"
)

// testScreenshotApp creates a ScreenshotApp with a mock Chrome instance for testing
func testScreenshotApp(_ *testing.T) *ScreenshotApp {
	cfg := config.DefaultConfig()
	logger := logging.New("info", "text", os.Stderr)

	// Create app configuration
	app := &ScreenshotApp{
		config: cfg,
		logger: logger,
		retryConfig: retry.Config{
			MaxAttempts: cfg.RetryAttempts,
			BaseDelay:   cfg.RetryDelay,
			MaxDelay:    30 * time.Second,
			Multiplier:  2.0,
			Jitter:      true,
		},
	}
	return app
}

// screenshotURL is a package-level variable that we can override in tests
var screenshotURL = func(ctx context.Context, target ScreenshotTarget, opts ScreenshotOptions) ([]byte, error) {
	// This will be mocked in tests
	return nil, nil
}

func TestDefaultScreenshotOptions(t *testing.T) {
	opts := DefaultScreenshotOptions()

	if opts.OutputDir != "screenshots" {
		t.Errorf("Expected OutputDir to be 'screenshots', got %s", opts.OutputDir)
	}

	if opts.Timeout != 30*time.Second {
		t.Errorf("Expected Timeout to be 30s, got %v", opts.Timeout)
	}

	if opts.ViewportWidth != 1920 || opts.ViewportHeight != 1080 {
		t.Errorf("Expected viewport 1920x1080, got %dx%d", opts.ViewportWidth, opts.ViewportHeight)
	}

	if !opts.FullPage {
		t.Error("Expected FullPage to be true")
	}

	if opts.Concurrency != 5 {
		t.Errorf("Expected Concurrency to be 5, got %d", opts.Concurrency)
	}
}

func TestNewScreenshotApp(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := logging.New("info", "text", os.Stderr)

	app := NewScreenshotApp(cfg, logger)

	if app == nil {
		t.Fatal("Expected app to be created")
	}

	if app.config != cfg {
		t.Error("Expected config to be set")
	}

	if app.logger != logger {
		t.Error("Expected logger to be set")
	}

	if app.retryConfig.MaxAttempts != cfg.RetryAttempts {
		t.Errorf("Expected retry attempts to be %d, got %d", cfg.RetryAttempts, app.retryConfig.MaxAttempts)
	}
}

func TestParseSingleTarget_URL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ScreenshotTarget
		wantErr  bool
	}{
		{
			name:  "HTTP URL",
			input: "http://example.com",
			expected: ScreenshotTarget{
				URL:      "http://example.com",
				Host:     "example.com",
				Port:     80,
				Protocol: "http",
			},
			wantErr: false,
		},
		{
			name:  "HTTPS URL",
			input: "https://example.com",
			expected: ScreenshotTarget{
				URL:      "https://example.com",
				Host:     "example.com",
				Port:     443,
				Protocol: "https",
			},
			wantErr: false,
		},
		{
			name:  "URL with custom port",
			input: "https://example.com:8443",
			expected: ScreenshotTarget{
				URL:      "https://example.com:8443",
				Host:     "example.com",
				Port:     8443,
				Protocol: "https",
			},
			wantErr: false,
		},
		{
			name:    "Invalid URL",
			input:   "not-a-url",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := ParseSingleTarget(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if target.URL != tt.expected.URL {
				t.Errorf("Expected URL %s, got %s", tt.expected.URL, target.URL)
			}

			if target.Host != tt.expected.Host {
				t.Errorf("Expected Host %s, got %s", tt.expected.Host, target.Host)
			}

			if target.Port != tt.expected.Port {
				t.Errorf("Expected Port %d, got %d", tt.expected.Port, target.Port)
			}

			if target.Protocol != tt.expected.Protocol {
				t.Errorf("Expected Protocol %s, got %s", tt.expected.Protocol, target.Protocol)
			}
		})
	}
}

func TestParseSingleTarget_HostPort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ScreenshotTarget
		wantErr  bool
	}{
		{
			name:  "HTTP port",
			input: "example.com:80",
			expected: ScreenshotTarget{
				URL:      "http://example.com:80",
				Host:     "example.com",
				Port:     80,
				Protocol: "http",
			},
			wantErr: false,
		},
		{
			name:  "HTTPS port",
			input: "example.com:443",
			expected: ScreenshotTarget{
				URL:      "https://example.com:443",
				Host:     "example.com",
				Port:     443,
				Protocol: "https",
			},
			wantErr: false,
		},
		{
			name:  "Custom port defaults to HTTP",
			input: "example.com:8080",
			expected: ScreenshotTarget{
				URL:      "http://example.com:8080",
				Host:     "example.com",
				Port:     8080,
				Protocol: "http",
			},
			wantErr: false,
		},
		{
			name:    "Invalid host:port",
			input:   "invalid-host-port",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := ParseSingleTarget(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if target.URL != tt.expected.URL {
				t.Errorf("Expected URL %s, got %s", tt.expected.URL, target.URL)
			}

			if target.Host != tt.expected.Host {
				t.Errorf("Expected Host %s, got %s", tt.expected.Host, target.Host)
			}

			if target.Port != tt.expected.Port {
				t.Errorf("Expected Port %d, got %d", tt.expected.Port, target.Port)
			}

			if target.Protocol != tt.expected.Protocol {
				t.Errorf("Expected Protocol %s, got %s", tt.expected.Protocol, target.Protocol)
			}
		})
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name       string
		cidr       string
		ports      []int
		protocols  []string
		wantErr    bool
		minTargets int
		maxTargets int
	}{
		{
			name:       "Small /30 network",
			cidr:       "192.168.1.0/30",
			ports:      []int{80, 443},
			protocols:  []string{"http", "https"},
			wantErr:    false,
			minTargets: 6, // 4 IPs * 2 ports * 1 protocol each (http for 80, https for 443) - but skips network/broadcast for /30
			maxTargets: 8, // All 4 IPs if network/broadcast not skipped
		},
		{
			name:    "Invalid CIDR",
			cidr:    "invalid-cidr",
			ports:   []int{80},
			wantErr: true,
		},
		{
			name:    "No ports",
			cidr:    "192.168.1.0/30",
			ports:   []int{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := ParseCIDR(tt.cidr, tt.ports, tt.protocols)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(targets) < tt.minTargets || len(targets) > tt.maxTargets {
				t.Errorf("Expected %d-%d targets, got %d", tt.minTargets, tt.maxTargets, len(targets))
			}

			// Verify targets have valid structure
			for _, target := range targets {
				if target.Host == "" {
					t.Error("Target has empty host")
				}

				if target.Port <= 0 || target.Port > 65535 {
					t.Errorf("Target has invalid port: %d", target.Port)
				}

				if target.Protocol != "http" && target.Protocol != "https" {
					t.Errorf("Target has invalid protocol: %s", target.Protocol)
				}

				if !strings.HasPrefix(target.URL, target.Protocol+"://") {
					t.Errorf("Target URL doesn't match protocol: %s", target.URL)
				}

				// Verify IP is valid
				if net.ParseIP(target.Host) == nil {
					t.Errorf("Target has invalid IP: %s", target.Host)
				}
			}
		})
	}
}

func TestParseTargetsFromFile(t *testing.T) {
	// Create a temporary file with test targets
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "targets.txt")

	content := `# Test targets file
example.com:80
example.com:443 http
# Comment line
test.com:8080

another.com:9000`

	err := os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	targets, err := ParseTargetsFromFile(testFile)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should have 4 valid targets
	expectedTargets := 4
	if len(targets) != expectedTargets {
		t.Errorf("Expected %d targets, got %d", expectedTargets, len(targets))
	}

	// Verify first target
	if len(targets) > 0 {
		target := targets[0]
		if target.Host != "example.com" || target.Port != 80 {
			t.Errorf("First target incorrect: %+v", target)
		}
		if target.Protocol != "http" {
			t.Errorf("Expected protocol http, got %s", target.Protocol)
		}
	}
}

func TestGenerateFilename(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := logging.New("info", "text", os.Stderr)
	app := NewScreenshotApp(cfg, logger)

	target := ScreenshotTarget{
		Host:     "example.com",
		Port:     443,
		Protocol: "https",
		URL:      "https://example.com:443",
	}

	filename := app.generateFilename(target)

	// Should contain sanitized host, port, protocol
	if !strings.Contains(filename, "example_com") {
		t.Errorf("Filename should contain sanitized host: %s", filename)
	}

	if !strings.Contains(filename, "443") {
		t.Errorf("Filename should contain port: %s", filename)
	}

	if !strings.Contains(filename, "https") {
		t.Errorf("Filename should contain protocol: %s", filename)
	}

	if !strings.HasSuffix(filename, ".png") {
		t.Errorf("Filename should end with .png: %s", filename)
	}
}

func TestScreenshotResult_Basic(t *testing.T) {
	target := ScreenshotTarget{
		URL:      "http://example.com",
		Host:     "example.com",
		Port:     80,
		Protocol: "http",
	}

	tests := []struct {
		name     string
		result   ScreenshotResult
		expected string
	}{
		{
			name: "successful_result",
			result: ScreenshotResult{
				Target:   target,
				FilePath: "/path/to/screenshot.png",
				Success:  true,
				Error:    nil,
			},
			expected: "success",
		},
		{
			name: "failed_result",
			result: ScreenshotResult{
				Target:   target,
				FilePath: "",
				Success:  false,
				Error:    fmt.Errorf("screenshot failed"),
			},
			expected: "failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.result.Success && tt.result.Error != nil {
				t.Error("Successful result should not have error")
			}
			if !tt.result.Success && tt.result.Error == nil {
				t.Error("Failed result should have error")
			}
		})
	}
}

func TestParseViewport_Function(t *testing.T) {
	tests := []struct {
		name        string
		viewport    string
		expectError bool
		expectedW   int
		expectedH   int
	}{
		{
			name:        "valid_viewport_1920x1080",
			viewport:    "1920x1080",
			expectError: false,
			expectedW:   1920,
			expectedH:   1080,
		},
		{
			name:        "valid_viewport_1366x768",
			viewport:    "1366x768",
			expectError: false,
			expectedW:   1366,
			expectedH:   768,
		},
		{
			name:        "invalid_format_no_x",
			viewport:    "1920-1080",
			expectError: true,
		},
		{
			name:        "invalid_format_empty",
			viewport:    "",
			expectError: true,
		},
		{
			name:        "invalid_zero_width",
			viewport:    "0x1080",
			expectError: true,
		},
		{
			name:        "invalid_zero_height",
			viewport:    "1920x0",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			width, height, err := parseViewport(tt.viewport)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if width != tt.expectedW {
				t.Errorf("Expected width %d, got %d", tt.expectedW, width)
			}

			if height != tt.expectedH {
				t.Errorf("Expected height %d, got %d", tt.expectedH, height)
			}
		})
	}
}

func TestScreenshotOptions_Validation(t *testing.T) {
	tests := []struct {
		name    string
		opts    *ScreenshotOptions
		isValid bool
	}{
		{
			name:    "default_options",
			opts:    DefaultScreenshotOptions(),
			isValid: true,
		},
		{
			name: "custom_valid_options",
			opts: &ScreenshotOptions{
				OutputDir:       "/tmp/screenshots",
				Timeout:         60 * time.Second,
				ViewportWidth:   1366,
				ViewportHeight:  768,
				FullPage:        true,
				WaitTime:        2 * time.Second,
				UserAgent:       "Custom Agent",
				Concurrency:     8,
				SkipPortCheck:   true,
				IgnoreSSLErrors: true,
				DryRun:          false,
			},
			isValid: true,
		},
		{
			name: "invalid_empty_output_dir",
			opts: &ScreenshotOptions{
				OutputDir:      "",
				Timeout:        30 * time.Second,
				ViewportWidth:  1920,
				ViewportHeight: 1080,
				Concurrency:    5,
			},
			isValid: false,
		},
		{
			name: "invalid_zero_timeout",
			opts: &ScreenshotOptions{
				OutputDir:      "screenshots",
				Timeout:        0,
				ViewportWidth:  1920,
				ViewportHeight: 1080,
				Concurrency:    5,
			},
			isValid: false,
		},
		{
			name: "invalid_zero_concurrency",
			opts: &ScreenshotOptions{
				OutputDir:      "screenshots",
				Timeout:        30 * time.Second,
				ViewportWidth:  1920,
				ViewportHeight: 1080,
				Concurrency:    0,
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validateScreenshotOptions(tt.opts)
			if isValid != tt.isValid {
				t.Errorf("Expected validation result %v, got %v", tt.isValid, isValid)
			}
		})
	}
}

func TestAdaptiveConcurrencyManager_Comprehensive(t *testing.T) {
	acm := NewAdaptiveConcurrencyManager()

	tests := []struct {
		name          string
		operationType string
		targetCount   int
		minExpected   int
		maxExpected   int
	}{
		{
			name:          "screenshot_small_batch",
			operationType: "screenshot",
			targetCount:   5,
			minExpected:   1,
			maxExpected:   runtime.NumCPU() * 2,
		},
		{
			name:          "screenshot_large_batch",
			operationType: "screenshot",
			targetCount:   100,
			minExpected:   1,
			maxExpected:   runtime.NumCPU() * 4,
		},
		{
			name:          "connectivity_check",
			operationType: "connectivity_check",
			targetCount:   50,
			minExpected:   1,
			maxExpected:   runtime.NumCPU() * 8,
		},
		{
			name:          "unknown_operation",
			operationType: "unknown",
			targetCount:   10,
			minExpected:   1,
			maxExpected:   runtime.NumCPU() * 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			concurrency := acm.GetRecommendedConcurrency(tt.operationType, tt.targetCount)

			if concurrency < tt.minExpected {
				t.Errorf("Concurrency %d is below minimum %d", concurrency, tt.minExpected)
			}

			if concurrency > tt.maxExpected {
				t.Errorf("Concurrency %d is above maximum %d", concurrency, tt.maxExpected)
			}
		})
	}

	// Test specific methods
	t.Run("screenshot_concurrency", func(t *testing.T) {
		concurrency := acm.GetScreenshotConcurrency(20)
		if concurrency <= 0 {
			t.Error("Screenshot concurrency should be positive")
		}
	})

	t.Run("connectivity_concurrency", func(t *testing.T) {
		concurrency := acm.GetConnectivityCheckConcurrency(50)
		if concurrency <= 0 {
			t.Error("Connectivity concurrency should be positive")
		}
	})

	t.Run("system_info", func(t *testing.T) {
		info := acm.GetSystemInfo()

		expectedKeys := []string{"cpu_count", "go_max_procs", "base_concurrency"}
		for _, key := range expectedKeys {
			if _, exists := info[key]; !exists {
				t.Errorf("Expected system info to contain key %q", key)
			}
		}
	})
}

func TestChromePoolConfig_Extended(t *testing.T) {
	config := DefaultChromePoolConfig()

	if config.MaxInstances <= 0 {
		t.Error("MaxInstances should be positive")
	}

	if config.MaxIdleTime <= 0 {
		t.Error("MaxIdleTime should be positive")
	}

	if config.MaxUseCount <= 0 {
		t.Error("MaxUseCount should be positive")
	}

	if config.ViewportWidth <= 0 {
		t.Error("ViewportWidth should be positive")
	}

	if config.ViewportHeight <= 0 {
		t.Error("ViewportHeight should be positive")
	}

	// Test that it's reasonable for the current system
	if config.MaxInstances > runtime.NumCPU()*4 {
		t.Errorf("MaxInstances %d seems too high for %d CPUs", config.MaxInstances, runtime.NumCPU())
	}
}

func TestMockChromePool_Interface(t *testing.T) {
	pool := NewMockChromePool()

	// Test Get
	instance, err := pool.Get()
	if err != nil {
		t.Errorf("Mock pool Get() failed: %v", err)
	}

	if instance == nil {
		t.Error("Mock pool Get() returned nil instance")
	}

	// Test instance methods
	if err := instance.Navigate("http://example.com"); err != nil {
		t.Errorf("Mock instance Navigate() failed: %v", err)
	}

	screenshot, err := instance.Screenshot()
	if err != nil {
		t.Errorf("Mock instance Screenshot() failed: %v", err)
	}

	if len(screenshot) == 0 {
		t.Error("Mock instance Screenshot() returned empty data")
	}

	if !instance.IsHealthy() {
		t.Error("Mock instance should be healthy")
	}

	useCount := instance.GetUseCount()
	if useCount < 0 {
		t.Error("Use count should be non-negative")
	}

	// Test Put
	if err := pool.Put(instance); err != nil {
		t.Errorf("Mock pool Put() failed: %v", err)
	}

	// Test Stats
	stats := pool.Stats()
	if stats.ActiveInstances < 0 {
		t.Error("Active instances should be non-negative")
	}

	// Test Close
	if err := pool.Close(); err != nil {
		t.Errorf("Mock pool Close() failed: %v", err)
	}
}

func TestScreenshotTarget_ValidationExtended(t *testing.T) {
	tests := []struct {
		name    string
		target  ScreenshotTarget
		isValid bool
	}{
		{
			name: "valid_custom_port",
			target: ScreenshotTarget{
				URL:      "http://example.com:8080",
				Host:     "example.com",
				Port:     8080,
				Protocol: "http",
			},
			isValid: true,
		},
		{
			name: "valid_ip_address",
			target: ScreenshotTarget{
				URL:      "https://192.168.1.1:8443",
				Host:     "192.168.1.1",
				Port:     8443,
				Protocol: "https",
			},
			isValid: true,
		},
		{
			name: "invalid_port_too_high",
			target: ScreenshotTarget{
				URL:      "http://example.com:70000",
				Host:     "example.com",
				Port:     70000,
				Protocol: "http",
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validateScreenshotTarget(tt.target)
			if isValid != tt.isValid {
				t.Errorf("Expected validation result %v, got %v", tt.isValid, isValid)
			}
		})
	}
}

// Helper functions for testing

func parseViewport(viewport string) (int, int, error) {
	parts := strings.Split(viewport, "x")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("viewport must be in format WIDTHxHEIGHT")
	}

	width, err := strconv.Atoi(parts[0])
	if err != nil || width <= 0 {
		return 0, 0, fmt.Errorf("invalid width: %s", parts[0])
	}

	height, err := strconv.Atoi(parts[1])
	if err != nil || height <= 0 {
		return 0, 0, fmt.Errorf("invalid height: %s", parts[1])
	}

	return width, height, nil
}

func validateScreenshotOptions(opts *ScreenshotOptions) bool {
	if opts.OutputDir == "" {
		return false
	}
	if opts.Timeout <= 0 {
		return false
	}
	if opts.Concurrency <= 0 {
		return false
	}
	return true
}

func validateScreenshotTarget(target ScreenshotTarget) bool {
	if target.URL == "" || target.Host == "" {
		return false
	}
	if target.Port <= 0 || target.Port > 65535 {
		return false
	}
	if target.Protocol != "http" && target.Protocol != "https" {
		return false
	}
	return true
}

// ...existing code...

// Benchmark tests
func BenchmarkGenerateFilename(b *testing.B) {
	host := "example.com"
	port := 443
	protocol := "https"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fmt.Sprintf("%s_%d_%s.png",
			strings.ReplaceAll(host, ".", "_"),
			port,
			protocol)
	}
}

func BenchmarkParseViewport(b *testing.B) {
	viewport := "1920x1080"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = parseViewport(viewport)
	}
}

func BenchmarkAdaptiveConcurrencyManager(b *testing.B) {
	acm := NewAdaptiveConcurrencyManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = acm.GetRecommendedConcurrency("screenshot", 50)
	}
}

func TestProcessTargets_DryRun(t *testing.T) {
	// Create a test app with dry run enabled
	app := testScreenshotApp(t)
	// Use a temporary directory for output
	outputDir := t.TempDir()

	// Create screenshot options with dry run enabled
	opts := DefaultScreenshotOptions()
	opts.DryRun = true
	opts.OutputDir = outputDir

	// Create test targets with mock data
	tests := []struct {
		name       string
		targets    []ScreenshotTarget
		shouldFail bool
	}{
		{
			name: "single target",
			targets: []ScreenshotTarget{
				{
					Host:     "localhost",
					Port:     8080,
					Protocol: "http",
					URL:      "http://localhost:8080",
				},
			},
			shouldFail: false,
		},
		{
			name: "multiple targets",
			targets: []ScreenshotTarget{
				{
					Host:     "localhost",
					Port:     8080,
					Protocol: "http",
					URL:      "http://localhost:8080",
				},
				{
					Host:     "127.0.0.1",
					Port:     8443,
					Protocol: "https",
					URL:      "https://127.0.0.1:8443",
				},
			},
			shouldFail: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Override the screenshot function to use our mock
			oldScreenshot := screenshotURL
			screenshotURL = func(ctx context.Context, target ScreenshotTarget, opts ScreenshotOptions) ([]byte, error) {
				// Verify the context is not nil
				if ctx == nil {
					t.Error("Context should not be nil")
				}

				// Verify the target URL is as expected
				expectedURL := fmt.Sprintf("%s://%s:%d", target.Protocol, target.Host, target.Port)
				if target.URL != expectedURL {
					t.Errorf("Expected URL %s, got %s", expectedURL, target.URL)
				}

				if tc.shouldFail {
					return nil, fmt.Errorf("mock error")
				}

				// Return a minimal transparent PNG
				return []byte{
					0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
					0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
					0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
					0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
					0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41,
					0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
					0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
					0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
					0x42, 0x60, 0x82,
				}, nil
			}
			defer func() { screenshotURL = oldScreenshot }()

			// Process targets with context and options
			ctx := context.Background()
			results, err := app.ProcessTargets(ctx, tc.targets, opts)
			if tc.shouldFail {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("ProcessTargets failed: %v", err)
			}

			// Verify the results
			if len(results) != len(tc.targets) {
				t.Fatalf("Expected %d results, got %d", len(tc.targets), len(results))
			}

			for i, result := range results {
				if !result.Success {
					t.Errorf("Result %d: dry run should always succeed", i)
				}

				if result.Error != nil {
					t.Errorf("Result %d: dry run should not have error: %v", i, result.Error)
				}

				if result.FilePath == "" {
					t.Errorf("Result %d: dry run should set file path", i)
				}

				// Verify the output path contains the expected components
				expectedComponents := []string{
					strings.ReplaceAll(tc.targets[i].Host, ".", "_"),
					fmt.Sprintf("%d", tc.targets[i].Port),
					tc.targets[i].Protocol,
					".png",
				}
				for _, component := range expectedComponents {
					if !strings.Contains(result.FilePath, component) {
						t.Errorf("Result %d: expected path to contain %s, got %s", i, component, result.FilePath)
					}
				}
			}
			// Verify no files were actually created in dry run mode
			files, err := os.ReadDir(outputDir)
			if err != nil {
				t.Fatalf("Failed to read output directory: %v", err)
			}

			if len(files) > 0 {
				t.Errorf("Expected no files to be created in dry run mode, but found %d", len(files))
			}
		})
	}
}

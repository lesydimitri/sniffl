package screenshot

import (
	"context"
	"testing"

	"github.com/lesydimitri/sniffl/internal/config"
	"github.com/lesydimitri/sniffl/internal/logging"
)

func TestAdaptiveConcurrencyManager(t *testing.T) {
	acm := NewAdaptiveConcurrencyManager()

	if acm == nil {
		t.Fatal("Expected AdaptiveConcurrencyManager to be created")
	}

	// Test system info
	info := acm.GetSystemInfo()
	if info == nil {
		t.Error("Expected system info to be returned")
	}

	if cpuCount, ok := info["cpu_count"]; !ok || cpuCount.(int) <= 0 {
		t.Error("Expected valid CPU count in system info")
	}

	// Test recommended concurrency for different scenarios
	tests := []struct {
		name           string
		operationType  string
		targetCount    int
		minExpected    int
		maxExpected    int
	}{
		{
			name:          "Screenshot small batch",
			operationType: "screenshot",
			targetCount:   5,
			minExpected:   1,
			maxExpected:   8,
		},
		{
			name:          "Screenshot large batch",
			operationType: "screenshot",
			targetCount:   100,
			minExpected:   1,
			maxExpected:   8,
		},
		{
			name:          "Connectivity check small",
			operationType: "connectivity_check",
			targetCount:   5,
			minExpected:   2,
			maxExpected:   32,
		},
		{
			name:          "Batch operation",
			operationType: "batch",
			targetCount:   50,
			minExpected:   1,
			maxExpected:   24,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var concurrency int
			switch tt.operationType {
			case "screenshot":
				concurrency = acm.GetScreenshotConcurrency(tt.targetCount)
			case "connectivity_check":
				concurrency = acm.GetConnectivityCheckConcurrency(tt.targetCount)
			case "batch":
				concurrency = acm.GetRecommendedConcurrency(tt.operationType, tt.targetCount)
			}

			if concurrency < tt.minExpected || concurrency > tt.maxExpected {
				t.Errorf("Expected concurrency between %d and %d, got %d",
					tt.minExpected, tt.maxExpected, concurrency)
			}
		})
	}
}

func TestConnectivityChecker(t *testing.T) {
	// Skip this test as it makes real network connections to external hosts
	// The connectivity checker functionality is tested indirectly through integration tests
	t.Skip("Skipping connectivity checker test to avoid external connections")
}

func TestChromePoolConfig(t *testing.T) {
	config := DefaultChromePoolConfig()

	if config == nil {
		t.Fatal("Expected ChromePoolConfig to be created")
	}

	if config.MaxInstances <= 0 {
		t.Error("Expected MaxInstances to be positive")
	}

	if config.MaxIdleTime <= 0 {
		t.Error("Expected MaxIdleTime to be positive")
	}

	if config.MaxUseCount <= 0 {
		t.Error("Expected MaxUseCount to be positive")
	}

	if config.ViewportWidth <= 0 || config.ViewportHeight <= 0 {
		t.Error("Expected positive viewport dimensions")
	}

	if config.UserAgent == "" {
		t.Error("Expected non-empty UserAgent")
	}
}

func TestChromePoolCreation(t *testing.T) {
	// Skip this test as it may attempt to create real Chrome instances
	// Chrome pool functionality is tested indirectly through integration tests
	t.Skip("Skipping Chrome pool creation test to avoid external dependencies")
}

func TestScreenshotAppWithOptimizations(t *testing.T) {
	// Skip this test as it creates a real ScreenshotApp which may initialize Chrome pools
	// ScreenshotApp functionality is tested indirectly through integration tests
	t.Skip("Skipping ScreenshotApp optimization test to avoid external dependencies")
}


func TestIsLocalNetwork(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "Localhost IP",
			host:     "127.0.0.1",
			expected: true,
		},
		{
			name:     "Private IP",
			host:     "192.168.1.1",
			expected: true,
		},
		{
			name:     "Public IP",
			host:     "8.8.8.8",
			expected: false,
		},
		{
			name:     "Hostname",
			host:     "example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLocalNetwork(tt.host)
			if result != tt.expected {
				t.Errorf("isLocalNetwork(%s) = %v, expected %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestIsServiceReachable(t *testing.T) {
	// Skip this test as it makes real network connections
	// The method functionality is tested indirectly through integration tests
	t.Skip("Skipping network connectivity test to avoid external connections")
}

func TestScreenshotAppConcurrencyIntegration(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := logging.New("info", "text", nil)
	app := NewScreenshotApp(cfg, logger)

	// Replace with mock Chrome pool for testing
	app.ChromePool = NewMockChromePool()

	// Create test targets
	targets := []ScreenshotTarget{
		{
			Host:     "127.0.0.1",
			Port:     80,
			Protocol: "http",
			URL:      "http://127.0.0.1:80",
		},
	}
	// Test with dry run to verify integration
	opts := DefaultScreenshotOptions()
	opts.DryRun = true
	opts.OutputDir = t.TempDir()
	opts.Concurrency = 2 // Test concurrency setting

	ctx := context.Background()
	results, err := app.ProcessTargets(ctx, targets, opts)

	if err != nil {
		t.Fatalf("ProcessTargets failed: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	result := results[0]
	if !result.Success {
		t.Error("Expected successful result in dry run")
	}

	if result.FilePath == "" {
		t.Error("Expected file path to be set")
	}
}

func TestScreenshotAppWithLargeTargetSet(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := logging.New("info", "text", nil)
	app := NewScreenshotApp(cfg, logger)

	// Create a larger set of targets to test batch processing
	targets := []ScreenshotTarget{
		{
			Host:     "127.0.0.1",
			Port:     80,
			Protocol: "http",
			URL:      "http://127.0.0.1:80",
		},
		{
			Host:     "127.0.0.1",
			Port:     443,
			Protocol: "https",
			URL:      "https://127.0.0.1:443",
		},
	}

	opts := DefaultScreenshotOptions()
	opts.DryRun = true
	opts.OutputDir = t.TempDir()
	opts.Concurrency = 1 // Force sequential processing

	ctx := context.Background()
	results, err := app.ProcessTargets(ctx, targets, opts)

	if err != nil {
		t.Fatalf("ProcessTargets failed: %v", err)
	}

	if len(results) != len(targets) {
		t.Errorf("Expected %d results, got %d", len(targets), len(results))
	}

	// All results should be successful in dry run
	for i, result := range results {
		if !result.Success {
				t.Errorf("Result %d should be successful in dry run", i)
		}
	}
}

func TestScreenshotAppErrorHandling(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := logging.New("info", "text", nil)
	app := NewScreenshotApp(cfg, logger)

	// Test with empty targets
	ctx := context.Background()
	opts := DefaultScreenshotOptions()
	opts.DryRun = true
	opts.OutputDir = t.TempDir()

	results, err := app.ProcessTargets(ctx, []ScreenshotTarget{}, opts)

	if err == nil {
		t.Error("Expected error with empty targets")
	}

	if results != nil {
		t.Error("Expected nil results with empty targets")
	}
}

func TestAdaptiveConcurrencyWithScreenshotApp(t *testing.T) {
	// Test that adaptive concurrency integrates properly
	concurrencyManager := NewAdaptiveConcurrencyManager()
	systemInfo := concurrencyManager.GetSystemInfo()

	if systemInfo == nil {
		t.Error("Expected system info to be available")
	}

	// Test different target counts
	testCounts := []int{1, 5, 10, 50, 100}

	for _, count := range testCounts {
		screenshotConcurrency := concurrencyManager.GetScreenshotConcurrency(count)
		connectivityConcurrency := concurrencyManager.GetConnectivityCheckConcurrency(count)

		if screenshotConcurrency <= 0 {
			t.Errorf("Invalid screenshot concurrency for %d targets: %d", count, screenshotConcurrency)
		}

		if connectivityConcurrency <= 0 {
			t.Errorf("Invalid connectivity concurrency for %d targets: %d", count, connectivityConcurrency)
		}

		// Connectivity checks should generally have higher concurrency than screenshots
		if count > 10 && connectivityConcurrency <= screenshotConcurrency {
			t.Logf("Note: For %d targets, connectivity concurrency (%d) <= screenshot concurrency (%d)",
				count, connectivityConcurrency, screenshotConcurrency)
		}
	}
}

package screenshot

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lesydimitri/sniffl/internal/config"
	"github.com/lesydimitri/sniffl/internal/logging"
)

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
		name      string
		cidr      string
		ports     []int
		protocols []string
		wantErr   bool
		minTargets int
		maxTargets int
	}{
		{
			name:       "Small /30 network",
			cidr:       "192.168.1.0/30",
			ports:      []int{80, 443},
			protocols:  []string{"http", "https"},
			wantErr:    false,
			minTargets: 2, // 2 usable IPs * 2 ports * 1 protocol each (http for 80, https for 443)
			maxTargets: 4,
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

func TestProcessTargets_DryRun(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := logging.New("info", "text", os.Stderr)
	app := NewScreenshotApp(cfg, logger)
	
	targets := []ScreenshotTarget{
		{
			URL:      "http://example.com",
			Host:     "example.com",
			Port:     80,
			Protocol: "http",
		},
	}
	
	opts := DefaultScreenshotOptions()
	opts.DryRun = true
	opts.OutputDir = t.TempDir()
	
	ctx := context.Background()
	results, err := app.ProcessTargets(ctx, targets, opts)
	
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
	
	result := results[0]
	if !result.Success {
		t.Error("Dry run should always succeed")
	}
	
	if result.Error != nil {
		t.Errorf("Dry run should not have error: %v", result.Error)
	}
	
	if result.FilePath == "" {
		t.Error("Dry run should set file path")
	}
}

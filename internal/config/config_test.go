package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Test default values
	if cfg.Verbose != false {
		t.Errorf("Expected Verbose to be false, got %v", cfg.Verbose)
	}

	if cfg.Timeout != 30*time.Second {
		t.Errorf("Expected Timeout to be 30s, got %v", cfg.Timeout)
	}

	if cfg.Concurrency != 5 {
		t.Errorf("Expected Concurrency to be 5, got %v", cfg.Concurrency)
	}

	if cfg.RetryAttempts != 3 {
		t.Errorf("Expected RetryAttempts to be 3, got %v", cfg.RetryAttempts)
	}

	if cfg.LogLevel != "warn" {
		t.Errorf("Expected LogLevel to be 'warn', got %v", cfg.LogLevel)
	}
}

func TestLoadConfig_NonExistentFile(t *testing.T) {
	// Test loading config when file doesn't exist - should return defaults
	cfg, err := LoadConfig("/nonexistent/path/config.yaml")
	if err != nil {
		t.Errorf("LoadConfig should not error when file doesn't exist, got: %v", err)
	}

	// Should return default config
	defaultCfg := DefaultConfig()
	if cfg.Timeout != defaultCfg.Timeout {
		t.Errorf("Expected default timeout, got %v", cfg.Timeout)
	}
}

func TestLoadConfig_ValidFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `verbose: true
timeout: 60s
concurrency: 10
export_mode: bundle
retry_attempts: 5
log_level: debug
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Load the config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify values were loaded correctly
	if !cfg.Verbose {
		t.Error("Expected Verbose to be true")
	}

	if cfg.Timeout != 60*time.Second {
		t.Errorf("Expected Timeout to be 60s, got %v", cfg.Timeout)
	}

	if cfg.Concurrency != 10 {
		t.Errorf("Expected Concurrency to be 10, got %v", cfg.Concurrency)
	}

	if cfg.ExportMode != "bundle" {
		t.Errorf("Expected ExportMode to be 'bundle', got %v", cfg.ExportMode)
	}

	if cfg.RetryAttempts != 5 {
		t.Errorf("Expected RetryAttempts to be 5, got %v", cfg.RetryAttempts)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("Expected LogLevel to be 'debug', got %v", cfg.LogLevel)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	// Create a temporary config file with invalid YAML
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid-config.yaml")

	invalidContent := `verbose: true
timeout: 60s
invalid yaml: [
`

	err := os.WriteFile(configPath, []byte(invalidContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Loading should fail
	_, err = LoadConfig(configPath)
	if err == nil {
		t.Error("LoadConfig should fail with invalid YAML")
	}
}

func TestSaveConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "save-test.yaml")

	cfg := DefaultConfig()
	cfg.Verbose = true
	cfg.ExportMode = "single"
	cfg.LogLevel = "debug"

	err := cfg.SaveConfig(configPath)
	if err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}

	// Load it back and verify
	loadedCfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	if loadedCfg.Verbose != cfg.Verbose {
		t.Errorf("Verbose mismatch: got %v, want %v", loadedCfg.Verbose, cfg.Verbose)
	}

	if loadedCfg.ExportMode != cfg.ExportMode {
		t.Errorf("ExportMode mismatch: got %v, want %v", loadedCfg.ExportMode, cfg.ExportMode)
	}

	if loadedCfg.LogLevel != cfg.LogLevel {
		t.Errorf("LogLevel mismatch: got %v, want %v", loadedCfg.LogLevel, cfg.LogLevel)
	}
}

func TestSaveConfig_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "subdir", "config.yaml")

	cfg := DefaultConfig()
	err := cfg.SaveConfig(configPath)
	if err != nil {
		t.Fatalf("SaveConfig should create directories, got error: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file was not created in subdirectory")
	}
}

func TestGenerateExampleConfig(t *testing.T) {
	example := GenerateExampleConfig()

	// Should contain header comment
	if len(example) == 0 {
		t.Error("GenerateExampleConfig returned empty string")
	}

	// Should contain some expected content
	expectedStrings := []string{
		"# sniffl configuration file",
		"verbose:",
		"timeout:",
		"log_level:",
	}

	for _, expected := range expectedStrings {
		if !contains(example, expected) {
			t.Errorf("Expected example config to contain '%s'", expected)
		}
	}
}

func TestFileExists(t *testing.T) {
	// Test with existing file
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "existing.txt")
	err := os.WriteFile(existingFile, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if !fileExists(existingFile) {
		t.Error("fileExists should return true for existing file")
	}

	// Test with non-existing file
	nonExistingFile := filepath.Join(tmpDir, "nonexistent.txt")
	if fileExists(nonExistingFile) {
		t.Error("fileExists should return false for non-existing file")
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsAt(s, substr))))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestFindConfigFile(t *testing.T) {
	// Save original environment
	originalHome := os.Getenv("HOME")
	originalUserProfile := os.Getenv("USERPROFILE")
	originalAppData := os.Getenv("APPDATA")
	originalXDGConfig := os.Getenv("XDG_CONFIG_HOME")

	defer func() {
		// Restore environment
		os.Setenv("HOME", originalHome)
		os.Setenv("USERPROFILE", originalUserProfile)
		os.Setenv("APPDATA", originalAppData)
		os.Setenv("XDG_CONFIG_HOME", originalXDGConfig)
	}()

	tests := []struct {
		name           string
		setupFunc      func(t *testing.T) string // Returns temp dir
		expectedSuffix string                    // Expected suffix of found path
		shouldFind     bool
	}{
		{
			name: "current_directory_yaml",
			setupFunc: func(t *testing.T) string {
				tmpDir := t.TempDir()
				configFile := filepath.Join(tmpDir, ".sniffl.yaml")
				if err := os.WriteFile(configFile, []byte("test: true"), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}
				// Change to temp directory
				oldWd, _ := os.Getwd()
				os.Chdir(tmpDir)
				t.Cleanup(func() { os.Chdir(oldWd) })
				return tmpDir
			},
			expectedSuffix: ".sniffl.yaml",
			shouldFind:     true,
		},
		{
			name: "current_directory_yml",
			setupFunc: func(t *testing.T) string {
				tmpDir := t.TempDir()
				configFile := filepath.Join(tmpDir, ".sniffl.yml")
				if err := os.WriteFile(configFile, []byte("test: true"), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}
				// Change to temp directory
				oldWd, _ := os.Getwd()
				os.Chdir(tmpDir)
				t.Cleanup(func() { os.Chdir(oldWd) })
				return tmpDir
			},
			expectedSuffix: ".sniffl.yml",
			shouldFind:     true,
		},
		{
			name: "home_directory_config",
			setupFunc: func(t *testing.T) string {
				tmpDir := t.TempDir()
				homeDir := filepath.Join(tmpDir, "home")
				if err := os.MkdirAll(homeDir, 0755); err != nil {
					t.Fatalf("Failed to create home dir: %v", err)
				}

				configFile := filepath.Join(homeDir, ".sniffl.yaml")
				if err := os.WriteFile(configFile, []byte("test: true"), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}

				// Set HOME environment
				os.Setenv("HOME", homeDir)
				if runtime.GOOS == "windows" {
					os.Setenv("USERPROFILE", homeDir)
				}

				return tmpDir
			},
			expectedSuffix: ".sniffl.yaml",
			shouldFind:     true,
		},
		{
			name: "no_config_found",
			setupFunc: func(t *testing.T) string {
				tmpDir := t.TempDir()
				// Set HOME to empty temp dir
				os.Setenv("HOME", tmpDir)
				if runtime.GOOS == "windows" {
					os.Setenv("USERPROFILE", tmpDir)
				}
				os.Unsetenv("APPDATA")
				os.Unsetenv("XDG_CONFIG_HOME")

				// Change to temp directory
				oldWd, _ := os.Getwd()
				os.Chdir(tmpDir)
				t.Cleanup(func() { os.Chdir(oldWd) })

				return tmpDir
			},
			shouldFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := tt.setupFunc(t)

			result := findConfigFile()

			if tt.shouldFind {
				if result == "" {
					t.Error("Expected to find config file but got empty string")
				} else if !strings.HasSuffix(result, tt.expectedSuffix) {
					t.Errorf("Expected path to end with %q, got: %s", tt.expectedSuffix, result)
				}

				// Verify file actually exists
				if !fileExists(result) {
					t.Errorf("Found config path %q does not exist", result)
				}
			} else {
				if result != "" {
					t.Errorf("Expected no config file found, but got: %s", result)
				}
			}

			_ = tmpDir // Use tmpDir to avoid unused variable warning
		})
	}
}

func TestFindConfigFile_OSSpecific(t *testing.T) {
	// Save original environment
	originalHome := os.Getenv("HOME")
	originalUserProfile := os.Getenv("USERPROFILE")
	originalAppData := os.Getenv("APPDATA")
	originalXDGConfig := os.Getenv("XDG_CONFIG_HOME")

	defer func() {
		// Restore environment
		os.Setenv("HOME", originalHome)
		os.Setenv("USERPROFILE", originalUserProfile)
		os.Setenv("APPDATA", originalAppData)
		os.Setenv("XDG_CONFIG_HOME", originalXDGConfig)
	}()

	tmpDir := t.TempDir()
	homeDir := filepath.Join(tmpDir, "home")
	if err := os.MkdirAll(homeDir, 0755); err != nil {
		t.Fatalf("Failed to create home dir: %v", err)
	}

	os.Setenv("HOME", homeDir)
	if runtime.GOOS == "windows" {
		os.Setenv("USERPROFILE", homeDir)
	}

	switch runtime.GOOS {
	case "windows":
		t.Run("windows_appdata", func(t *testing.T) {
			appDataDir := filepath.Join(tmpDir, "appdata")
			configDir := filepath.Join(appDataDir, "sniffl")
			if err := os.MkdirAll(configDir, 0755); err != nil {
				t.Fatalf("Failed to create config dir: %v", err)
			}

			configFile := filepath.Join(configDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte("test: true"), 0644); err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			os.Setenv("APPDATA", appDataDir)

			result := findConfigFile()
			if result == "" {
				t.Error("Expected to find Windows APPDATA config file")
			} else if !strings.Contains(result, "sniffl") {
				t.Errorf("Expected path to contain 'sniffl', got: %s", result)
			}
		})

		t.Run("windows_fallback", func(t *testing.T) {
			// Test fallback when APPDATA is not set
			os.Unsetenv("APPDATA")

			fallbackDir := filepath.Join(homeDir, "AppData", "Roaming", "sniffl")
			if err := os.MkdirAll(fallbackDir, 0755); err != nil {
				t.Fatalf("Failed to create fallback dir: %v", err)
			}

			configFile := filepath.Join(fallbackDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte("test: true"), 0644); err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			result := findConfigFile()
			if result == "" {
				t.Error("Expected to find Windows fallback config file")
			}
		})

	case "darwin":
		t.Run("macos_preferences", func(t *testing.T) {
			prefsDir := filepath.Join(homeDir, "Library", "Preferences", "sniffl")
			if err := os.MkdirAll(prefsDir, 0755); err != nil {
				t.Fatalf("Failed to create preferences dir: %v", err)
			}

			configFile := filepath.Join(prefsDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte("test: true"), 0644); err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			result := findConfigFile()
			if result == "" {
				t.Error("Expected to find macOS preferences config file")
			} else if !strings.Contains(result, "Library/Preferences") {
				t.Errorf("Expected path to contain 'Library/Preferences', got: %s", result)
			}
		})

	default: // Linux/Unix
		t.Run("linux_xdg_config", func(t *testing.T) {
			xdgDir := filepath.Join(tmpDir, "xdg-config")
			configDir := filepath.Join(xdgDir, "sniffl")
			if err := os.MkdirAll(configDir, 0755); err != nil {
				t.Fatalf("Failed to create XDG config dir: %v", err)
			}

			configFile := filepath.Join(configDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte("test: true"), 0644); err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			os.Setenv("XDG_CONFIG_HOME", xdgDir)

			result := findConfigFile()
			if result == "" {
				t.Error("Expected to find XDG config file")
			} else if !strings.Contains(result, "sniffl") {
				t.Errorf("Expected path to contain 'sniffl', got: %s", result)
			}
		})

		t.Run("linux_fallback", func(t *testing.T) {
			// Test fallback when XDG_CONFIG_HOME is not set
			os.Unsetenv("XDG_CONFIG_HOME")

			configDir := filepath.Join(homeDir, ".config", "sniffl")
			if err := os.MkdirAll(configDir, 0755); err != nil {
				t.Fatalf("Failed to create .config dir: %v", err)
			}

			configFile := filepath.Join(configDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte("test: true"), 0644); err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			result := findConfigFile()
			if result == "" {
				t.Error("Expected to find .config fallback file")
			}
		})
	}
}

func TestLoadConfig_WithFoundFile(t *testing.T) {
	// Test LoadConfig when it finds a file via findConfigFile
	tmpDir := t.TempDir()

	// Create config file in current directory
	configFile := filepath.Join(tmpDir, ".sniffl.yaml")
	configContent := `
verbose: true
timeout: 60s
concurrency: 10
log_level: debug
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Change to temp directory so findConfigFile finds it
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// Load config with empty path (should trigger findConfigFile)
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify loaded values
	if !cfg.Verbose {
		t.Error("Expected Verbose to be true")
	}

	if cfg.Timeout != 60*time.Second {
		t.Errorf("Expected Timeout 60s, got %v", cfg.Timeout)
	}

	if cfg.Concurrency != 10 {
		t.Errorf("Expected Concurrency 10, got %d", cfg.Concurrency)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("Expected LogLevel 'debug', got %q", cfg.LogLevel)
	}
}

func TestGenerateExampleConfig_Content(t *testing.T) {
	example := GenerateExampleConfig()

	// Test that example contains expected sections
	expectedSections := []string{
		"# sniffl configuration file",
		"verbose:",
		"timeout:",
		"concurrency:",
		"export_mode:",
		"log_level:",
		"screenshot_",
	}

	for _, section := range expectedSections {
		if !strings.Contains(example, section) {
			t.Errorf("Expected example config to contain %q", section)
		}
	}

	// Test that it's valid YAML by trying to unmarshal
	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(example), cfg); err != nil {
		t.Errorf("Generated example config is not valid YAML: %v", err)
	}
}

func TestConfig_AllFields(t *testing.T) {
	// Test that all config fields can be set and retrieved
	cfg := &Config{
		Verbose:                 true,
		Timeout:                 45 * time.Second,
		Concurrency:             8,
		HTTPSProxy:              "http://proxy.example.com:8080",
		ExportMode:              "bundle",
		ExportDir:               "/tmp/exports",
		RetryAttempts:           5,
		RetryDelay:              2 * time.Second,
		CTShowExpired:           true,
		ScreenshotOutputDir:     "/tmp/screenshots",
		ScreenshotTimeout:       30 * time.Second,
		ScreenshotViewportW:     1366,
		ScreenshotViewportH:     768,
		ScreenshotFullPage:      true,
		ScreenshotWaitTime:      5 * time.Second,
		ScreenshotUserAgent:     "Custom Agent",
		ScreenshotConcurrency:   3,
		ScreenshotChromePath:    "/usr/bin/chrome",
		ScreenshotSkipPortCheck: true,
		ScreenshotIgnoreSSL:     true,
		LogLevel:                "warn",
		LogFormat:               "json",
		OutputDirPermissions:    0750,
		OutputFilePermissions:   0640,
	}

	// Save and reload to test serialization
	tmpFile := filepath.Join(t.TempDir(), "full-config.yaml")
	if err := cfg.SaveConfig(tmpFile); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	reloadedCfg, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}

	// Compare key fields
	if reloadedCfg.Verbose != cfg.Verbose {
		t.Errorf("Verbose mismatch: expected %v, got %v", cfg.Verbose, reloadedCfg.Verbose)
	}

	if reloadedCfg.Timeout != cfg.Timeout {
		t.Errorf("Timeout mismatch: expected %v, got %v", cfg.Timeout, reloadedCfg.Timeout)
	}

	if reloadedCfg.HTTPSProxy != cfg.HTTPSProxy {
		t.Errorf("HTTPSProxy mismatch: expected %v, got %v", cfg.HTTPSProxy, reloadedCfg.HTTPSProxy)
	}

	if reloadedCfg.ScreenshotViewportW != cfg.ScreenshotViewportW {
		t.Errorf("ScreenshotViewportW mismatch: expected %v, got %v", cfg.ScreenshotViewportW, reloadedCfg.ScreenshotViewportW)
	}
}

// Benchmark tests
func BenchmarkLoadConfig(b *testing.B) {
	tmpFile := filepath.Join(b.TempDir(), "bench-config.yaml")
	cfg := DefaultConfig()
	cfg.SaveConfig(tmpFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = LoadConfig(tmpFile)
	}
}

func BenchmarkSaveConfig(b *testing.B) {
	cfg := DefaultConfig()
	tmpDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tmpFile := filepath.Join(tmpDir, fmt.Sprintf("bench-config-%d.yaml", i))
		_ = cfg.SaveConfig(tmpFile)
	}
}

func BenchmarkFindConfigFile(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = findConfigFile()
	}
}

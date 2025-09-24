package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

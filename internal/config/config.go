// Package config provides configuration management for sniffl
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Default configuration values
const (
	// DefaultTimeout is the default timeout for network operations
	DefaultTimeout = 30 * time.Second
	// DefaultConcurrency is the default number of concurrent operations
	DefaultConcurrency = 5
	// DefaultRetryAttempts is the default number of retry attempts
	DefaultRetryAttempts = 3
	// DefaultRetryDelay is the default delay between retries
	DefaultRetryDelay = time.Second
)

// File permission constants
const (
	// DirPermissions are the permissions for created directories
	DirPermissions = 0755
	// FilePermissions are the permissions for created files
	FilePermissions = 0644
)

// Config represents the application configuration
type Config struct {
	// Global settings
	Verbose     bool          `yaml:"verbose"`
	Timeout     time.Duration `yaml:"timeout"`
	Concurrency int           `yaml:"concurrency"`

	// Network settings
	HTTPSProxy string `yaml:"https_proxy"`

	// Export settings
	ExportMode string `yaml:"export_mode"` // single, bundle, full_bundle
	ExportDir  string `yaml:"export_dir"`

	// Retry settings
	RetryAttempts int           `yaml:"retry_attempts"`
	RetryDelay    time.Duration `yaml:"retry_delay"`

	// CT settings
	CTShowExpired bool `yaml:"ct_show_expired"`

	// Screenshot settings
	ScreenshotOutputDir     string        `yaml:"screenshot_output_dir"`
	ScreenshotTimeout       time.Duration `yaml:"screenshot_timeout"`
	ScreenshotViewportW     int           `yaml:"screenshot_viewport_width"`
	ScreenshotViewportH     int           `yaml:"screenshot_viewport_height"`
	ScreenshotFullPage      bool          `yaml:"screenshot_full_page"`
	ScreenshotWaitTime      time.Duration `yaml:"screenshot_wait_time"`
	ScreenshotUserAgent     string        `yaml:"screenshot_user_agent"`
	ScreenshotConcurrency   int           `yaml:"screenshot_concurrency"`
	ScreenshotAutoDownload  bool          `yaml:"screenshot_auto_download"`
	ScreenshotChromePath    string        `yaml:"screenshot_chrome_path"`
	ScreenshotSkipPortCheck bool          `yaml:"screenshot_skip_port_check"`
	ScreenshotIgnoreSSL     bool          `yaml:"screenshot_ignore_ssl_errors"`

	// Logging settings
	LogLevel  string `yaml:"log_level"`  // debug, info, warn, error
	LogFormat string `yaml:"log_format"` // text, json
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Verbose:                 false,
		Timeout:                 DefaultTimeout,
		Concurrency:             DefaultConcurrency,
		ExportMode:              "",
		ExportDir:               ".",
		RetryAttempts:           DefaultRetryAttempts,
		RetryDelay:              DefaultRetryDelay,
		CTShowExpired:           false,
		ScreenshotOutputDir:     "screenshots",
		ScreenshotTimeout:       30 * time.Second,
		ScreenshotViewportW:     1920,
		ScreenshotViewportH:     1080,
		ScreenshotFullPage:      true,
		ScreenshotWaitTime:      2 * time.Second,
		ScreenshotUserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		ScreenshotConcurrency:   5,
		ScreenshotAutoDownload:  true,
		ScreenshotChromePath:    "",
		ScreenshotSkipPortCheck: false,
		ScreenshotIgnoreSSL:     true, // Default to true for network reconnaissance
		LogLevel:                "warn",
		LogFormat:               "text",
	}
}

// LoadConfig loads configuration from file, falling back to defaults
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// If no config path specified, try default locations
	if configPath == "" {
		configPath = findConfigFile()
	}

	// If config file exists, load it
	if configPath != "" && fileExists(configPath) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", configPath, err)
		}
	}

	return config, nil
}

// SaveConfig saves the configuration to a file
func (c *Config) SaveConfig(configPath string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, DirPermissions); err != nil {
		return fmt.Errorf("failed to create config directory %s: %w", dir, err)
	}

	if err := os.WriteFile(configPath, data, FilePermissions); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", configPath, err)
	}

	return nil
}

// findConfigFile looks for config files in standard locations
func findConfigFile() string {
	locations := []string{
		".sniffl.yaml",
		".sniffl.yml",
	}

	// Check home directory
	if home, err := os.UserHomeDir(); err == nil {
		locations = append(locations,
			filepath.Join(home, ".sniffl.yaml"),
			filepath.Join(home, ".sniffl.yml"),
			filepath.Join(home, ".config", "sniffl", "config.yaml"),
			filepath.Join(home, ".config", "sniffl", "config.yml"),
		)
	}

	for _, path := range locations {
		if fileExists(path) {
			return path
		}
	}

	return ""
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GenerateExampleConfig creates an example configuration file
func GenerateExampleConfig() string {
	config := DefaultConfig()
	// Set some example values
	config.Verbose = true
	config.ExportMode = "bundle"
	config.RetryAttempts = 5
	config.LogLevel = "info"

	data, _ := yaml.Marshal(config)

	header := `# sniffl configuration file
# This file contains default settings for the sniffl certificate tool
# Place this file at ~/.sniffl.yaml or ~/.config/sniffl/config.yaml

`

	return header + string(data)
}

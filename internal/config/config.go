package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultTimeout       = 30 * time.Second
	DefaultConcurrency   = 5
	DefaultRetryAttempts = 3
	DefaultRetryDelay    = time.Second
)

const (
	DirPermissions  = 0o700
	FilePermissions = 0o600
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
	ScreenshotChromePath    string        `yaml:"screenshot_chrome_path"`
	ScreenshotSkipPortCheck bool          `yaml:"screenshot_skip_port_check"`
	ScreenshotIgnoreSSL     bool          `yaml:"screenshot_ignore_ssl_errors"`

	// Logging settings
	LogLevel  string `yaml:"log_level"`  // debug, info, warn, error
	LogFormat string `yaml:"log_format"` // text, json

	// Output permissions (override defaults if needed)
	OutputDirPermissions  os.FileMode `yaml:"output_dir_permissions"`
	OutputFilePermissions os.FileMode `yaml:"output_file_permissions"`
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
		ScreenshotChromePath:    "",
		ScreenshotSkipPortCheck: false,
		ScreenshotIgnoreSSL:     true, // Default to true for network reconnaissance
		LogLevel:                "warn",
		LogFormat:               "text",
		OutputDirPermissions:    DirPermissions,
		OutputFilePermissions:   FilePermissions,
	}
}

// LoadConfig loads configuration from file, falling back to defaults
// It searches for config files in standard locations and merges with defaults
func LoadConfig(configPath string) (*Config, error) {
	return LoadConfigWithExplicitFlag(configPath, false)
}

// LoadConfigWithExplicitFlag loads configuration with a flag indicating if the path was explicitly provided
func LoadConfigWithExplicitFlag(configPath string, explicit bool) (*Config, error) {
	config := DefaultConfig()

	// If no config path specified, try default locations
	if configPath == "" {
		configPath = findConfigFile()
	}

	// If config file was explicitly specified but doesn't exist, return error
	if configPath != "" && !fileExists(configPath) && explicit {
		return nil, fmt.Errorf("failed to load config: config file not found: %s", configPath)
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

	// Add OS-specific config locations
	if home, err := os.UserHomeDir(); err == nil {
		// Always check home directory for dotfiles
		locations = append(locations,
			filepath.Join(home, ".sniffl.yaml"),
			filepath.Join(home, ".sniffl.yml"),
		)
		
		// Add OS-specific standard config locations
		switch runtime.GOOS {
		case "windows":
			// Windows: %APPDATA%\sniffl\config.yaml
			if appData := os.Getenv("APPDATA"); appData != "" {
				locations = append(locations,
					filepath.Join(appData, "sniffl", "config.yaml"),
					filepath.Join(appData, "sniffl", "config.yml"),
				)
			} else {
				// Fallback to user profile
				locations = append(locations,
					filepath.Join(home, "AppData", "Roaming", "sniffl", "config.yaml"),
					filepath.Join(home, "AppData", "Roaming", "sniffl", "config.yml"),
				)
			}
			
		case "darwin":
			// macOS: ~/Library/Preferences/sniffl/config.yaml
			locations = append(locations,
				filepath.Join(home, "Library", "Preferences", "sniffl", "config.yaml"),
				filepath.Join(home, "Library", "Preferences", "sniffl", "config.yml"),
			)
			
		default:
			// Linux/Unix: Follow XDG Base Directory specification
			// XDG_CONFIG_HOME or ~/.config/sniffl/config.yaml
			if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
				locations = append(locations,
					filepath.Join(xdgConfig, "sniffl", "config.yaml"),
					filepath.Join(xdgConfig, "sniffl", "config.yml"),
				)
			} else {
				locations = append(locations,
					filepath.Join(home, ".config", "sniffl", "config.yaml"),
					filepath.Join(home, ".config", "sniffl", "config.yml"),
				)
			}
		}
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

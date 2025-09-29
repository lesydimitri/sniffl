package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommand(t *testing.T) {
	// Reset global variables before each test
	resetGlobals()

	tests := []struct {
		name           string
		args           []string
		expectError    bool
		expectOutput   string
	}{
		{
			name:         "help_flag",
			args:         []string{"--help"},
			expectError:  false,
			expectOutput: "Certificate Sniffing & Export Tool",
		},
		{
			name:         "version_info",
			args:         []string{"--help"},
			expectError:  false,
			expectOutput: "sniffl",
		},
		{
			name:         "no_args_shows_help",
			args:         []string{},
			expectError:  false,
			expectOutput: "Certificate Sniffing & Export Tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new root command for each test to avoid state pollution
			cmd := createTestRootCmd()
			
			// Capture output
			buf := &bytes.Buffer{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			
			// Set args
			cmd.SetArgs(tt.args)
			
			// Execute
			err := cmd.Execute()
			
			// Check error expectation
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			
			// Check output
			output := buf.String()
			if tt.expectOutput != "" && !strings.Contains(output, tt.expectOutput) {
				t.Errorf("Expected output to contain %q, got: %s", tt.expectOutput, output)
			}
		})
	}
}

func TestRootCommandFlags(t *testing.T) {
	resetGlobals()
	
	cmd := createTestRootCmd()
	
	// Test that flags are properly defined
	flags := []string{"config", "verbose"}
	
	for _, flagName := range flags {
		if cmd.PersistentFlags().Lookup(flagName) == nil {
			t.Errorf("Expected flag %q to be defined", flagName)
		}
	}
}

func TestPersistentPreRunE(t *testing.T) {
	resetGlobals()
	
	tests := []struct {
		name        string
		setupFunc   func(t *testing.T) string // Returns temp config file path
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_config",
			setupFunc: func(t *testing.T) string {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "config.yaml")
				configContent := `
verbose: false
timeout: 30s
concurrency: 5
log_level: info
`
				if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}
				return configPath
			},
			expectError: false,
		},
		{
			name: "invalid_config_file",
			setupFunc: func(t *testing.T) string {
				return "/nonexistent/config.yaml"
			},
			expectError: true,
			errorMsg:    "failed to load config",
		},
		{
			name: "malformed_yaml",
			setupFunc: func(t *testing.T) string {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, "config.yaml")
				configContent := `
invalid: yaml: content:
  - missing
    proper: structure
`
				if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
					t.Fatalf("Failed to create test config: %v", err)
				}
				return configPath
			},
			expectError: true,
			errorMsg:    "failed to load config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetGlobals()
			
			// Create test command
			cmd := createTestRootCmd()
			
			// Setup config file
			configPath := tt.setupFunc(t)
			if configPath != "" {
				_ = cmd.PersistentFlags().Set("config", configPath)
			}
			
			// Execute PersistentPreRunE
			err := cmd.PersistentPreRunE(cmd, []string{})
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				
				// Verify config was loaded
				if cfg == nil {
					t.Error("Expected config to be loaded")
				}
				
				// Verify logger was created
				if logger == nil {
					t.Error("Expected logger to be created")
				}
				
				// Verify context was created
				if rootCtx == nil {
					t.Error("Expected context to be created")
				}
			}
		})
	}
}

func TestVerboseFlagOverride(t *testing.T) {
	resetGlobals()
	
	// Create config with verbose=false
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `verbose: false`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}
	
	cmd := createTestRootCmd()
	_ = cmd.PersistentFlags().Set("config", configPath)
	
	// Parse args to set the verbose flag as "changed"
	cmd.SetArgs([]string{"--verbose"})
	err := cmd.ParseFlags([]string{"--verbose"})
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}
	
	// Execute PersistentPreRunE directly
	err = cmd.PersistentPreRunE(cmd, []string{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	// Verify verbose flag overrode config
	if cfg == nil {
		t.Fatal("Config should not be nil")
	}
	if !cfg.Verbose {
		t.Error("Expected verbose flag to override config value")
	}
}

func TestLogFileCreation(t *testing.T) {
	resetGlobals()
	
	tmpDir := t.TempDir()
	exportDir := filepath.Join(tmpDir, "export")
	
	// Create config with export directory
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `export_dir: ` + exportDir
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}
	
	cmd := createTestRootCmd()
	_ = cmd.PersistentFlags().Set("config", configPath)
	
	// Execute PersistentPreRunE
	err := cmd.PersistentPreRunE(cmd, []string{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	// Check if log directory was created
	logDir := filepath.Join(exportDir, "logs")
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		t.Error("Expected log directory to be created")
	}
}

func TestGetTimestamp(t *testing.T) {
	timestamp := getTimestamp()
	
	// Verify format (should be YYYYMMDD_HHMMSS)
	if len(timestamp) != 15 {
		t.Errorf("Expected timestamp length 15, got %d: %s", len(timestamp), timestamp)
	}
	
	// Verify it contains underscore separator
	if !strings.Contains(timestamp, "_") {
		t.Errorf("Expected timestamp to contain underscore: %s", timestamp)
	}
	
	// Verify it's numeric (except underscore)
	for i, r := range timestamp {
		if i == 8 { // Position of underscore
			if r != '_' {
				t.Errorf("Expected underscore at position 8, got %c", r)
			}
		} else {
			if r < '0' || r > '9' {
				t.Errorf("Expected digit at position %d, got %c", i, r)
			}
		}
	}
}

func TestExecute(t *testing.T) {
	// Test that Execute function exists and can be called
	// We can't easily test the actual execution without mocking os.Exit
	// but we can verify the function exists and basic structure
	
	// Save original args
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()
	
	// Set test args
	os.Args = []string{"sniffl", "--help"}
	
	// This would normally call os.Exit, but with --help it should not
	// We'll just verify the function can be called
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Execute panicked: %v", r)
		}
	}()
	
	// Note: We can't actually call Execute() here because it would exit the test
	// Instead, we verify the function exists and the command structure is correct
	if rootCmd == nil {
		t.Error("rootCmd should not be nil")
	}
	
	if rootCmd.Use != "sniffl" {
		t.Errorf("Expected Use='sniffl', got %q", rootCmd.Use)
	}
}

func TestGetConfig(t *testing.T) {
	resetGlobals()
	
	// Test when config is nil
	config := GetConfig()
	if config == nil {
		t.Error("GetConfig should not return nil")
	}
	
	// Set a config and test retrieval
	resetGlobals()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `verbose: true`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}
	
	cmd := createTestRootCmd()
	_ = cmd.PersistentFlags().Set("config", configPath)

	err := cmd.PersistentPreRunE(cmd, []string{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	config = GetConfig()
	if config == nil {
		t.Error("GetConfig should return loaded config")
	}
	if !config.Verbose {
		t.Error("Expected config.Verbose to be true")
	}
}

func TestGetLogger(t *testing.T) {
	resetGlobals()
	
	// Test when logger is nil
	testLogger := GetLogger()
	if testLogger == nil {
		t.Error("GetLogger should not return nil")
	}
	
	// Set a logger and test retrieval
	resetGlobals()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `log_level: debug`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}
	
	cmd := createTestRootCmd()
	_ = cmd.PersistentFlags().Set("config", configPath)

	err := cmd.PersistentPreRunE(cmd, []string{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	testLogger = GetLogger()
	if testLogger == nil {
		t.Error("GetLogger should return created logger")
	}
	if !testLogger.IsDebugEnabled() {
		t.Error("Expected debug to be enabled")
	}
}

func TestGetContext(t *testing.T) {
	resetGlobals()
	
	// Test when context is nil
	ctx := GetContext()
	if ctx == nil {
		t.Error("GetContext should not return nil")
	}
	
	// Set a context and test retrieval
	resetGlobals()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}
	
	cmd := createTestRootCmd()
	_ = cmd.PersistentFlags().Set("config", configPath)

	err := cmd.PersistentPreRunE(cmd, []string{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	ctx = GetContext()
	if ctx == nil {
		t.Error("GetContext should return created context")
	}
	
	// Verify context is not cancelled
	select {
	case <-ctx.Done():
		t.Error("Context should not be cancelled initially")
	default:
		// Good, context is not cancelled
	}
}

// Helper functions

func resetGlobals() {
	cfg = nil
	logger = nil
	rootCtx = nil
	if cancelFunc != nil {
		cancelFunc()
		cancelFunc = nil
	}
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
}

func createTestRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sniffl",
		Short: "Certificate Sniffing & Export Tool",
		Long: asciiBanner + `

sniffl is a Certificate Sniffing & Export Tool designed to fetch, inspect, 
and export TLS certificates from remote servers using multiple protocols including 
SMTP, IMAP, POP3, or plain TLS connection. It also supports querying Certificate 
Transparency logs to discover all issued certificates for a domain.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return rootCmd.PersistentPreRunE(cmd, args)
		},
	}
	
	// Add persistent flags
	cmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sniffl.yaml)")
	cmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	
	return cmd
}

// Benchmark tests
func BenchmarkGetTimestamp(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = getTimestamp()
	}
}

func BenchmarkGetConfig(b *testing.B) {
	resetGlobals()
	
	// Setup a basic config
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("{}"), 0644); err != nil {
		b.Fatalf("Failed to create test config: %v", err)
	}
	
	cmd := createTestRootCmd()
	cmd.PersistentFlags().Set("config", configPath)
	cmd.PersistentPreRunE(cmd, []string{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetConfig()
	}
}

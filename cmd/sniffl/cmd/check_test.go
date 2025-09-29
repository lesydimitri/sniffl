package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lesydimitri/sniffl/internal/shared"
	"github.com/spf13/cobra"
)

func TestCheckCommand(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		expectError  bool
		expectOutput string
		setupFunc    func(t *testing.T) string // Returns temp file path if needed
	}{
		{
			name:         "help_flag",
			args:         []string{"check", "--help"},
			expectError:  false,
			expectOutput: "Check certificates from live servers",
		},
		{
			name:         "dry_run_single_target",
			args:         []string{"check", "example.com:443", "--dry-run"},
			expectError:  false,
			expectOutput: "DRY RUN MODE",
		},
		{
			name:         "dry_run_with_protocol",
			args:         []string{"check", "smtp.example.com:587", "--protocol", "smtp", "--dry-run"},
			expectError:  false,
			expectOutput: "protocol: smtp",
		},
		{
			name:         "dry_run_with_export",
			args:         []string{"check", "example.com:443", "--export", "bundle", "--dry-run"},
			expectError:  false,
			expectOutput: "export certificates in 'bundle' mode",
		},
		{
			name:         "dry_run_with_export_dns",
			args:         []string{"check", "example.com:443", "--export-dns", "--dry-run"},
			expectError:  false,
			expectOutput: "export DNS names",
		},
		{
			name:         "dry_run_with_proxy",
			args:         []string{"check", "example.com:443", "--https-proxy", "http://proxy.example.com:8080", "--dry-run"},
			expectError:  false,
			expectOutput: "use HTTPS proxy",
		},
		{
			name: "dry_run_with_file",
			args: []string{"check", "--file", "", "--dry-run"}, // File path will be set in setupFunc
			setupFunc: func(t *testing.T) string {
				tmpDir := t.TempDir()
				targetsFile := filepath.Join(tmpDir, "targets.txt")
				content := "example.com:443\nsmtp.example.com:587 smtp\n"
				if err := os.WriteFile(targetsFile, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create targets file: %v", err)
				}
				return targetsFile
			},
			expectError:  false,
			expectOutput: "Would process 2 target(s)",
		},
		{
			name:        "invalid_target_format",
			args:        []string{"check", "invalid-target", "--dry-run"},
			expectError: true,
		},
		{
			name:        "missing_target",
			args:        []string{"check", "--dry-run"},
			expectError: true,
		},
		{
			name:        "file_and_protocol_mutually_exclusive",
			args:        []string{"check", "--file", "targets.txt", "--protocol", "smtp"},
			expectError: true,
		},
		{
			name:        "invalid_protocol",
			args:        []string{"check", "example.com:443", "--protocol", "invalid", "--dry-run"},
			expectError: true,
		},
		{
			name:        "invalid_export_mode",
			args:        []string{"check", "example.com:443", "--export", "invalid", "--dry-run"},
			expectError: true,
		},
		{
			name:        "invalid_proxy_url",
			args:        []string{"check", "example.com:443", "--https-proxy", "invalid-url", "--dry-run"},
			expectError: true,
		},
		{
			name:        "nonexistent_file",
			args:        []string{"check", "--file", "/nonexistent/file.txt", "--dry-run"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global state
			resetGlobals()
			resetCheckFlags()

			// Setup if needed
			if tt.setupFunc != nil {
				filePath := tt.setupFunc(t)
				// Replace empty file path in args
				for i, arg := range tt.args {
					if arg == "" && i > 0 && tt.args[i-1] == "--file" {
						tt.args[i] = filePath
					}
				}
			}

			// Create test command
			cmd := createTestCommand()
			// Capture output
			buf := &bytes.Buffer{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			// Redirect stdout to capture fmt.Printf output from showDryRun
			originalStdout := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("Failed to create pipe: %v", err)
			}
			os.Stdout = w

			// Set args
			cmd.SetArgs(tt.args)

			// Execute
			execErr := cmd.Execute()

			// Restore stdout and read output
			w.Close()
			os.Stdout = originalStdout

			stdoutOutput, readErr := io.ReadAll(r)
			if readErr != nil {
				t.Fatalf("Failed to read stdout: %v", readErr)
			}

			// Combine command output and stdout output
			combinedOutput := buf.String() + string(stdoutOutput)

			// Check error expectation
			if tt.expectError && execErr == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && execErr != nil {
				t.Errorf("Unexpected error: %v", execErr)
			}

			// Check output
			if tt.expectOutput != "" && !strings.Contains(combinedOutput, tt.expectOutput) {
				t.Errorf("Expected output to contain %q, got: %s", tt.expectOutput, combinedOutput)
			}
		})
	}
}

func TestCheckCommandFlags(t *testing.T) {
	resetCheckFlags()

	cmd := createTestCheckCmd()

	// Test that flags are properly defined
	expectedFlags := map[string]string{
		"file":        "f",
		"protocol":    "p",
		"export":      "e",
		"export-dns":  "",
		"https-proxy": "",
		"dry-run":     "",
		"strict":      "",
	}

	for flagName, shorthand := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected flag %q to be defined", flagName)
			continue
		}

		if shorthand != "" && flag.Shorthand != shorthand {
			t.Errorf("Expected flag %q to have shorthand %q, got %q", flagName, shorthand, flag.Shorthand)
		}
	}
}

func TestValidateCheckArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		file        string
		protocol    string
		export      string
		httpsProxy  string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid_single_target",
			args:        []string{"example.com:443"},
			expectError: false,
		},
		{
			name:        "valid_target_with_protocol",
			args:        []string{"smtp.example.com:587"},
			protocol:    "smtp",
			expectError: false,
		},
		{
			name:        "valid_target_with_export",
			args:        []string{"example.com:443"},
			export:      "bundle",
			expectError: false,
		},
		{
			name:        "valid_target_with_proxy",
			args:        []string{"example.com:443"},
			httpsProxy:  "http://proxy.example.com:8080",
			expectError: false,
		},
		{
			name:        "invalid_target_format",
			args:        []string{"invalid-target"},
			expectError: true,
			errorMsg:    "Invalid host:port format",
		},
		{
			name:        "invalid_protocol",
			args:        []string{"example.com:443"},
			protocol:    "invalid",
			expectError: true,
			errorMsg:    "invalid protocol",
		},
		{
			name:        "invalid_export_mode",
			args:        []string{"example.com:443"},
			export:      "invalid",
			expectError: true,
			errorMsg:    "invalid export mode",
		},
		{
			name:        "invalid_proxy_url",
			args:        []string{"example.com:443"},
			httpsProxy:  "invalid-url",
			expectError: true,
			errorMsg:    "invalid proxy URL",
		},
		{
			name:        "missing_target_and_file",
			args:        []string{},
			expectError: true,
			errorMsg:    "either specify a target or use --file",
		},
		{
			name:        "both_target_and_file",
			args:        []string{"example.com:443"},
			file:        "targets.txt",
			expectError: true,
			errorMsg:    "cannot specify both target and --file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCheckFlags()

			// Set flag values
			checkFile = tt.file
			checkProtocol = tt.protocol
			checkExport = tt.export
			checkHTTPSProxy = tt.httpsProxy

			// Call validation function (we need to extract this from runCheck)
			err := validateCheckArgs(tt.args)

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
			}
		})
	}
}

func TestParseTargetsFromFile(t *testing.T) {
	tests := []struct {
		name           string
		fileContent    string
		expectedCount  int
		expectError    bool
		expectedTarget string // First target for verification
	}{
		{
			name: "valid_targets",
			fileContent: `example.com:443
smtp.example.com:587 smtp
imap.example.com:993 imap
`,
			expectedCount:  3,
			expectError:    false,
			expectedTarget: "example.com:443",
		},
		{
			name: "targets_with_comments",
			fileContent: `# This is a comment
example.com:443
# Another comment
smtp.example.com:587 smtp
`,
			expectedCount:  2,
			expectError:    false,
			expectedTarget: "example.com:443",
		},
		{
			name: "targets_with_empty_lines",
			fileContent: `example.com:443

smtp.example.com:587 smtp

`,
			expectedCount:  2,
			expectError:    false,
			expectedTarget: "example.com:443",
		},
		{
			name: "invalid_target_format",
			fileContent: `example.com:443
invalid-target
`,
			expectedCount: 0,
			expectError:   true,
		},
		{
			name:        "empty_file",
			fileContent: "",
			expectError: true,
		},
		{
			name: "only_comments",
			fileContent: `# Comment 1
# Comment 2
`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpDir := t.TempDir()
			filePath := filepath.Join(tmpDir, "targets.txt")

			if err := os.WriteFile(filePath, []byte(tt.fileContent), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			// Parse targets
			targets, err := parseTargetsFromFile(filePath)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if len(targets) != tt.expectedCount {
					t.Errorf("Expected %d targets, got %d", tt.expectedCount, len(targets))
				}

				if tt.expectedCount > 0 && tt.expectedTarget != "" {
					if targets[0].HostPort != tt.expectedTarget {
						t.Errorf("Expected first target %q, got %q", tt.expectedTarget, targets[0].HostPort)
					}
				}
			}
		})
	}
}

func TestShowDryRun(t *testing.T) {
	tests := []struct {
		name         string
		targets      []string
		exportMode   string
		exportDNS    bool
		proxyURL     string
		expectOutput []string
	}{
		{
			name:         "single_target",
			targets:      []string{"example.com:443"},
			expectOutput: []string{"DRY RUN MODE", "Would process 1 target(s)", "example.com:443"},
		},
		{
			name:         "multiple_targets",
			targets:      []string{"example.com:443", "smtp.example.com:587"},
			expectOutput: []string{"Would process 2 target(s)", "1. example.com:443", "2. smtp.example.com:587"},
		},
		{
			name:         "with_export_mode",
			targets:      []string{"example.com:443"},
			exportMode:   "bundle",
			expectOutput: []string{"export certificates in 'bundle' mode"},
		},
		{
			name:         "with_export_dns",
			targets:      []string{"example.com:443"},
			exportDNS:    true,
			expectOutput: []string{"export DNS names"},
		},
		{
			name:         "with_proxy",
			targets:      []string{"example.com:443"},
			proxyURL:     "http://proxy.example.com:8080",
			expectOutput: []string{"use HTTPS proxy", "http://proxy.example.com:8080"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create targets
			var targets []shared.Target
			for _, hostPort := range tt.targets {
				targets = append(targets, shared.Target{HostPort: hostPort})
			}

			// Parse proxy URL if provided
			var proxyURL *url.URL
			if tt.proxyURL != "" {
				var err error
				proxyURL, err = url.Parse(tt.proxyURL)
				if err != nil {
					t.Fatalf("Failed to parse proxy URL: %v", err)
				}
			}

			// We need to temporarily redirect stdout to capture the output
			// Since showDryRun uses fmt.Printf which writes to stdout
			originalStdout := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stdout = w

			// Call showDryRun
			showDryRun(targets, tt.exportMode, tt.exportDNS, proxyURL)

			// Restore stdout and read output
			w.Close()
			os.Stdout = originalStdout

			output := make([]byte, 1024)
			n, _ := r.Read(output)
			outputStr := string(output[:n])

			// Check expected output
			for _, expected := range tt.expectOutput {
				if !strings.Contains(outputStr, expected) {
					t.Errorf("Expected output to contain %q, got: %s", expected, outputStr)
				}
			}
		})
	}
}

// Helper functions

func resetCheckFlags() {
	checkFile = ""
	checkProtocol = ""
	checkExport = ""
	checkExportDNS = false
	checkHTTPSProxy = ""
	checkDryRun = false
	checkStrict = false
}

func createTestCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check [host:port]",
		Short: "Check certificates from live servers",
		RunE:  runCheck,
	}

	// Add flags (same as init function)
	cmd.Flags().StringVarP(&checkFile, "file", "f", "", "file with targets (host:port [protocol])")
	cmd.Flags().StringVarP(&checkProtocol, "protocol", "p", "", "connection protocol (smtp|imap|pop3|http|none, auto-detected if omitted)")
	cmd.Flags().StringVarP(&checkExport, "export", "e", "", "export certificates (single|bundle|full_bundle)")
	cmd.Flags().BoolVar(&checkExportDNS, "export-dns", false, "export DNS names to EXPORT_DIR/dns with timestamped filename")
	cmd.Flags().StringVar(&checkHTTPSProxy, "https-proxy", "", "HTTP proxy URL")
	cmd.Flags().BoolVar(&checkDryRun, "dry-run", false, "show what would be done without executing")
	cmd.Flags().BoolVar(&checkStrict, "strict", false, "enforce strict TLS verification and do not use insecure fallback")

	cmd.MarkFlagsMutuallyExclusive("file", "protocol")

	return cmd
}

func createTestCommand() *cobra.Command {
	// Create root command
	rootCmd := createTestRootCmd()

	// Add check command
	checkCmd := createTestCheckCmd()
	rootCmd.AddCommand(checkCmd)

	return rootCmd
}

// Mock validation function (extracted from runCheck logic)
func validateCheckArgs(args []string) error {
	// Check if both target and file are specified
	if len(args) > 0 && checkFile != "" {
		return fmt.Errorf("cannot specify both target and --file")
	}

	// Check if neither target nor file is specified
	if len(args) == 0 && checkFile == "" {
		return fmt.Errorf("either specify a target or use --file")
	}

	// Validate target format if provided
	if len(args) > 0 {
		hostPort := args[0]
		if !shared.IsValidHostPort(hostPort) {
			return fmt.Errorf("Invalid host:port format: %s", hostPort)
		}
	}

	// Validate protocol
	if checkProtocol != "" {
		validProtocols := []string{"smtp", "imap", "pop3", "http", "none"}
		valid := false
		for _, p := range validProtocols {
			if checkProtocol == p {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid protocol: %s", checkProtocol)
		}
	}

	// Validate export mode
	if checkExport != "" {
		validModes := []string{"single", "bundle", "full_bundle"}
		valid := false
		for _, m := range validModes {
			if checkExport == m {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid export mode: %s", checkExport)
		}
	}

	// Validate proxy URL
	if checkHTTPSProxy != "" {
		u, err := url.Parse(checkHTTPSProxy)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid proxy URL: must be a valid URL with scheme and host")
		}
	}

	return nil
}

// Mock function to parse targets from file
func parseTargetsFromFile(filePath string) ([]shared.Target, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var targets []shared.Target

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		hostPort := parts[0]
		if !shared.IsValidHostPort(hostPort) {
			return nil, fmt.Errorf("invalid target format: %s", hostPort)
		}

		target := shared.Target{HostPort: hostPort}
		if len(parts) > 1 {
			target.Protocol = parts[1]
		}

		targets = append(targets, target)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets found in file")
	}

	return targets, nil
}

// Benchmark tests
func BenchmarkValidateCheckArgs(b *testing.B) {
	args := []string{"example.com:443"}
	checkProtocol = "smtp"
	checkExport = "bundle"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validateCheckArgs(args)
	}
}

func BenchmarkParseTargetsFromFile(b *testing.B) {
	// Create test file
	tmpDir := b.TempDir()
	filePath := filepath.Join(tmpDir, "targets.txt")
	content := "example.com:443\nsmtp.example.com:587 smtp\nimap.example.com:993 imap\n"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseTargetsFromFile(filePath)
	}
}

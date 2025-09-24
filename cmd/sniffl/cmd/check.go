package cmd

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/lesydimitri/sniffl/internal/check"
	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/lesydimitri/sniffl/internal/retry"
	"github.com/lesydimitri/sniffl/internal/shared"
)

var checkCmd = &cobra.Command{
	Use:   "check [host:port]",
	Short: "Check certificates from live servers",
	Long: `Check certificates from live servers using various protocols.

You can either specify a single host:port or use --file to check multiple targets.`,
	Example: `  # Check a single SMTP server
  sniffl check smtp.gmail.com:587 --protocol smtp --export bundle

  # Check multiple targets from file
  sniffl check --file targets.txt --export full_bundle --export-dns domains.txt

  # Use HTTP proxy
  sniffl check example.com:443 --https-proxy http://proxy.example.com:8080`,
	RunE: runCheck,
}

var (
	checkFile       string
	checkProtocol   string
	checkExport     string
	checkExportDNS  string
	checkHTTPSProxy string
	checkDryRun     bool
)

func init() {
	checkCmd.Flags().StringVarP(&checkFile, "file", "f", "", "file with targets (host:port [protocol])")
	checkCmd.Flags().StringVarP(&checkProtocol, "protocol", "p", "", "connection protocol (smtp|imap|pop3|http|none, auto-detected if omitted)")
	checkCmd.Flags().StringVarP(&checkExport, "export", "e", "", "export certificates (single|bundle|full_bundle)")
	checkCmd.Flags().StringVar(&checkExportDNS, "export-dns", "", "file to write DNS names")
	checkCmd.Flags().StringVar(&checkHTTPSProxy, "https-proxy", "", "HTTP proxy URL")
	checkCmd.Flags().BoolVar(&checkDryRun, "dry-run", false, "show what would be done without executing")
	
	// Mark file and positional args as mutually exclusive
	checkCmd.MarkFlagsMutuallyExclusive("file", "protocol")
}

func runCheck(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	cfg := GetConfig()
	ctx := GetContext()
	
	// Validate arguments
	if checkFile == "" && len(args) != 1 {
		return errors.NewValidationError("specify either a host:port or --file, not both")
	}
	
	if checkFile != "" && len(args) != 0 {
		return errors.NewValidationError("when using --file, don't specify a host:port")
	}
	
	// Validate export mode
	if checkExport != "" && checkExport != "single" && checkExport != "bundle" && checkExport != "full_bundle" {
		return errors.NewValidationError("invalid export mode: must be single, bundle, or full_bundle")
	}
	
	// Validate protocol
	if checkProtocol != "" && !shared.SupportedProtocols[checkProtocol] {
		return errors.NewValidationError("invalid protocol: must be smtp, imap, pop3, http, or none")
	}
	
	// Protocol flag is only valid with single host, not with file
	if checkProtocol != "" && checkFile != "" {
		return errors.NewValidationError("--protocol flag is only valid with single host, not with --file")
	}
	
	// Parse proxy URL if provided
	var proxyURL *url.URL
	if checkHTTPSProxy != "" {
		u, err := url.Parse(checkHTTPSProxy)
		if err != nil {
			return errors.WrapValidationError("invalid https-proxy", err)
		}
		proxyURL = u
	}
	
	// Parse targets
	var targets []shared.Target
	var err error
	
	if checkFile != "" {
		f, e := os.Open(checkFile)
		if e != nil {
			return errors.WrapFileError(fmt.Sprintf("failed to open targets file %s", checkFile), e)
		}
		defer func() {
			if err := f.Close(); err != nil {
				logger.Failure("Failed to close targets file", "error", err)
			}
		}()
		targets, err = shared.ParseTargets(f, "")
		if err != nil {
			return errors.WrapValidationError(fmt.Sprintf("failed to parse targets from file %s", checkFile), err)
		}
	} else {
		// Single host mode
		hostPort := args[0]
		if !shared.IsValidHostPort(hostPort) {
			return errors.NewValidationError(fmt.Sprintf("invalid host:port format: %s", hostPort))
		}
		targets = []shared.Target{{HostPort: hostPort, Protocol: strings.ToLower(checkProtocol)}}
	}
	
	// Show dry-run information
	if checkDryRun {
		return showDryRun(targets, checkExport, checkExportDNS, proxyURL)
	}
	
	// Setup DNS export file
	var dnsFile *os.File
	if checkExportDNS != "" {
		f, err := os.Create(checkExportDNS)
		if err != nil {
			return errors.WrapFileError("cannot create DNS export file", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				logger.Failure("Failed to close DNS export file", "error", err)
			}
		}()
		dnsFile = f
	}
	
	// Override config with command line options
	if checkExport != "" {
		cfg.ExportMode = checkExport
	}
	if checkHTTPSProxy != "" {
		cfg.HTTPSProxy = checkHTTPSProxy
	}
	
	// Create check configuration
	checkCfg := check.Config{
		ExportMode:  cfg.ExportMode,
		DNSExport:   dnsFile,
		HTTPSProxy:  proxyURL,
		Verbose:     cfg.Verbose,
		Concurrency: cfg.Concurrency,
		Out:         os.Stdout,
		Err:         os.Stderr,
		HTTPClient:  nil,
		Logger:      logger,
		FileCreator: func(name string) (io.WriteCloser, error) {
			// Join with export directory if specified
			filePath := name
			if cfg.ExportDir != "" && cfg.ExportDir != "." {
				filePath = filepath.Join(cfg.ExportDir, name)
			}
			
			// ensure parent dirs
			if dir := filepath.Dir(filePath); dir != "." {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return nil, errors.WrapFileError(fmt.Sprintf("failed to create directory %s", dir), err)
				}
			}
			file, err := os.Create(filePath)
			if err != nil {
				return nil, errors.WrapFileError(fmt.Sprintf("failed to create file %s", filePath), err)
			}
			return file, nil
		},
	}
	
	app := check.New(checkCfg)
	
	// Run with retry logic
	retryConfig := retry.Config{
		MaxAttempts: cfg.RetryAttempts,
		BaseDelay:   cfg.RetryDelay,
		MaxDelay:    cfg.Timeout,
		Multiplier:  2.0,
		Jitter:      true,
	}
	
	err = retry.Do(ctx, retryConfig, logger, func() error {
		return app.Run(ctx, targets)
	})
	
	if err != nil {
		return errors.WrapNetworkError("certificate check failed", err)
	}
	
	logger.Success("Certificate check completed successfully")
	return nil
}

func showDryRun(targets []shared.Target, exportMode, exportDNS string, proxyURL *url.URL) error {
	fmt.Println("=== DRY RUN MODE ===")
	fmt.Printf("Would process %d target(s):\n", len(targets))
	
	for i, target := range targets {
		fmt.Printf("  %d. %s", i+1, target.HostPort)
		if target.Protocol != "" {
			fmt.Printf(" (protocol: %s)", target.Protocol)
		}
		fmt.Println()
	}
	
	if exportMode != "" {
		fmt.Printf("Would export certificates in '%s' mode\n", exportMode)
	}
	
	if exportDNS != "" {
		fmt.Printf("Would export DNS names to: %s\n", exportDNS)
	}
	
	if proxyURL != nil {
		fmt.Printf("Would use HTTPS proxy: %s\n", proxyURL.String())
	}
	
	fmt.Println("=== END DRY RUN ===")
	return nil
}

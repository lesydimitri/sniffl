package cmd

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/lesydimitri/sniffl/internal/check"
	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/lesydimitri/sniffl/internal/retry"
	"github.com/lesydimitri/sniffl/internal/shared"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check [host:port]",
	Short: "Check certificates from live servers",
	Long: `Check certificates from live servers using various protocols.

You can either specify a single host:port or use --file to check multiple targets.`,
	Example: `  sniffl check smtp.gmail.com:587 --protocol smtp --export bundle
  sniffl check --file targets.txt --export full_bundle --export-dns
  sniffl check example.com:443 --https-proxy http://proxy.example.com:8080`,
	RunE: runCheck,
}

var (
	checkFile       string
	checkProtocol   string
	checkExport     string
	checkExportDNS  bool
	checkHTTPSProxy string
	checkDryRun     bool
	checkStrict     bool
)

func init() {
	checkCmd.Flags().StringVarP(&checkFile, "file", "f", "", "file with targets (host:port [protocol])")
	checkCmd.Flags().StringVarP(&checkProtocol, "protocol", "p", "", "connection protocol (smtp|imap|pop3|http|none, auto-detected if omitted)")
	checkCmd.Flags().StringVarP(&checkExport, "export", "e", "", "export certificates (single|bundle|full_bundle)")
	checkCmd.Flags().BoolVar(&checkExportDNS, "export-dns", false, "export DNS names to EXPORT_DIR/dns with timestamped filename")
	checkCmd.Flags().StringVar(&checkHTTPSProxy, "https-proxy", "", "HTTP proxy URL")
	checkCmd.Flags().BoolVar(&checkDryRun, "dry-run", false, "show what would be done without executing")
	checkCmd.Flags().BoolVar(&checkStrict, "strict", false, "enforce strict TLS verification and do not use insecure fallback")

	checkCmd.MarkFlagsMutuallyExclusive("file", "protocol")
}

func runCheck(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	cfg := GetConfig()
	ctx := GetContext()

	if checkFile == "" && len(args) != 1 {
		return errors.NewValidationError("specify either a host:port or --file, not both")
	}

	if checkFile != "" && len(args) != 0 {
		return errors.NewValidationError("when using --file, don't specify a host:port")
	}

	if checkExport != "" && checkExport != "single" && checkExport != "bundle" && checkExport != "full_bundle" {
		return errors.NewValidationError("invalid export mode: must be single, bundle, or full_bundle")
	}

	if checkProtocol != "" && !shared.SupportedProtocols[checkProtocol] {
		return errors.NewValidationError("invalid protocol: must be smtp, imap, pop3, http, or none")
	}

	if checkProtocol != "" && checkFile != "" {
		return errors.NewValidationError("--protocol flag is only valid with single host, not with --file")
	}
	var proxyURL *url.URL
	// Validate proxy URL
	if checkHTTPSProxy != "" {
		u, err := url.Parse(checkHTTPSProxy)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return errors.NewValidationError("invalid https-proxy URL: must be a valid URL with scheme and host")
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
			if closeErr := f.Close(); closeErr != nil {
				logger.Warn("Failed to close targets file", "path", checkFile, "error", closeErr)
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
		showDryRun(targets, checkExport, checkExportDNS, proxyURL)
		return nil
	}

	// Setup DNS export writer
	var dnsWriter io.Writer
	var dnsPath string
	if checkExportDNS {
		fileManager := shared.NewFileManager(cfg.OutputDirPermissions, cfg.OutputFilePermissions)
		
		// Determine base name: single target host or targets file name
		var base string
		if checkFile != "" {
			base = strings.TrimSuffix(filepath.Base(checkFile), filepath.Ext(checkFile))
		} else {
			// single target mode; extract host safely from args[0]
			hostPort := args[0]
			if shared.IsValidHostPort(hostPort) {
				if h, _, err := net.SplitHostPort(hostPort); err == nil {
					base = h
				} else {
					base = strings.ReplaceAll(hostPort, ":", "_")
				}
			} else {
				base = strings.ReplaceAll(hostPort, ":", "_")
			}
		}
		
		filename := fmt.Sprintf("%s_dns.txt", base)
		f, path, err := fileManager.CreateTimestampedFile(cfg.ExportDir, "dns", filename)
		if err != nil {
			return err
		}
		dnsPath = path
		defer fileManager.SafeCloseFile(f, dnsPath, logger)
		dnsWriter = f
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
		ExportMode:   cfg.ExportMode,
		DNSExport:    dnsWriter,
		HTTPSProxy:   proxyURL,
		Verbose:      cfg.Verbose,
		StrictVerify: checkStrict,
		Concurrency:  cfg.Concurrency,
		Out:          os.Stdout,
		Err:          os.Stderr,
		HTTPClient:   nil,
		Logger:       logger,
		FileCreator: func(name string) (io.WriteCloser, error) {
			fileManager := shared.NewFileManager(cfg.OutputDirPermissions, cfg.OutputFilePermissions)
			
			// Absolute paths (e.g., cache files) are respected as-is
			if filepath.IsAbs(name) {
				return fileManager.CreateFile(name)
			}

			// Certificates: EXPORT_DIR/certificates with timestamped filename
			base := filepath.Base(name)
			f, _, err := fileManager.CreateTimestampedFile(cfg.ExportDir, "certificates", base)
			return f, err
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

	// Concise stdout success message
	fmt.Println("Certificate check completed successfully")
	if dnsPath != "" {
		fmt.Printf("[+] Exported DNS names: %s\n", dnsPath)
	}
	logger.Success("Certificate check completed successfully")
	return nil
}

func showDryRun(targets []shared.Target, exportMode string, exportDNS bool, proxyURL *url.URL) {
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

	if exportDNS {
		if len(targets) == 1 {
			fmt.Println("Would export DNS names to: EXPORT_DIR/dns/<timestamp>_<host>_dns.txt")
		} else {
			fmt.Println("Would export DNS names to: EXPORT_DIR/dns/<timestamp>_<targets-file>_dns.txt")
		}
	}

	if proxyURL != nil {
		fmt.Printf("Would use HTTPS proxy: %s\n", proxyURL.String())
	}

	fmt.Println("=== END DRY RUN ===")
}

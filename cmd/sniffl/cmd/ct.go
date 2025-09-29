package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lesydimitri/sniffl/internal/ct"
	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/lesydimitri/sniffl/internal/retry"
	"github.com/spf13/cobra"
)

var ctCmd = &cobra.Command{
	Use:   "ct <domain>",
	Short: "Query Certificate Transparency logs for a domain",
	Long: `Query Certificate Transparency logs to discover all issued certificates 
for a domain and its subdomains.

CT queries show valid certificates by default. Use --show-expired to include 
expired certificates in results. Discovered domains are automatically filtered 
to include only relevant subdomains.`,
	Example: `  # Query CT logs for a domain
  sniffl ct example.com

  # Include expired certificates
  sniffl ct github.com --show-expired

    # Export discovered domains
    sniffl ct example.com --export-dns`,
	Args: cobra.ExactArgs(1),
	RunE: runCT,
}

var (
	ctShowExpired bool
	ctExportDNS   bool
	ctDryRun      bool
)

func init() {
	ctCmd.Flags().BoolVar(&ctShowExpired, "show-expired", false, "show expired certificates in CT results")
	ctCmd.Flags().BoolVar(&ctExportDNS, "export-dns", false, "export discovered DNS names to EXPORT_DIR/dns with timestamped filename")
	ctCmd.Flags().BoolVar(&ctDryRun, "dry-run", false, "show what would be done without executing")
}

func runCT(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	cfg := GetConfig()
	ctx := GetContext()

	domain := args[0]

	// Override config with command line options
	if ctShowExpired {
		cfg.CTShowExpired = ctShowExpired
	}

	// Show dry-run information
	if ctDryRun {
		showCTDryRun(domain, cfg.CTShowExpired, ctExportDNS)
		return nil
	}

	// Setup DNS export file
	var dnsFile *os.File
	var dnsPath string
	if ctExportDNS {
		// Place DNS under EXPORT_DIR/dns with timestamped name using domain
		dnsDir := filepath.Join(cfg.ExportDir, "dns")
		if err := os.MkdirAll(dnsDir, cfg.OutputDirPermissions); err != nil {
			return errors.WrapFileError("cannot create DNS export directory", err)
		}
		ts := time.Now().UTC().Format("20060102_150405")
		safeDomain := filepath.Base(domain)
		dnsPath = filepath.Join(dnsDir, fmt.Sprintf("%s_%s_dns.txt", ts, safeDomain))
		f, err := os.OpenFile(dnsPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, cfg.OutputFilePermissions)
		if err != nil {
			return errors.WrapFileError("cannot create DNS export file", err)
		}
		defer func() {
			if closeErr := f.Close(); closeErr != nil {
				logger.Warn("Failed to close DNS export file", "path", dnsPath, "error", closeErr)
			}
		}()
		dnsFile = f
	}

	logger.Info("Starting Certificate Transparency query", "domain", domain)

	// Create CT query with retry logic
	retryConfig := retry.Config{
		MaxAttempts: cfg.RetryAttempts,
		BaseDelay:   cfg.RetryDelay,
		MaxDelay:    cfg.Timeout,
		Multiplier:  2.0,
		Jitter:      true,
	}

	var ctQuery *ct.Query
	var entries []ct.Entry

	err := retry.Do(ctx, retryConfig, logger, func() error {
		var err error
		ctQuery, err = ct.NewQueryWithLogger(os.Stdout, os.Stderr, logger)
		if err != nil {
			return errors.WrapCTError("failed to initialize CT query", err)
		}

		entries, err = ctQuery.QueryDomain(domain)
		if err != nil {
			return errors.WrapCTError(fmt.Sprintf("failed to query CT logs for %s", domain), err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	defer func() {
		if err := ctQuery.Close(); err != nil {
			logger.Failure("Failed to close CT query", "error", err)
		}
	}()

	// Display results
	ctQuery.DisplayResults(domain, entries, cfg.CTShowExpired, dnsFile)

	// Concise stdout success message
	fmt.Printf("CT query completed: domain=%s, certificates_found=%d\n", domain, len(entries))
	if dnsPath != "" {
		fmt.Printf("[+] Exported DNS names: %s\n", dnsPath)
	}
	logger.Success("Certificate Transparency query completed successfully",
		"domain", domain,
		"certificates_found", len(entries))

	return nil
}

func showCTDryRun(domain string, showExpired bool, exportDNS bool) {
	fmt.Println("=== DRY RUN MODE ===")
	fmt.Printf("Would query Certificate Transparency logs for domain: %s\n", domain)

	if showExpired {
		fmt.Println("Would include expired certificates in results")
	} else {
		fmt.Println("Would show only valid certificates (default)")
	}

	if exportDNS {
		fmt.Println("Would export discovered DNS names to: EXPORT_DIR/dns/<timestamp>_<domain>_dns.txt")
	}

	fmt.Println("=== END DRY RUN ===")
}

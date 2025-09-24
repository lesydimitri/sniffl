package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lesydimitri/sniffl/internal/config"
	"github.com/lesydimitri/sniffl/internal/logging"
	"github.com/spf13/cobra"
)

const asciiBanner = ` ▗▄▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▄▖▗▖   
▐▌   ▐▛▚▖▐▌  █  ▐▌   ▐▌   ▐▌   
 ▝▀▚▖▐▌ ▝▜▌  █  ▐▛▀▀▘▐▛▀▀▘▐▌   
▗▄▄▞▘▐▌  ▐▌▗▄█▄▖▐▌   ▐▌   ▐▙▄▄▖`

var (
	cfgFile    string
	cfg        *config.Config
	logger     *logging.Logger
	rootCtx    context.Context
	cancelFunc context.CancelFunc
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sniffl",
	Short: "Certificate Sniffing & Export Tool",
	Long: asciiBanner + `

sniffl is a Certificate Sniffing & Export Tool designed to fetch, inspect, 
and export TLS certificates from remote servers using multiple protocols including 
SMTP, IMAP, POP3, or plain TLS connection. It also supports querying Certificate 
Transparency logs to discover all issued certificates for a domain.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		var err error
		cfg, err = config.LoadConfig(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Override config with command line flags
		if cmd.Flags().Changed("verbose") {
			verbose, _ := cmd.Flags().GetBool("verbose")
			cfg.Verbose = verbose
		}

		// Set log level based on verbose flag
		logLevel := cfg.LogLevel
		if cfg.Verbose {
			logLevel = "info" // Show info and debug when verbose
		}

		// Initialize logger
		logger = logging.New(logLevel, cfg.LogFormat, os.Stderr)

		// Create context with cancellation
		rootCtx, cancelFunc = context.WithCancel(context.Background())

		// Handle interrupt signals gracefully
		go func() {
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			<-sigChan
			logger.Info("Received interrupt signal, shutting down gracefully...")
			cancelFunc()
		}()

		return nil
	},
	Version: getVersion(),
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if cancelFunc != nil {
			cancelFunc()
		}
		os.Exit(1)
	}
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sniffl.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	// Add subcommands
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(ctCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(manCmd)
}

// getVersion returns the application version
// Set at build time
var version = "dev"

func getVersion() string {
	return version
}

// GetContext returns the root context
func GetContext() context.Context {
	return rootCtx
}

// GetConfig returns the loaded configuration
func GetConfig() *config.Config {
	return cfg
}

// GetLogger returns the configured logger
func GetLogger() *logging.Logger {
	return logger
}

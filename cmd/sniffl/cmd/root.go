package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

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
	logFile    *os.File
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
		var err error
		// Check if config flag was explicitly set
		explicitConfig := cmd.PersistentFlags().Changed("config")
		cfg, err = config.LoadConfigWithExplicitFlag(cfgFile, explicitConfig)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if cmd.Flags().Changed("verbose") {
			verbose, _ := cmd.Flags().GetBool("verbose")
			cfg.Verbose = verbose
		}

		logLevel := cfg.LogLevel
		if cfg.Verbose {
			logLevel = "debug"
		}

		var logOut io.Writer = os.Stderr
		if cfg.ExportDir != "" && cfg.ExportDir != "." {
			logDir := filepath.Join(cfg.ExportDir, "logs")
			if err := os.MkdirAll(logDir, cfg.OutputDirPermissions); err == nil {
				ts := getTimestamp()
				path := filepath.Join(logDir, fmt.Sprintf("%s_sniffl.log", ts))
				if f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, cfg.OutputFilePermissions); e == nil {
					logOut = f
					logFile = f
				}
			}
		}
		logger = logging.New(logLevel, cfg.LogFormat, logOut)
		rootCtx, cancelFunc = context.WithCancel(context.Background())
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
	defer func() {
		if cancelFunc != nil {
			cancelFunc()
		}
		if logFile != nil {
			if err := logFile.Close(); err != nil {
				// Log to stderr since our logger might be using this file
				fmt.Fprintf(os.Stderr, "Warning: failed to close log file: %v\n", err)
			}
		}
	}()
	
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sniffl.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(ctCmd)
	rootCmd.AddCommand(screenshotCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(manCmd)
}

var version = "dev"

func getVersion() string {
	return version
}

func getTimestamp() string {
	return time.Now().UTC().Format("20060102_150405")
}

// GetContext returns the root context
func GetContext() context.Context {
	if rootCtx == nil {
		return context.Background()
	}
	return rootCtx
}

// GetConfig returns the loaded configuration
func GetConfig() *config.Config {
	if cfg == nil {
		return config.DefaultConfig()
	}
	return cfg
}

// GetLogger returns the configured logger
func GetLogger() *logging.Logger {
	if logger == nil {
		return logging.New("warn", "text", os.Stderr)
	}
	return logger
}

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lesydimitri/sniffl/internal/config"
	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long:  `Manage sniffl configuration files.`,
}

var configInitCmd = &cobra.Command{
	Use:   "init [path]",
	Short: "Initialize a new configuration file",
	Long: `Initialize a new configuration file with default values.

If no path is specified, the config will be created at ~/.sniffl.yaml`,
	Example: `  # Create config in home directory
  sniffl config init

  # Create config at specific path
  sniffl config init ./my-config.yaml`,
	RunE: runConfigInit,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  `Display the current configuration values.`,
	RunE:  runConfigShow,
}

var configExampleCmd = &cobra.Command{
	Use:   "example",
	Short: "Show example configuration",
	Long:  `Display an example configuration file with all available options.`,
	RunE:  runConfigExample,
}

func init() {
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configExampleCmd)
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	logger := GetLogger()

	var configPath string
	if len(args) > 0 {
		configPath = args[0]
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return errors.WrapConfigError("failed to get home directory", err)
		}
		configPath = filepath.Join(home, ".sniffl.yaml")
	}

	// Check if file already exists
	if _, err := os.Stat(configPath); err == nil {
		return errors.NewConfigError(fmt.Sprintf("configuration file already exists: %s", configPath))
	}

	// Create default config
	cfg := config.DefaultConfig()

	// Save to file
	if err := cfg.SaveConfig(configPath); err != nil {
		return errors.WrapConfigError("failed to create configuration file", err)
	}

	logger.Success("Configuration file created", "path", configPath)
	fmt.Printf("Configuration file created at: %s\n", configPath)
	fmt.Println("You can now edit this file to customize your settings.")

	return nil
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	cfg := GetConfig()

	fmt.Println("Current Configuration:")
	fmt.Printf("  Verbose: %t\n", cfg.Verbose)
	fmt.Printf("  Timeout: %s\n", cfg.Timeout)
	fmt.Printf("  Concurrency: %d\n", cfg.Concurrency)
	fmt.Printf("  HTTPS Proxy: %s\n", cfg.HTTPSProxy)
	fmt.Printf("  Export Mode: %s\n", cfg.ExportMode)
	fmt.Printf("  Export Directory: %s\n", cfg.ExportDir)
	fmt.Printf("  Retry Attempts: %d\n", cfg.RetryAttempts)
	fmt.Printf("  Retry Delay: %s\n", cfg.RetryDelay)
	fmt.Printf("  CT Show Expired: %t\n", cfg.CTShowExpired)
	fmt.Printf("  Log Level: %s\n", cfg.LogLevel)
	fmt.Printf("  Log Format: %s\n", cfg.LogFormat)
	fmt.Printf("  Output Dir Permissions: %04o\n", cfg.OutputDirPermissions)
	fmt.Printf("  Output File Permissions: %04o\n", cfg.OutputFilePermissions)

	return nil
}

func runConfigExample(cmd *cobra.Command, args []string) error {
	example := config.GenerateExampleConfig()
	fmt.Print(example)
	return nil
}

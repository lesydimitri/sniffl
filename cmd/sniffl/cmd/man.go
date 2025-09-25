package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/lesydimitri/sniffl/internal/config"
	"github.com/lesydimitri/sniffl/internal/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var manCmd = &cobra.Command{
	Use:   "man [command]",
	Short: "Show manual pages or generate documentation",
	Long: `Show comprehensive manual pages for sniffl and its subcommands.

This automatically installs all man pages if needed and opens them with the standard
'man' command.

Supports the standard Unix convention of separate man pages for each subcommand.`,
	Example: `  # Show main manual page
  sniffl man
  
  # Show specific command manual pages
  sniffl man check
  sniffl man ct
  sniffl man config
  sniffl man screenshot
  
  # Generate documentation files for distribution
  sniffl man --generate
  sniffl man --generate --format markdown`,
	RunE: runMan,
}

var (
	manFormat   string
	manGenerate bool
	manOutput   string
)

func init() {
	manCmd.Flags().BoolVar(&manGenerate, "generate", false, "generate documentation files instead of showing man page")
	manCmd.Flags().StringVar(&manOutput, "output", "./man", "output directory for generated files")
	manCmd.Flags().StringVar(&manFormat, "format", "man", "output format when generating (man|markdown|rest)")
}

func runMan(cmd *cobra.Command, args []string) error {
	logger := GetLogger()

	// If --generate flag is not set, show man page directly
	if !manGenerate {
		return showManPage(args)
	}

	// Generate documentation files
	outputDir := manOutput

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, config.DirPermissions); err != nil {
		return errors.WrapFileError(fmt.Sprintf("failed to create output directory %s", outputDir), err)
	}

	logger.Info("Generating documentation", "format", manFormat, "output_dir", outputDir)

	var err error
	switch manFormat {
	case "man":
		err = generateManPages(outputDir)
	case "markdown", "md":
		err = generateMarkdownDocs(outputDir)
	case "rest", "rst":
		err = generateReSTDocs(outputDir)
	default:
		return errors.NewValidationError(fmt.Sprintf("unsupported format: %s", manFormat))
	}

	if err != nil {
		return errors.WrapFileError("failed to generate documentation", err)
	}

	logger.Success("Documentation generated successfully", "output_dir", outputDir)
	fmt.Printf("Documentation generated in: %s\n", outputDir)

	// Show installation instructions for man pages
	if manFormat == "man" {
		installManPagesSingle(outputDir)
	}

	return nil
}

// showManPage displays the appropriate man page using the system's man viewer
func showManPage(args []string) error {
	// Determine which command to show
	commandName := "sniffl"
	if len(args) > 0 {
		switch args[0] {
		case "check", "ct", "config", "man", "completion", "screenshot":
			commandName = "sniffl-" + args[0]
		default:
			return errors.NewValidationError(fmt.Sprintf("unknown command: %s", args[0]))
		}
	}

	// Try to use system man command first (if already installed)
	if err := trySystemManCommand(commandName); err == nil {
		return nil
	}

	// If not available, auto-install and then show
	return autoInstallAndShowManPage(commandName)
}

// trySystemManCommand tries to use the already installed system man page
func trySystemManCommand(commandName string) error {
	if _, err := exec.LookPath("man"); err != nil {
		return err
	}

	cmd := exec.Command("man", commandName)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// autoInstallAndShowManPage automatically installs all man pages and shows the requested one
func autoInstallAndShowManPage(commandName string) error {
	// Get user's home directory for local installation
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return errors.WrapFileError("failed to get home directory", err)
	}

	// Create local man directory
	localManDir := filepath.Join(homeDir, ".local", "share", "man", "man1")
	if err := os.MkdirAll(localManDir, config.DirPermissions); err != nil {
		return errors.WrapFileError("failed to create local man directory", err)
	}

	// Generate and install all man pages locally (comprehensive approach)
	if err := generateAndInstallAllManPages(localManDir); err != nil {
		return err
	}

	// Update MANPATH temporarily for this session
	if err := updateManPath(filepath.Join(homeDir, ".local", "share", "man")); err != nil {
		// If MANPATH update fails, fall back to direct display
		manFile := filepath.Join(localManDir, commandName+".1")
		return displayManPageDirect(manFile)
	}

	// Now try to use system man command for the specific command
	cmd := exec.Command("man", commandName)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Fallback to direct display
		manFile := filepath.Join(localManDir, commandName+".1")
		return displayManPageDirect(manFile)
	}

	return nil
}

// generateAndInstallAllManPages creates comprehensive man pages for all commands
func generateAndInstallAllManPages(localManDir string) error {
	header := &doc.GenManHeader{
		Title:   "SNIFFL",
		Section: "1",
		Source:  "sniffl " + getVersion(),
		Manual:  "sniffl Manual",
	}

	// Generate all man pages using Cobra's GenManTree (creates separate comprehensive pages)
	return doc.GenManTree(rootCmd, header, localManDir)
}

// updateManPath temporarily updates MANPATH for the current process
func updateManPath(manDir string) error {
	currentPath := os.Getenv("MANPATH")
	if currentPath == "" {
		// If MANPATH is not set, get system default
		if cmd := exec.Command("manpath"); cmd != nil {
			if output, err := cmd.Output(); err == nil {
				currentPath = strings.TrimSpace(string(output))
			}
		}
	}

	// Add our local man directory
	newPath := manDir
	if currentPath != "" {
		newPath = manDir + ":" + currentPath
	}

	return os.Setenv("MANPATH", newPath)
}

// displayManPageDirect displays the man page content directly
func displayManPageDirect(manFile string) error {
	content, err := os.ReadFile(manFile)
	if err != nil {
		return errors.WrapFileError("failed to read man page", err)
	}

	// Try to use a pager if available
	if err := displayWithPager(string(content)); err == nil {
		return nil
	}

	// Fallback: print directly to stdout
	fmt.Print(string(content))
	return nil
}

// displayWithPager tries to use a pager like less or more
func displayWithPager(content string) error {
	// Try common pagers in order of preference
	pagers := []string{"less", "more", "cat"}

	for _, pager := range pagers {
		if _, err := exec.LookPath(pager); err != nil {
			continue
		}

		cmd := exec.Command(pager)
		cmd.Stdin = strings.NewReader(content)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			// If it's just a signal (like user pressing 'q'), that's OK
			if exitError, ok := err.(*exec.ExitError); ok {
				if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
					if status.Signaled() {
						return nil // User interrupted, that's fine
					}
				}
			}
			continue
		}
		return nil
	}

	return fmt.Errorf("no suitable pager found")
}

func generateManPages(outputDir string) error {
	header := &doc.GenManHeader{
		Title:   "SNIFFL",
		Section: "1",
		Source:  "sniffl " + getVersion(),
		Manual:  "sniffl Manual",
	}

	// Generate comprehensive man pages for all commands (separate pages)
	return doc.GenManTree(rootCmd, header, outputDir)
}

func generateMarkdownDocs(outputDir string) error {
	return doc.GenMarkdownTree(rootCmd, outputDir)
}

func generateReSTDocs(outputDir string) error {
	return doc.GenReSTTree(rootCmd, outputDir)
}

// installManPagesSingle provides instructions for installing comprehensive man pages
func installManPagesSingle(manDir string) {
	fmt.Printf(`
To make all sniffl man pages available system-wide for all users, you can:

1. Install system-wide (requires admin privileges):
   sudo cp %s/*.1 /usr/local/share/man/man1/
   sudo mandb

2. For personal use, all man pages have been automatically installed to:
   ~/.local/share/man/man1/
   
   Add this to your shell profile (~/.bashrc, ~/.zshrc) for permanent access:
   export MANPATH="$HOME/.local/share/man:$MANPATH"

After installation, you can use:
   man sniffl           # Main command
   man sniffl-check     # Certificate checking
   man sniffl-ct        # Certificate Transparency
   man sniffl-config    # Configuration management
   man sniffl-screenshot # Web screenshot capture

`, manDir)
}

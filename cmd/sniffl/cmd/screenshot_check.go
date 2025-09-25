package cmd

import (
	"fmt"
	"os"

	"github.com/lesydimitri/sniffl/internal/screenshot"
	"github.com/spf13/cobra"
)

var screenshotCheckCmd = &cobra.Command{
	Use:   "check-chrome",
	Short: "Check Chrome/Chromium installation for screenshot functionality",
	Long: `Check if Chrome or Chromium is properly installed and accessible for screenshot capture.

This command helps diagnose Chrome installation issues that may prevent the screenshot
mode from working correctly.`,
	Example: `  # Check Chrome installation
  sniffl screenshot check-chrome

  # Check specific Chrome path
  sniffl screenshot check-chrome --chrome-path /usr/bin/google-chrome`,
	RunE: runScreenshotCheck,
}

var screenshotCheckChromePath string

func init() {
	screenshotCheckCmd.Flags().StringVar(&screenshotCheckChromePath, "chrome-path", "", "specific Chrome path to check")
	screenshotCmd.AddCommand(screenshotCheckCmd)
}

func runScreenshotCheck(cmd *cobra.Command, args []string) error {
	logger := GetLogger()

	// Always print a concise stdout status for non-verbose users
	fmt.Println("Checking Chrome/Chromium installation...")

	if screenshotCheckChromePath != "" {
		// Check specific path
		logger.Info("Checking specified Chrome path", "path", screenshotCheckChromePath)

		if _, err := os.Stat(screenshotCheckChromePath); err != nil {
			logger.Failure("Chrome not found at specified path", "path", screenshotCheckChromePath, "error", err)
			return fmt.Errorf("chrome not found at %s: %w", screenshotCheckChromePath, err)
		}

		logger.Success("Chrome found at specified path", "path", screenshotCheckChromePath)
		fmt.Println("Chrome found at specified path:", screenshotCheckChromePath)
		return nil
	}

	// Auto-detect Chrome
	execPath, err := screenshot.FindChromeExecutable()
	if err != nil {
		logger.Failure("Chrome/Chromium auto-detection failed", "error", err)

		// Provide helpful installation instructions
		fmt.Println("\n" + getChromeInstallationHelp())

		return err
	}

	logger.Success("Chrome/Chromium found", "path", execPath)
	fmt.Println("Chrome/Chromium found:", execPath)
	fmt.Println("Screenshot functionality should work correctly")

	return nil
}

func getChromeInstallationHelp() string {
	return `Chrome/Chromium Installation Help:

macOS:
  • Install Google Chrome: https://www.google.com/chrome/
  • Install via Homebrew: brew install --cask google-chrome
  • Install Chromium: brew install --cask chromium

Linux (Ubuntu/Debian):
  • Google Chrome: 
    wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
    sudo sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list'
    sudo apt update && sudo apt install google-chrome-stable
  
  • Chromium: sudo apt install chromium-browser

Linux (CentOS/RHEL/Fedora):
  • Google Chrome: sudo dnf install google-chrome-stable
  • Chromium: sudo dnf install chromium

Windows:
  • Download from: https://www.google.com/chrome/
  • Or install via Chocolatey: choco install googlechrome

Alternative: Use custom Chrome path with --chrome-path flag if Chrome is installed in a non-standard location.`
}

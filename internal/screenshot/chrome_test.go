package screenshot

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFindChromeExecutableWithOptions(t *testing.T) {
	// Save original environment and restore it after the test
	origEnvPath := os.Getenv("PATH")
	defer func() {
		if err := os.Setenv("PATH", origEnvPath); err != nil {
			// PATH restore error (ignored)
			_ = err
		}
	}()

	// Create a temporary directory for the test
	tmpDir := t.TempDir()

	tests := []struct {
		name         string
		autoDownload bool
		setup        func(t *testing.T) (cleanup func())
		wantErr      bool
		wantDownload bool
	}{
		{
			name:         "No Chrome installed, no auto-download",
			autoDownload: false,
			setup: func(t *testing.T) func() {
				// Set PATH to empty to ensure no Chrome is found
				if err := os.Setenv("PATH", ""); err != nil {
					// PATH set error (ignored)
					_ = err
				}
				return func() {}
			},
			wantErr:      true,
			wantDownload: false,
		},
		{
			name:         "No Chrome installed, with auto-download",
			autoDownload: true,
			setup: func(t *testing.T) func() {
				// Set PATH to empty to ensure no Chrome is found
				if err := os.Setenv("PATH", ""); err != nil {
					// PATH set error (ignored)
					_ = err
				}
				// Create cache directory
				cacheDir, err := getCacheDir()
				if err != nil {
					t.Fatal(err)
				}
				return func() {
					if err := os.RemoveAll(cacheDir); err != nil {
						// Cache dir removal error (ignored)
						_ = err
					}
				}
			},
			wantErr:      false,
			wantDownload: true,
		},
		{
			name:         "Chrome already installed",
			autoDownload: true,
			setup: func(t *testing.T) func() {
				// Create a mock Chrome executable
				var execPath string
				switch runtime.GOOS {
				case "windows":
					execPath = filepath.Join(tmpDir, "chrome.exe")
				default:
					execPath = filepath.Join(tmpDir, "chrome")
				}

				err := os.WriteFile(execPath, []byte("mock chrome"), 0755)
				if err != nil {
					t.Fatal(err)
				}

				// Add the temporary directory to PATH
				if err := os.Setenv("PATH", fmt.Sprintf("%s%c%s", tmpDir, os.PathListSeparator, origEnvPath)); err != nil {
					_ = err
				}

				return func() {
					if err := os.Remove(execPath); err != nil {
						// Exec path removal error (ignored)
						_ = err
					}
				}
			},
			wantErr:      false,
			wantDownload: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setup(t)
			defer cleanup()

			// If we expect a download, we don't want to actually download Chrome in tests
			if tt.wantDownload {
				oldDownload := downloadPortableChromium
				downloadPortableChromium = func() (string, error) {
					// Return a mock path
					return filepath.Join(t.TempDir(), "mock-chrome"), nil
				}
				defer func() { downloadPortableChromium = oldDownload }()
			}

			execPath, err := FindChromeExecutableWithOptions(tt.autoDownload)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if execPath == "" {
				t.Error("Expected executable path but got empty string")
			}
		})
	}
}

func TestGetCacheDir(t *testing.T) {
	dir, err := getCacheDir()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if dir == "" {
		t.Error("Expected cache directory but got empty string")
	}

	// Verify the directory was created
	_, err = os.Stat(dir)
	if err != nil {
		t.Errorf("Cache directory was not created: %v", err)
	}

	// Clean up
	if err := os.RemoveAll(dir); err != nil {
		// Directory removal error (ignored)
		_ = err
	}
}

func TestGetChromiumDownloadURL(t *testing.T) {
	url, err := getChromiumDownloadURL()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if url == "" {
		t.Error("Expected download URL but got empty string")
	}

	// Verify URL format
	expectedPrefix := "https://storage.googleapis.com/chromium-browser-snapshots"
	if !strings.HasPrefix(url, expectedPrefix) {
		t.Errorf("Expected URL to start with %s, got %s", expectedPrefix, url)
	}

	// Verify URL is appropriate for current platform
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	switch goos {
	case "linux":
		if !strings.Contains(url, "Linux_x64") {
			t.Errorf("Expected Linux_x64 in URL for linux/amd64, got %s", url)
		}
	case "darwin":
		switch goarch {
		case "amd64":
			if !strings.Contains(url, "Mac/") {
				t.Errorf("Expected Mac/ in URL for darwin/amd64, got %s", url)
			}
		case "arm64":
			if !strings.Contains(url, "Mac_Arm/") {
				t.Errorf("Expected Mac_Arm/ in URL for darwin/arm64, got %s", url)
			}
		}
	case "windows":
		switch goarch {
		case "amd64":
			if !strings.Contains(url, "Win_x64") {
				t.Errorf("Expected Win_x64 in URL for windows/amd64, got %s", url)
			}
		default:
			if !strings.Contains(url, "Win/") {
				t.Errorf("Expected Win/ in URL for windows/386, got %s", url)
			}
		}
	}
}

func TestDownloadAndExtractChromium(t *testing.T) {
	// Skip the actual download in tests to avoid long test times and network dependencies
	t.Skip("Skipping actual download test - use this test manually when needed")
}

func TestExtractZip(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir := t.TempDir()
	srcZip := filepath.Join(tmpDir, "test.zip")

	// Create a test zip file
	if err := createTestZip(srcZip); err != nil {
		t.Fatalf("Failed to create test zip: %v", err)
	}

	// Extract the zip
	extractDir := filepath.Join(tmpDir, "extract")
	if err := extractZip(srcZip, extractDir); err != nil {
		t.Fatalf("Failed to extract zip: %v", err)
	}

	// Verify the extracted files
	extractedFile := filepath.Join(extractDir, "test.txt")
	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("Failed to read extracted file: %v", err)
	}

	if string(content) != "test content" {
		t.Errorf("Expected content 'test content', got '%s'", string(content))
	}
}

// Helper function to create a test zip file
func createTestZip(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			// File close error (ignored)
			_ = err
		}
	}()

	w := zip.NewWriter(file)
	defer func() {
		if err := w.Close(); err != nil {
			// Writer close error (ignored)
			_ = err
		}
	}()

	f, err := w.Create("test.txt")
	if err != nil {
		return err
	}

	_, err = f.Write([]byte("test content"))
	return err
}

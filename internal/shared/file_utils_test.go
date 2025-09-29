package shared

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewFileManager(t *testing.T) {
	dirPerms := os.FileMode(0755)
	filePerms := os.FileMode(0644)
	
	fm := NewFileManager(dirPerms, filePerms)
	
	if fm == nil {
		t.Fatal("Expected non-nil FileManager")
	}
	
	if fm.dirPermissions != dirPerms {
		t.Errorf("Expected dir permissions %v, got %v", dirPerms, fm.dirPermissions)
	}
	
	if fm.filePermissions != filePerms {
		t.Errorf("Expected file permissions %v, got %v", filePerms, fm.filePermissions)
	}
}

func TestFileManager_CreateFile(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
		setupFunc   func(t *testing.T) string // Returns actual path to use
	}{
		{
			name:        "simple_file",
			expectError: false,
			setupFunc: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "test.txt")
			},
		},
		{
			name:        "nested_directory",
			expectError: false,
			setupFunc: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "subdir", "nested", "test.txt")
			},
		},
		{
			name:        "existing_directory",
			expectError: false,
			setupFunc: func(t *testing.T) string {
				tmpDir := t.TempDir()
				subDir := filepath.Join(tmpDir, "existing")
				if err := os.MkdirAll(subDir, 0755); err != nil {
					t.Fatalf("Failed to create test directory: %v", err)
				}
				return filepath.Join(subDir, "test.txt")
			},
		},
		{
			name:        "invalid_path",
			expectError: true,
			setupFunc: func(t *testing.T) string {
				// Try to create file in non-existent root directory (should fail on most systems)
				return "/nonexistent_root_dir_12345/test.txt"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := NewFileManager(0755, 0644)
			path := tt.setupFunc(t)
			
			file, err := fm.CreateFile(path)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					if file != nil {
						file.Close()
					}
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			if file == nil {
				t.Error("Expected non-nil file")
				return
			}
			
			// Test that we can write to the file
			testData := "test content"
			if _, writeErr := file.Write([]byte(testData)); writeErr != nil {
				t.Errorf("Failed to write to file: %v", writeErr)
			}
			
			// Close the file
			if closeErr := file.Close(); closeErr != nil {
				t.Errorf("Failed to close file: %v", closeErr)
			}
			
			// Verify file exists and has correct content
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Errorf("Failed to read file: %v", readErr)
			} else if string(content) != testData {
				t.Errorf("Expected file content %q, got %q", testData, string(content))
			}
			
			// Verify directory was created with correct permissions
			dir := filepath.Dir(path)
			if stat, statErr := os.Stat(dir); statErr != nil {
				t.Errorf("Failed to stat directory: %v", statErr)
			} else {
				// Note: On some systems, the actual permissions might differ due to umask
				expectedPerms := os.FileMode(0755)
				if stat.Mode().Perm() != expectedPerms {
					t.Logf("Directory permissions: expected %v, got %v (may differ due to umask)", 
						expectedPerms, stat.Mode().Perm())
				}
			}
		})
	}
}

func TestFileManager_CreateTimestampedFile(t *testing.T) {
	tests := []struct {
		name        string
		baseDir     string
		subDir      string
		filename    string
		expectError bool
		setupFunc   func(t *testing.T) (string, string, string) // Returns baseDir, subDir, filename
	}{
		{
			name:        "simple_timestamped_file",
			expectError: false,
			setupFunc: func(t *testing.T) (string, string, string) {
				return t.TempDir(), "logs", "app.log"
			},
		},
		{
			name:        "nested_subdirectory",
			expectError: false,
			setupFunc: func(t *testing.T) (string, string, string) {
				return t.TempDir(), "logs/2023/12", "debug.log"
			},
		},
		{
			name:        "empty_subdirectory",
			expectError: false,
			setupFunc: func(t *testing.T) (string, string, string) {
				return t.TempDir(), "", "test.txt"
			},
		},
		{
			name:        "special_characters_in_filename",
			expectError: false,
			setupFunc: func(t *testing.T) (string, string, string) {
				return t.TempDir(), "output", "test-file_v1.2.txt"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := NewFileManager(0755, 0644)
			baseDir, subDir, filename := tt.setupFunc(t)
			
			file, fullPath, err := fm.CreateTimestampedFile(baseDir, subDir, filename)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					if file != nil {
						file.Close()
					}
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			if file == nil {
				t.Error("Expected non-nil file")
				return
			}
			
			if fullPath == "" {
				t.Error("Expected non-empty full path")
			}
			
			// Verify path structure
			expectedDir := filepath.Join(baseDir, subDir)
			actualDir := filepath.Dir(fullPath)
			if actualDir != expectedDir {
				t.Errorf("Expected directory %q, got %q", expectedDir, actualDir)
			}
			
			// Verify filename has timestamp prefix
			actualFilename := filepath.Base(fullPath)
			if !strings.Contains(actualFilename, filename) {
				t.Errorf("Expected filename to contain %q, got %q", filename, actualFilename)
			}
			
			// Verify timestamp format (YYYYMMDD_HHMMSS_)
			timestampPart := strings.Split(actualFilename, "_")
			if len(timestampPart) < 3 {
				t.Errorf("Expected timestamped filename format, got %q", actualFilename)
			} else {
				// Check date part (YYYYMMDD)
				datePart := timestampPart[0]
				if len(datePart) != 8 {
					t.Errorf("Expected date part to be 8 characters, got %d: %q", len(datePart), datePart)
				}
				
				// Check time part (HHMMSS)
				timePart := timestampPart[1]
				if len(timePart) != 6 {
					t.Errorf("Expected time part to be 6 characters, got %d: %q", len(timePart), timePart)
				}
			}
			
			// Test writing to the file
			testData := "timestamped test content"
			if _, writeErr := file.Write([]byte(testData)); writeErr != nil {
				t.Errorf("Failed to write to file: %v", writeErr)
			}
			
			// Close the file
			if closeErr := file.Close(); closeErr != nil {
				t.Errorf("Failed to close file: %v", closeErr)
			}
			
			// Verify file exists and has correct content
			content, readErr := os.ReadFile(fullPath)
			if readErr != nil {
				t.Errorf("Failed to read file: %v", readErr)
			} else if string(content) != testData {
				t.Errorf("Expected file content %q, got %q", testData, string(content))
			}
		})
	}
}

func TestFileManager_EnsureDirectory(t *testing.T) {
	tests := []struct {
		name        string
		expectError bool
		setupFunc   func(t *testing.T) string // Returns directory path
	}{
		{
			name:        "new_directory",
			expectError: false,
			setupFunc: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "new_dir")
			},
		},
		{
			name:        "nested_directories",
			expectError: false,
			setupFunc: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "level1", "level2", "level3")
			},
		},
		{
			name:        "existing_directory",
			expectError: false,
			setupFunc: func(t *testing.T) string {
				tmpDir := t.TempDir()
				existingDir := filepath.Join(tmpDir, "existing")
				if err := os.MkdirAll(existingDir, 0755); err != nil {
					t.Fatalf("Failed to create test directory: %v", err)
				}
				return existingDir
			},
		},
		{
			name:        "invalid_path",
			expectError: true,
			setupFunc: func(t *testing.T) string {
				return "/nonexistent_root_12345/test_dir"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := NewFileManager(0755, 0644)
			dirPath := tt.setupFunc(t)
			
			err := fm.EnsureDirectory(dirPath)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			// Verify directory exists
			if stat, statErr := os.Stat(dirPath); statErr != nil {
				t.Errorf("Directory should exist: %v", statErr)
			} else if !stat.IsDir() {
				t.Error("Path should be a directory")
			}
		})
	}
}

func TestFileManager_FileExists(t *testing.T) {
	tmpDir := t.TempDir()
	fm := NewFileManager(0755, 0644)
	
	// Create a test file
	existingFile := filepath.Join(tmpDir, "existing.txt")
	if err := os.WriteFile(existingFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	// Create a test directory
	existingDir := filepath.Join(tmpDir, "existing_dir")
	if err := os.MkdirAll(existingDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "existing_file",
			path:     existingFile,
			expected: true,
		},
		{
			name:     "existing_directory",
			path:     existingDir,
			expected: true,
		},
		{
			name:     "nonexistent_file",
			path:     filepath.Join(tmpDir, "nonexistent.txt"),
			expected: false,
		},
		{
			name:     "nonexistent_directory",
			path:     filepath.Join(tmpDir, "nonexistent_dir"),
			expected: false,
		},
		{
			name:     "empty_path",
			path:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fm.FileExists(tt.path)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for path %q", tt.expected, result, tt.path)
			}
		})
	}
}

func TestFileManager_SafeCloseFile(t *testing.T) {
	tmpDir := t.TempDir()
	fm := NewFileManager(0755, 0644)
	
	// Create a mock logger
	logOutput := &strings.Builder{}
	logger := &mockLogger{output: logOutput}
	
	tests := []struct {
		name         string
		setupFunc    func() (io.Closer, string) // Returns file and filename
		expectLog    bool
		expectedLog  string
	}{
		{
			name: "successful_close",
			setupFunc: func() (io.Closer, string) {
				filename := "test_success.txt"
				file, err := os.Create(filepath.Join(tmpDir, filename))
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return file, filename
			},
			expectLog: false,
		},
		{
			name: "nil_file",
			setupFunc: func() (io.Closer, string) {
				return nil, "nil_file.txt"
			},
			expectLog: false,
		},
		{
			name: "failing_close",
			setupFunc: func() (io.Closer, string) {
				return &failingCloser{}, "failing_file.txt"
			},
			expectLog:   true,
			expectedLog: "Failed to close file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput.Reset()
			
			file, filename := tt.setupFunc()
			
			// Should not panic
			fm.SafeCloseFile(file, filename, logger)
			
			logStr := logOutput.String()
			if tt.expectLog {
				if !strings.Contains(logStr, tt.expectedLog) {
					t.Errorf("Expected log to contain %q, got: %s", tt.expectedLog, logStr)
				}
			} else {
				if logStr != "" {
					t.Errorf("Expected no log output, got: %s", logStr)
				}
			}
		})
	}
}

func TestGetTimestamp(t *testing.T) {
	// Test multiple calls to ensure format consistency
	for i := 0; i < 5; i++ {
		timestamp := GetTimestamp()
		
		// Verify format (YYYYMMDD_HHMMSS)
		if len(timestamp) != 15 {
			t.Errorf("Expected timestamp length 15, got %d: %s", len(timestamp), timestamp)
		}
		
		// Verify underscore separator
		if !strings.Contains(timestamp, "_") {
			t.Errorf("Expected timestamp to contain underscore: %s", timestamp)
		}
		
		// Verify position of underscore
		if timestamp[8] != '_' {
			t.Errorf("Expected underscore at position 8, got %c", timestamp[8])
		}
		
		// Verify all other characters are digits
		for j, r := range timestamp {
			if j == 8 { // Skip underscore
				continue
			}
			if r < '0' || r > '9' {
				t.Errorf("Expected digit at position %d, got %c", j, r)
			}
		}
		
		// Verify it's a valid time format by parsing
		if _, err := time.Parse("20060102_150405", timestamp); err != nil {
			t.Errorf("Failed to parse timestamp %q: %v", timestamp, err)
		}
		
		// Small delay to ensure different timestamps if needed
		time.Sleep(time.Millisecond)
	}
}

func TestGetTimestamp_Uniqueness(t *testing.T) {
	// Test that timestamps are unique when called with sufficient delay
	timestamps := make(map[string]bool)
	
	for i := 0; i < 3; i++ { // Reduced iterations for reliability
		timestamp := GetTimestamp()
		if timestamps[timestamp] {
			t.Errorf("Duplicate timestamp generated: %s", timestamp)
		}
		timestamps[timestamp] = true
		time.Sleep(time.Second) // Full second delay to ensure uniqueness
	}
}

// Helper types for testing

type mockLogger struct {
	output *strings.Builder
}

func (ml *mockLogger) Warn(msg string, args ...interface{}) {
	ml.output.WriteString(msg)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			ml.output.WriteString(" ")
			if key, ok := args[i].(string); ok {
				ml.output.WriteString(key)
				ml.output.WriteString("=")
				// Handle different value types
				switch v := args[i+1].(type) {
				case string:
					ml.output.WriteString(v)
				case error:
					ml.output.WriteString(v.Error())
				default:
					ml.output.WriteString("unknown")
				}
			}
		}
	}
}

type failingCloser struct{}

func (fc *failingCloser) Close() error {
	return os.ErrClosed
}

// Benchmark tests
func BenchmarkFileManager_CreateFile(b *testing.B) {
	tmpDir := b.TempDir()
	fm := NewFileManager(0755, 0644)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := filepath.Join(tmpDir, "bench", "test", "file.txt")
		file, err := fm.CreateFile(path)
		if err != nil {
			b.Fatalf("Failed to create file: %v", err)
		}
		file.Close()
	}
}

func BenchmarkGetTimestamp(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetTimestamp()
	}
}

func BenchmarkFileManager_FileExists(b *testing.B) {
	tmpDir := b.TempDir()
	fm := NewFileManager(0755, 0644)
	
	// Create a test file
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("test"), 0644)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fm.FileExists(testFile)
	}
}

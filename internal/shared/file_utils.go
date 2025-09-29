package shared

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// FileManager handles file operations with consistent permissions and error handling
type FileManager struct {
	dirPermissions  os.FileMode
	filePermissions os.FileMode
}

// NewFileManager creates a new file manager with specified permissions
func NewFileManager(dirPerms, filePerms os.FileMode) *FileManager {
	return &FileManager{
		dirPermissions:  dirPerms,
		filePermissions: filePerms,
	}
}

// CreateFile creates a file with proper error handling and permissions
func (fm *FileManager) CreateFile(path string) (io.WriteCloser, error) {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, fm.dirPermissions); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Create file
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fm.filePermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to create file %s: %w", path, err)
	}

	return file, nil
}

// CreateTimestampedFile creates a file with timestamp prefix in the specified directory
func (fm *FileManager) CreateTimestampedFile(baseDir, subDir, filename string) (io.WriteCloser, string, error) {
	// Create full directory path
	fullDir := filepath.Join(baseDir, subDir)
	if err := os.MkdirAll(fullDir, fm.dirPermissions); err != nil {
		return nil, "", fmt.Errorf("failed to create directory %s: %w", fullDir, err)
	}

	// Generate timestamped filename
	timestamp := GetTimestamp()
	timestampedName := fmt.Sprintf("%s_%s", timestamp, filename)
	fullPath := filepath.Join(fullDir, timestampedName)

	// Create file
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fm.filePermissions)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create file %s: %w", fullPath, err)
	}

	return file, fullPath, nil
}

// EnsureDirectory creates a directory with proper permissions if it doesn't exist
func (fm *FileManager) EnsureDirectory(path string) error {
	if err := os.MkdirAll(path, fm.dirPermissions); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	return nil
}

// FileExists checks if a file exists
func (fm *FileManager) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// SafeCloseFile safely closes a file with error logging
func (fm *FileManager) SafeCloseFile(file io.Closer, filename string, logger interface{ Warn(string, ...interface{}) }) {
	if file != nil {
		if err := file.Close(); err != nil {
			logger.Warn("Failed to close file", "filename", filename, "error", err)
		}
	}
}

// GetTimestamp returns a UTC timestamp suitable for filenames
func GetTimestamp() string {
	return time.Now().UTC().Format("20060102_150405")
}

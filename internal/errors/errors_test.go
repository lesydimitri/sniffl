package errors

import (
	"fmt"
	"net"
	"testing"
)

func TestSnifflError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *SnifflError
		expected string
	}{
		{
			name:     "error without cause",
			err:      New(ValidationError, "invalid input"),
			expected: "validation error: invalid input",
		},
		{
			name:     "error with cause",
			err:      Wrap(NetworkError, "connection failed", fmt.Errorf("timeout")),
			expected: "network error: connection failed: timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("SnifflError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSnifflError_Unwrap(t *testing.T) {
	cause := fmt.Errorf("original error")
	err := Wrap(TLSError, "wrapped error", cause)

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("SnifflError.Unwrap() = %v, want %v", unwrapped, cause)
	}

	// Test error without cause
	errNoCause := New(ValidationError, "no cause")
	if unwrapped := errNoCause.Unwrap(); unwrapped != nil {
		t.Errorf("SnifflError.Unwrap() = %v, want nil", unwrapped)
	}
}

func TestSnifflError_WithContext(t *testing.T) {
	err := New(FileError, "file not found")
	_ = err.WithContext("path", "/tmp/test.txt") //nolint:errcheck
	_ = err.WithContext("operation", "read")     //nolint:errcheck

	if err.Context["path"] != "/tmp/test.txt" {
		t.Errorf("Context[path] = %v, want /tmp/test.txt", err.Context["path"])
	}

	if err.Context["operation"] != "read" {
		t.Errorf("Context[operation] = %v, want read", err.Context["operation"])
	}
}

func TestConvenienceConstructors(t *testing.T) {
	tests := []struct {
		name     string
		err      *SnifflError
		wantType ErrorType
	}{
		{"NewValidationError", NewValidationError("test"), ValidationError},
		{"NewNetworkError", NewNetworkError("test"), NetworkError},
		{"NewTLSError", NewTLSError("test"), TLSError},
		{"NewFileError", NewFileError("test"), FileError},
		{"NewConfigError", NewConfigError("test"), ConfigError},
		{"NewCTError", NewCTError("test"), CTError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Type != tt.wantType {
				t.Errorf("Error type = %v, want %v", tt.err.Type, tt.wantType)
			}
		})
	}
}

func TestWrapConvenienceConstructors(t *testing.T) {
	cause := fmt.Errorf("original")

	tests := []struct {
		name     string
		err      *SnifflError
		wantType ErrorType
	}{
		{"WrapValidationError", WrapValidationError("test", cause), ValidationError},
		{"WrapNetworkError", WrapNetworkError("test", cause), NetworkError},
		{"WrapTLSError", WrapTLSError("test", cause), TLSError},
		{"WrapFileError", WrapFileError("test", cause), FileError},
		{"WrapConfigError", WrapConfigError("test", cause), ConfigError},
		{"WrapCTError", WrapCTError("test", cause), CTError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Type != tt.wantType {
				t.Errorf("Error type = %v, want %v", tt.err.Type, tt.wantType)
			}
			if tt.err.Cause != cause {
				t.Errorf("Error cause = %v, want %v", tt.err.Cause, cause)
			}
		})
	}
}

func TestIsNetworkTimeout(t *testing.T) {
	// Create a timeout error
	timeoutErr := &net.OpError{
		Op:  "dial",
		Err: &timeoutError{},
	}

	if !IsNetworkTimeout(timeoutErr) {
		t.Error("IsNetworkTimeout should return true for timeout error")
	}

	// Test with non-timeout error
	regularErr := fmt.Errorf("regular error")
	if IsNetworkTimeout(regularErr) {
		t.Error("IsNetworkTimeout should return false for regular error")
	}
}

func TestIsConnectionRefused(t *testing.T) {
	// Create a connection refused error
	dialErr := &net.OpError{
		Op: "dial",
	}

	if !IsConnectionRefused(dialErr) {
		t.Error("IsConnectionRefused should return true for dial error")
	}

	// Test with non-dial error
	readErr := &net.OpError{
		Op: "read",
	}
	if IsConnectionRefused(readErr) {
		t.Error("IsConnectionRefused should return false for read error")
	}

	// Test with regular error
	regularErr := fmt.Errorf("regular error")
	if IsConnectionRefused(regularErr) {
		t.Error("IsConnectionRefused should return false for regular error")
	}
}

// Mock timeout error for testing
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return false }

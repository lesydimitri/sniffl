package shared

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/lesydimitri/sniffl/internal/logging"
)

func TestNewErrorHandler(t *testing.T) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	output := &bytes.Buffer{}
	
	eh := NewErrorHandler(logger, output)
	
	if eh == nil {
		t.Fatal("Expected non-nil ErrorHandler")
	}
	
	if eh.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
	
	if eh.out != output {
		t.Error("Expected output to be set correctly")
	}
}

func TestNewErrorHandler_NilOutput(t *testing.T) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	
	eh := NewErrorHandler(logger, nil)
	
	if eh == nil {
		t.Fatal("Expected non-nil ErrorHandler")
	}
	
	if eh.out != nil {
		t.Error("Expected output to be nil")
	}
}

func TestErrorHandler_HandleNetworkError(t *testing.T) {
	tests := []struct {
		name           string
		operation      string
		target         string
		inputError     error
		expectOutput   bool
		expectedOutput string
	}{
		{
			name:           "connection_refused",
			operation:      "connect",
			target:         "example.com:443",
			inputError:     errors.New("connection refused"),
			expectOutput:   true,
			expectedOutput: "[-] connect failed for example.com:443: connection refused",
		},
		{
			name:           "timeout_error",
			operation:      "read",
			target:         "slow.example.com:80",
			inputError:     errors.New("i/o timeout"),
			expectOutput:   true,
			expectedOutput: "[-] read failed for slow.example.com:80: i/o timeout",
		},
		{
			name:           "dns_resolution_error",
			operation:      "resolve",
			target:         "nonexistent.example.com:443",
			inputError:     errors.New("no such host"),
			expectOutput:   true,
			expectedOutput: "[-] resolve failed for nonexistent.example.com:443: no such host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput := &bytes.Buffer{}
			logger := logging.New("debug", "text", logOutput)
			
			var output *bytes.Buffer
			if tt.expectOutput {
				output = &bytes.Buffer{}
			}
			
			eh := NewErrorHandler(logger, output)
			
			// Call the method
			err := eh.HandleNetworkError(tt.operation, tt.target, tt.inputError)
			
			// Check that error is returned and wrapped
			if err == nil {
				t.Error("Expected error to be returned")
			}
			
			// Check that error message contains original error
			if !strings.Contains(err.Error(), tt.inputError.Error()) {
				t.Errorf("Expected wrapped error to contain original error message")
			}
			
			// Check output if expected
			if tt.expectOutput && output != nil {
				outputStr := output.String()
				if !strings.Contains(outputStr, tt.expectedOutput) {
					t.Errorf("Expected output to contain %q, got: %s", tt.expectedOutput, outputStr)
				}
			}
			
			// Check that logging occurred
			logStr := logOutput.String()
			if !strings.Contains(logStr, tt.operation+" failed") {
				t.Errorf("Expected log to contain operation failure message")
			}
		})
	}
}

func TestErrorHandler_HandleTLSError(t *testing.T) {
	tests := []struct {
		name           string
		operation      string
		target         string
		inputError     error
		expectOutput   bool
		expectedOutput string
	}{
		{
			name:           "certificate_verify_failed",
			operation:      "TLS handshake",
			target:         "untrusted.example.com:443",
			inputError:     errors.New("certificate verify failed"),
			expectOutput:   true,
			expectedOutput: "[-] TLS handshake failed for untrusted.example.com:443: certificate verify failed",
		},
		{
			name:           "protocol_version_error",
			operation:      "TLS negotiation",
			target:         "old.example.com:443",
			inputError:     errors.New("protocol version not supported"),
			expectOutput:   true,
			expectedOutput: "[-] TLS negotiation failed for old.example.com:443: protocol version not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput := &bytes.Buffer{}
			logger := logging.New("debug", "text", logOutput)
			
			var output *bytes.Buffer
			if tt.expectOutput {
				output = &bytes.Buffer{}
			}
			
			eh := NewErrorHandler(logger, output)
			
			// Call the method
			err := eh.HandleTLSError(tt.operation, tt.target, tt.inputError)
			
			// Check that error is returned and wrapped
			if err == nil {
				t.Error("Expected error to be returned")
			}
			
			// Check that error message contains original error
			if !strings.Contains(err.Error(), tt.inputError.Error()) {
				t.Errorf("Expected wrapped error to contain original error message")
			}
			
			// Check output if expected
			if tt.expectOutput && output != nil {
				outputStr := output.String()
				if !strings.Contains(outputStr, tt.expectedOutput) {
					t.Errorf("Expected output to contain %q, got: %s", tt.expectedOutput, outputStr)
				}
			}
			
			// Check that logging occurred
			logStr := logOutput.String()
			if !strings.Contains(logStr, tt.operation+" failed") {
				t.Errorf("Expected log to contain operation failure message")
			}
		})
	}
}

func TestErrorHandler_HandleValidationError(t *testing.T) {
	tests := []struct {
		name           string
		message        string
		target         string
		expectOutput   bool
		expectedOutput string
	}{
		{
			name:           "invalid_host_port",
			message:        "Invalid host:port format",
			target:         "invalid-target",
			expectOutput:   true,
			expectedOutput: "[-] Invalid host:port format: invalid-target (skipped)",
		},
		{
			name:           "invalid_protocol",
			message:        "Unsupported protocol",
			target:         "example.com:443",
			expectOutput:   true,
			expectedOutput: "[-] Unsupported protocol: example.com:443 (skipped)",
		},
		{
			name:           "empty_target",
			message:        "Target cannot be empty",
			target:         "",
			expectOutput:   true,
			expectedOutput: "[-] Target cannot be empty:  (skipped)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput := &bytes.Buffer{}
			logger := logging.New("debug", "text", logOutput)
			
			var output *bytes.Buffer
			if tt.expectOutput {
				output = &bytes.Buffer{}
			}
			
			eh := NewErrorHandler(logger, output)
			
			// Call the method
			err := eh.HandleValidationError(tt.message, tt.target)
			
			// Check that error is returned
			if err == nil {
				t.Error("Expected error to be returned")
			}
			
			// Check that error message contains validation message
			if !strings.Contains(err.Error(), tt.message) {
				t.Errorf("Expected error to contain validation message")
			}
			
			// Check output if expected
			if tt.expectOutput && output != nil {
				outputStr := output.String()
				if !strings.Contains(outputStr, tt.expectedOutput) {
					t.Errorf("Expected output to contain %q, got: %s", tt.expectedOutput, outputStr)
				}
			}
			
			// Check that logging occurred
			logStr := logOutput.String()
			if !strings.Contains(logStr, "Validation error") {
				t.Errorf("Expected log to contain validation error message")
			}
		})
	}
}

func TestErrorHandler_HandleFileError(t *testing.T) {
	tests := []struct {
		name       string
		operation  string
		path       string
		inputError error
	}{
		{
			name:       "file_not_found",
			operation:  "read",
			path:       "/nonexistent/file.txt",
			inputError: errors.New("no such file or directory"),
		},
		{
			name:       "permission_denied",
			operation:  "write",
			path:       "/root/protected.txt",
			inputError: errors.New("permission denied"),
		},
		{
			name:       "disk_full",
			operation:  "create",
			path:       "/tmp/large_file.dat",
			inputError: errors.New("no space left on device"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput := &bytes.Buffer{}
			logger := logging.New("debug", "text", logOutput)
			
			eh := NewErrorHandler(logger, nil) // No output writer for file errors
			
			// Call the method
			err := eh.HandleFileError(tt.operation, tt.path, tt.inputError)
			
			// Check that error is returned and wrapped
			if err == nil {
				t.Error("Expected error to be returned")
			}
			
			// Check that error message contains original error
			if !strings.Contains(err.Error(), tt.inputError.Error()) {
				t.Errorf("Expected wrapped error to contain original error message")
			}
			
			// Check that logging occurred
			logStr := logOutput.String()
			if !strings.Contains(logStr, tt.operation+" failed") {
				t.Errorf("Expected log to contain operation failure message")
			}
		})
	}
}

func TestErrorHandler_LogSuccess(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		target    string
		details   map[string]interface{}
	}{
		{
			name:      "simple_success",
			operation: "connect",
			target:    "example.com:443",
			details:   map[string]interface{}{"duration": "100ms"},
		},
		{
			name:      "complex_success",
			operation: "certificate_fetch",
			target:    "secure.example.com:443",
			details: map[string]interface{}{
				"certificates": 3,
				"duration":     "250ms",
				"protocol":     "TLS 1.3",
			},
		},
		{
			name:      "no_details",
			operation: "validate",
			target:    "test.com:80",
			details:   nil,
		},
		{
			name:      "empty_details",
			operation: "parse",
			target:    "data.example.com:443",
			details:   map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput := &bytes.Buffer{}
			logger := logging.New("debug", "text", logOutput)
			
			eh := NewErrorHandler(logger, nil)
			
			// Call the method
			eh.LogSuccess(tt.operation, tt.target, tt.details)
			
			// Check that logging occurred
			logStr := logOutput.String()
			expectedMsg := tt.operation + " completed successfully"
			if !strings.Contains(logStr, expectedMsg) {
				t.Errorf("Expected log to contain %q, got: %s", expectedMsg, logStr)
			}
			
			// Check that target is logged
			if !strings.Contains(logStr, "target="+tt.target) {
				t.Errorf("Expected log to contain target, got: %s", logStr)
			}
			
			// Check that details are logged
			for key := range tt.details {
				// Note: This is a simplified check. In practice, the logging format might be different
				if !strings.Contains(logStr, key) {
					t.Errorf("Expected log to contain detail key %q, got: %s", key, logStr)
				}
			}
		})
	}
}

func TestErrorHandler_WithNilOutput(t *testing.T) {
	logOutput := &bytes.Buffer{}
	logger := logging.New("debug", "text", logOutput)
	
	eh := NewErrorHandler(logger, nil) // No output writer
	
	// Test that methods don't panic with nil output
	err1 := eh.HandleNetworkError("connect", "example.com:443", errors.New("test error"))
	if err1 == nil {
		t.Error("Expected error to be returned")
	}
	
	err2 := eh.HandleTLSError("handshake", "example.com:443", errors.New("test error"))
	if err2 == nil {
		t.Error("Expected error to be returned")
	}
	
	err3 := eh.HandleValidationError("test message", "example.com:443")
	if err3 == nil {
		t.Error("Expected error to be returned")
	}
	
	// Should not panic
	eh.LogSuccess("test", "example.com:443", map[string]interface{}{"key": "value"})
}

// Test error output write failures
func TestErrorHandler_OutputWriteFailure(t *testing.T) {
	logOutput := &bytes.Buffer{}
	logger := logging.New("debug", "text", logOutput)
	
	// Create a writer that always fails
	failingWriter := &failingWriter{}
	
	eh := NewErrorHandler(logger, failingWriter)
	
	// These should not panic even if output writing fails
	_ = eh.HandleNetworkError("connect", "example.com:443", errors.New("test error"))
	_ = eh.HandleTLSError("handshake", "example.com:443", errors.New("test error"))
	_ = eh.HandleValidationError("test message", "example.com:443")
	
	// Check that warnings about write failures are logged
	logStr := logOutput.String()
	if !strings.Contains(logStr, "Failed to write") {
		t.Error("Expected warning about write failure to be logged")
	}
}

// Helper type for testing write failures
type failingWriter struct{}

func (fw *failingWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write failed")
}

// Benchmark tests
func BenchmarkErrorHandler_HandleNetworkError(b *testing.B) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	output := &bytes.Buffer{}
	eh := NewErrorHandler(logger, output)
	
	operation := "connect"
	target := "example.com:443"
	inputError := errors.New("connection refused")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eh.HandleNetworkError(operation, target, inputError)
	}
}

func BenchmarkErrorHandler_LogSuccess(b *testing.B) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	eh := NewErrorHandler(logger, nil)
	
	operation := "connect"
	target := "example.com:443"
	details := map[string]interface{}{
		"duration": "100ms",
		"status":   "success",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eh.LogSuccess(operation, target, details)
	}
}

package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name         string
		level        string
		format       string
		output       *bytes.Buffer
		expectLevel  slog.Level
		expectJSON   bool
	}{
		{
			name:        "debug_text",
			level:       "debug",
			format:      "text",
			output:      &bytes.Buffer{},
			expectLevel: slog.LevelDebug,
			expectJSON:  false,
		},
		{
			name:        "info_json",
			level:       "info",
			format:      "json",
			output:      &bytes.Buffer{},
			expectLevel: slog.LevelInfo,
			expectJSON:  true,
		},
		{
			name:        "warn_text",
			level:       "warn",
			format:      "text",
			output:      &bytes.Buffer{},
			expectLevel: slog.LevelWarn,
			expectJSON:  false,
		},
		{
			name:        "warning_text",
			level:       "warning",
			format:      "text",
			output:      &bytes.Buffer{},
			expectLevel: slog.LevelWarn,
			expectJSON:  false,
		},
		{
			name:        "error_json",
			level:       "error",
			format:      "json",
			output:      &bytes.Buffer{},
			expectLevel: slog.LevelError,
			expectJSON:  true,
		},
		{
			name:        "invalid_level_defaults_to_info",
			level:       "invalid",
			format:      "text",
			output:      &bytes.Buffer{},
			expectLevel: slog.LevelInfo,
			expectJSON:  false,
		},
		{
			name:        "empty_level_defaults_to_info",
			level:       "",
			format:      "text",
			output:      &bytes.Buffer{},
			expectLevel: slog.LevelInfo,
			expectJSON:  false,
		},
		{
			name:        "nil_output_uses_stderr",
			level:       "info",
			format:      "text",
			output:      nil,
			expectLevel: slog.LevelInfo,
			expectJSON:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output *bytes.Buffer
			if tt.output != nil {
				output = tt.output
			}

			logger := New(tt.level, tt.format, output)

			if logger == nil {
				t.Fatal("Expected non-nil logger")
			}

			if logger.level != tt.expectLevel {
				t.Errorf("Expected level %v, got %v", tt.expectLevel, logger.level)
			}

			// Test that logger actually works by logging a message at appropriate level
			if output != nil {
				// Use a log level that will actually output based on the logger's level
				switch tt.expectLevel {
				case slog.LevelDebug:
					logger.Debug("test message", "key", "value")
				case slog.LevelInfo:
					logger.Info("test message", "key", "value")
				case slog.LevelWarn:
					logger.Warn("test message", "key", "value")
				case slog.LevelError:
					logger.Error("test message", "key", "value")
				}
				
				logOutput := output.String()

				if tt.expectJSON {
					// Verify it's valid JSON
					var jsonData map[string]interface{}
					if err := json.Unmarshal([]byte(logOutput), &jsonData); err != nil {
						t.Errorf("Expected valid JSON output, got: %s", logOutput)
					}
					if !strings.Contains(logOutput, `"msg":"test message"`) {
						t.Errorf("Expected JSON to contain message, got: %s", logOutput)
					}
				} else {
					// Verify it's text format
					if !strings.Contains(logOutput, "test message") {
						t.Errorf("Expected text to contain message, got: %s", logOutput)
					}
					if !strings.Contains(logOutput, "key=value") {
						t.Errorf("Expected text to contain key=value, got: %s", logOutput)
					}
				}
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"Debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"WARNING", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"invalid", slog.LevelInfo},
		{"", slog.LevelInfo},
		{"trace", slog.LevelInfo}, // Unknown level defaults to info
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseLevel(tt.input)
			if result != tt.expected {
				t.Errorf("parseLevel(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsDebugEnabled(t *testing.T) {
	tests := []struct {
		level    string
		expected bool
	}{
		{"debug", true},
		{"info", false},
		{"warn", false},
		{"error", false},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			logger := New(tt.level, "text", &bytes.Buffer{})
			result := logger.IsDebugEnabled()
			if result != tt.expected {
				t.Errorf("IsDebugEnabled() for level %s = %v, want %v", tt.level, result, tt.expected)
			}
		})
	}
}

func TestSpecializedLogMethods(t *testing.T) {
	tests := []struct {
		name           string
		logFunc        func(*Logger, *bytes.Buffer)
		expectedType   string
		expectedLevel  string
		expectedMsg    string
	}{
		{
			name: "Progress",
			logFunc: func(l *Logger, buf *bytes.Buffer) {
				l.Progress("processing", "count", 5)
			},
			expectedType:  "progress",
			expectedLevel: "INFO",
			expectedMsg:   "processing",
		},
		{
			name: "Success",
			logFunc: func(l *Logger, buf *bytes.Buffer) {
				l.Success("completed", "duration", "5s")
			},
			expectedType:  "success",
			expectedLevel: "INFO",
			expectedMsg:   "completed",
		},
		{
			name: "Failure",
			logFunc: func(l *Logger, buf *bytes.Buffer) {
				l.Failure("failed", "error", "timeout")
			},
			expectedType:  "failure",
			expectedLevel: "ERROR",
			expectedMsg:   "failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := New("debug", "text", buf)

			tt.logFunc(logger, buf)

			output := buf.String()
			if !strings.Contains(output, tt.expectedMsg) {
				t.Errorf("Expected message %q in output: %s", tt.expectedMsg, output)
			}
			if !strings.Contains(output, "type="+tt.expectedType) {
				t.Errorf("Expected type=%s in output: %s", tt.expectedType, output)
			}
			if !strings.Contains(output, tt.expectedLevel) {
				t.Errorf("Expected level %s in output: %s", tt.expectedLevel, output)
			}
		})
	}
}

func TestCategoryLogMethods(t *testing.T) {
	tests := []struct {
		name             string
		logFunc          func(*Logger, *bytes.Buffer)
		expectedCategory string
		expectedMsg      string
	}{
		{
			name: "Network",
			logFunc: func(l *Logger, buf *bytes.Buffer) {
				l.Network("connecting", "host", "example.com")
			},
			expectedCategory: "network",
			expectedMsg:      "connecting",
		},
		{
			name: "TLS",
			logFunc: func(l *Logger, buf *bytes.Buffer) {
				l.TLS("handshake", "version", "1.3")
			},
			expectedCategory: "tls",
			expectedMsg:      "handshake",
		},
		{
			name: "CT",
			logFunc: func(l *Logger, buf *bytes.Buffer) {
				l.CT("querying", "domain", "example.com")
			},
			expectedCategory: "ct",
			expectedMsg:      "querying",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := New("debug", "text", buf) // Use debug level to see debug messages

			tt.logFunc(logger, buf)

			output := buf.String()
			if !strings.Contains(output, tt.expectedMsg) {
				t.Errorf("Expected message %q in output: %s", tt.expectedMsg, output)
			}
			if !strings.Contains(output, "category="+tt.expectedCategory) {
				t.Errorf("Expected category=%s in output: %s", tt.expectedCategory, output)
			}
		})
	}
}

func TestCategoryLogMethodsWithInfoLevel(t *testing.T) {
	// Test that category methods don't log when level is info (since they use Debug)
	buf := &bytes.Buffer{}
	logger := New("info", "text", buf)

	logger.Network("connecting", "host", "example.com")
	logger.TLS("handshake", "version", "1.3")
	logger.CT("querying", "domain", "example.com")

	output := buf.String()
	if output != "" {
		t.Errorf("Expected no output for debug messages at info level, got: %s", output)
	}
}

func TestWithTarget(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New("info", "text", buf)

	targetLogger := logger.WithTarget("example.com:443")
	targetLogger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "target=example.com:443") {
		t.Errorf("Expected target context in output: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected message in output: %s", output)
	}

	// Verify the returned logger has the same level
	if targetLogger.level != logger.level {
		t.Errorf("Expected same level %v, got %v", logger.level, targetLogger.level)
	}
}

func TestWithProtocol(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New("info", "text", buf)

	protocolLogger := logger.WithProtocol("https")
	protocolLogger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "protocol=https") {
		t.Errorf("Expected protocol context in output: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected message in output: %s", output)
	}

	// Verify the returned logger has the same level
	if protocolLogger.level != logger.level {
		t.Errorf("Expected same level %v, got %v", logger.level, protocolLogger.level)
	}
}

func TestChainedContext(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New("info", "text", buf)

	// Test chaining WithTarget and WithProtocol
	chainedLogger := logger.WithTarget("example.com:443").WithProtocol("https")
	chainedLogger.Info("chained context test")

	output := buf.String()
	if !strings.Contains(output, "target=example.com:443") {
		t.Errorf("Expected target context in chained output: %s", output)
	}
	if !strings.Contains(output, "protocol=https") {
		t.Errorf("Expected protocol context in chained output: %s", output)
	}
	if !strings.Contains(output, "chained context test") {
		t.Errorf("Expected message in chained output: %s", output)
	}
}

func TestJSONOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New("info", "json", buf)

	logger.Info("json test", "key1", "value1", "key2", 42)

	output := buf.String()
	
	// Verify it's valid JSON
	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(output), &jsonData); err != nil {
		t.Fatalf("Expected valid JSON output, got error: %v, output: %s", err, output)
	}

	// Check specific fields
	if jsonData["msg"] != "json test" {
		t.Errorf("Expected msg='json test', got %v", jsonData["msg"])
	}
	if jsonData["key1"] != "value1" {
		t.Errorf("Expected key1='value1', got %v", jsonData["key1"])
	}
	if jsonData["key2"] != float64(42) { // JSON numbers are float64
		t.Errorf("Expected key2=42, got %v", jsonData["key2"])
	}
}

func TestNilOutputUsesStderr(t *testing.T) {
	// Capture original stderr
	originalStderr := os.Stderr

	// Create a pipe to capture stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	// Create logger with nil output
	logger := New("info", "text", nil)
	logger.Info("stderr test")

	// Close writer and restore stderr
	w.Close()
	os.Stderr = originalStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil && err.Error() != "EOF" {
		t.Fatal(err)
	}
	r.Close()

	output := string(buf[:n])
	if !strings.Contains(output, "stderr test") {
		t.Errorf("Expected message in stderr output: %s", output)
	}
}

// Benchmark tests
func BenchmarkLogger_Info(b *testing.B) {
	logger := New("info", "text", &bytes.Buffer{})
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message", "iteration", i, "data", "test")
	}
}

func BenchmarkLogger_JSON(b *testing.B) {
	logger := New("info", "json", &bytes.Buffer{})
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message", "iteration", i, "data", "test")
	}
}

func BenchmarkLogger_WithContext(b *testing.B) {
	logger := New("info", "text", &bytes.Buffer{}).WithTarget("example.com").WithProtocol("https")
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message", "iteration", i)
	}
}

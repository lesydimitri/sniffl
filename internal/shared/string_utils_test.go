package shared

import (
	"errors"
	"strings"
	"testing"
)

func TestNewStringBuilder(t *testing.T) {
	tests := []struct {
		name     string
		capacity int
	}{
		{"zero_capacity", 0},
		{"small_capacity", 10},
		{"large_capacity", 1000},
		{"negative_capacity", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := NewStringBuilder(tt.capacity)
			if sb == nil {
				t.Error("Expected non-nil StringBuilder")
			}
			
			// Test initial state
			if sb.Len() != 0 {
				t.Errorf("Expected initial length 0, got %d", sb.Len())
			}
			
			if sb.String() != "" {
				t.Errorf("Expected empty initial string, got %q", sb.String())
			}
		})
	}
}

func TestStringBuilder_WriteString(t *testing.T) {
	tests := []struct {
		name     string
		inputs   []string
		expected string
	}{
		{
			name:     "single_string",
			inputs:   []string{"hello"},
			expected: "hello",
		},
		{
			name:     "multiple_strings",
			inputs:   []string{"hello", " ", "world"},
			expected: "hello world",
		},
		{
			name:     "empty_strings",
			inputs:   []string{"", "test", ""},
			expected: "test",
		},
		{
			name:     "unicode_strings",
			inputs:   []string{"🚀", " ", "test", " ", "🎉"},
			expected: "🚀 test 🎉",
		},
		{
			name:     "long_strings",
			inputs:   []string{strings.Repeat("a", 1000), strings.Repeat("b", 1000)},
			expected: strings.Repeat("a", 1000) + strings.Repeat("b", 1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := NewStringBuilder(0)
			
			for _, input := range tt.inputs {
				sb.WriteString(input)
			}
			
			result := sb.String()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
			
			expectedLen := len(tt.expected)
			if sb.Len() != expectedLen {
				t.Errorf("Expected length %d, got %d", expectedLen, sb.Len())
			}
		})
	}
}

func TestStringBuilder_WriteInt(t *testing.T) {
	tests := []struct {
		name     string
		inputs   []int
		expected string
	}{
		{
			name:     "single_positive",
			inputs:   []int{42},
			expected: "42",
		},
		{
			name:     "single_negative",
			inputs:   []int{-42},
			expected: "-42",
		},
		{
			name:     "zero",
			inputs:   []int{0},
			expected: "0",
		},
		{
			name:     "multiple_ints",
			inputs:   []int{1, 2, 3},
			expected: "123",
		},
		{
			name:     "large_numbers",
			inputs:   []int{2147483647, -2147483648},
			expected: "2147483647-2147483648",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := NewStringBuilder(0)
			
			for _, input := range tt.inputs {
				sb.WriteInt(input)
			}
			
			result := sb.String()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestStringBuilder_WriteByte(t *testing.T) {
	tests := []struct {
		name     string
		inputs   []byte
		expected string
	}{
		{
			name:     "single_byte",
			inputs:   []byte{'A'},
			expected: "A",
		},
		{
			name:     "multiple_bytes",
			inputs:   []byte{'H', 'e', 'l', 'l', 'o'},
			expected: "Hello",
		},
		{
			name:     "special_chars",
			inputs:   []byte{'\n', '\t', ' '},
			expected: "\n\t ",
		},
		{
			name:     "numeric_bytes",
			inputs:   []byte{'1', '2', '3'},
			expected: "123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := NewStringBuilder(0)
			
			for _, input := range tt.inputs {
				err := sb.WriteByte(input)
				if err != nil {
					t.Errorf("Unexpected error writing byte: %v", err)
				}
			}
			
			result := sb.String()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestStringBuilder_Mixed(t *testing.T) {
	sb := NewStringBuilder(50)
	
	// Mix different write operations
	sb.WriteString("Port: ")
	sb.WriteInt(443)
	sb.WriteByte('\n')
	sb.WriteString("Host: ")
	sb.WriteString("example.com")
	
	expected := "Port: 443\nHost: example.com"
	result := sb.String()
	
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
	
	if sb.Len() != len(expected) {
		t.Errorf("Expected length %d, got %d", len(expected), sb.Len())
	}
}

func TestJoinHostPort(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     int
		expected string
	}{
		{
			name:     "simple_domain",
			host:     "example.com",
			port:     443,
			expected: "example.com:443",
		},
		{
			name:     "ipv4_address",
			host:     "192.168.1.1",
			port:     80,
			expected: "192.168.1.1:80",
		},
		{
			name:     "ipv6_address",
			host:     "2001:db8::1",
			port:     8080,
			expected: "2001:db8::1:8080",
		},
		{
			name:     "localhost",
			host:     "localhost",
			port:     3000,
			expected: "localhost:3000",
		},
		{
			name:     "long_hostname",
			host:     "very-long-hostname.subdomain.example.com",
			port:     65535,
			expected: "very-long-hostname.subdomain.example.com:65535",
		},
		{
			name:     "port_zero",
			host:     "example.com",
			port:     0,
			expected: "example.com:0",
		},
		{
			name:     "empty_host",
			host:     "",
			port:     80,
			expected: ":80",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := JoinHostPort(tt.host, tt.port)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFormatError(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		target    string
		err       error
		expected  string
	}{
		{
			name:      "simple_error",
			operation: "connect",
			target:    "example.com:443",
			err:       errors.New("connection refused"),
			expected:  "connect failed for example.com:443: connection refused",
		},
		{
			name:      "tls_error",
			operation: "TLS handshake",
			target:    "secure.example.com:443",
			err:       errors.New("certificate verify failed"),
			expected:  "TLS handshake failed for secure.example.com:443: certificate verify failed",
		},
		{
			name:      "timeout_error",
			operation: "read",
			target:    "slow.example.com:80",
			err:       errors.New("i/o timeout"),
			expected:  "read failed for slow.example.com:80: i/o timeout",
		},
		{
			name:      "empty_operation",
			operation: "",
			target:    "example.com:443",
			err:       errors.New("unknown error"),
			expected:  " failed for example.com:443: unknown error",
		},
		{
			name:      "empty_target",
			operation: "connect",
			target:    "",
			err:       errors.New("no target specified"),
			expected:  "connect failed for : no target specified",
		},
		{
			name:      "long_error_message",
			operation: "validate",
			target:    "test.com:443",
			err:       errors.New(strings.Repeat("very long error message ", 10)),
			expected:  "validate failed for test.com:443: " + strings.Repeat("very long error message ", 10),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatError(tt.operation, tt.target, tt.err)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// Benchmark tests
func BenchmarkStringBuilder_WriteString(b *testing.B) {
	sb := NewStringBuilder(1000)
	testString := "benchmark test string"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.WriteString(testString)
	}
}

func BenchmarkStringBuilder_WriteInt(b *testing.B) {
	sb := NewStringBuilder(1000)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.WriteInt(i)
	}
}

func BenchmarkJoinHostPort(b *testing.B) {
	host := "example.com"
	port := 443
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = JoinHostPort(host, port)
	}
}

func BenchmarkFormatError(b *testing.B) {
	operation := "connect"
	target := "example.com:443"
	err := errors.New("connection refused")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatError(operation, target, err)
	}
}

// Comparison benchmarks
func BenchmarkJoinHostPort_vs_Sprintf(b *testing.B) {
	host := "example.com"
	port := 443
	
	b.Run("JoinHostPort", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = JoinHostPort(host, port)
		}
	})
	
	b.Run("Sprintf", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = strings.Join([]string{host, ":", string(rune(port + '0'))}, "")
		}
	})
}

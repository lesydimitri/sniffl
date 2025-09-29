package shared

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lesydimitri/sniffl/internal/logging"
)

func TestNewTLSHelper(t *testing.T) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	
	helper := NewTLSHelper(logger)
	
	if helper == nil {
		t.Fatal("Expected non-nil TLSHelper")
	}
	
	if helper.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
}

func TestTLSHelper_IsCertVerificationError(t *testing.T) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	helper := NewTLSHelper(logger)
	
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil_error",
			err:      nil,
			expected: false,
		},
		{
			name:     "certificate_invalid_error",
			err:      x509.CertificateInvalidError{Reason: x509.Expired},
			expected: true,
		},
		{
			name:     "hostname_error",
			err:      x509.HostnameError{Host: "example.com"},
			expected: true,
		},
		{
			name:     "unknown_authority_error",
			err:      x509.UnknownAuthorityError{},
			expected: true,
		},
		{
			name:     "generic_certificate_error",
			err:      errors.New("certificate verify failed"),
			expected: true,
		},
		{
			name:     "x509_certificate_error",
			err:      errors.New("x509: certificate signed by unknown authority"),
			expected: true,
		},
		{
			name:     "certificate_expired_error",
			err:      errors.New("certificate has expired"),
			expected: true,
		},
		{
			name:     "certificate_not_yet_valid_error",
			err:      errors.New("certificate is not yet valid"),
			expected: true,
		},
		{
			name:     "hostname_mismatch_error",
			err:      errors.New("hostname mismatch"),
			expected: true,
		},
		{
			name:     "case_insensitive_certificate_error",
			err:      errors.New("CERTIFICATE verification failed"),
			expected: true,
		},
		{
			name:     "network_error",
			err:      errors.New("connection refused"),
			expected: false,
		},
		{
			name:     "timeout_error",
			err:      errors.New("i/o timeout"),
			expected: false,
		},
		{
			name:     "generic_error",
			err:      errors.New("some other error"),
			expected: false,
		},
		{
			name:     "empty_error_message",
			err:      errors.New(""),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := helper.IsCertVerificationError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for error: %v", tt.expected, result, tt.err)
			}
		})
	}
}

func TestTLSHelper_BuildTLSConfig(t *testing.T) {
	logOutput := &bytes.Buffer{}
	logger := logging.New("debug", "text", logOutput)
	helper := NewTLSHelper(logger)
	
	tests := []struct {
		name       string
		serverName string
		rootCAs    *x509.CertPool
		insecure   bool
		expectLog  bool
	}{
		{
			name:       "secure_config",
			serverName: "example.com",
			rootCAs:    x509.NewCertPool(),
			insecure:   false,
			expectLog:  false,
		},
		{
			name:       "insecure_config",
			serverName: "test.example.com",
			rootCAs:    nil,
			insecure:   true,
			expectLog:  true,
		},
		{
			name:       "empty_server_name",
			serverName: "",
			rootCAs:    x509.NewCertPool(),
			insecure:   false,
			expectLog:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput.Reset()
			
			config := helper.BuildTLSConfig(tt.serverName, tt.rootCAs, tt.insecure)
			
			if config == nil {
				t.Fatal("Expected non-nil TLS config")
			}
			
			// Verify config properties
			if config.ServerName != tt.serverName {
				t.Errorf("Expected ServerName %q, got %q", tt.serverName, config.ServerName)
			}
			
			if config.RootCAs != tt.rootCAs {
				t.Error("Expected RootCAs to be set correctly")
			}
			
			if config.InsecureSkipVerify != tt.insecure {
				t.Errorf("Expected InsecureSkipVerify %v, got %v", tt.insecure, config.InsecureSkipVerify)
			}
			
			if config.MinVersion != tls.VersionTLS12 {
				t.Errorf("Expected MinVersion TLS 1.2, got %v", config.MinVersion)
			}
			
			// Check logging
			logStr := logOutput.String()
			if tt.expectLog {
				if !strings.Contains(logStr, "insecure TLS configuration") {
					t.Errorf("Expected insecure warning in log, got: %s", logStr)
				}
			} else {
				if strings.Contains(logStr, "insecure") {
					t.Errorf("Unexpected insecure warning in log: %s", logStr)
				}
			}
		})
	}
}

func TestTLSHelper_PerformHandshakeWithFallback(t *testing.T) {
	logOutput := &bytes.Buffer{}
	logger := logging.New("debug", "text", logOutput)
	helper := NewTLSHelper(logger)
	
	ctx := context.Background()
	serverName := "example.com"
	
	tests := []struct {
		name         string
		conn         mockTLSConn
		strictVerify bool
		expectError  bool
		expectInsecure bool
		expectedLog  string
	}{
		{
			name: "successful_handshake",
			conn: mockTLSConn{
				handshakeError: nil,
			},
			strictVerify:   false,
			expectError:    false,
			expectInsecure: false,
			expectedLog:    "TLS handshake successful",
		},
		{
			name: "cert_error_with_fallback",
			conn: mockTLSConn{
				handshakeError: x509.UnknownAuthorityError{},
			},
			strictVerify:   false,
			expectError:    false,
			expectInsecure: true,
			expectedLog:    "TLS verification failed, using insecure fallback",
		},
		{
			name: "cert_error_strict_mode",
			conn: mockTLSConn{
				handshakeError: x509.CertificateInvalidError{Reason: x509.Expired},
			},
			strictVerify: true,
			expectError:  true,
			expectedLog:  "",
		},
		{
			name: "non_cert_error",
			conn: mockTLSConn{
				handshakeError: errors.New("connection refused"),
			},
			strictVerify: false,
			expectError:  true,
			expectedLog:  "",
		},
		{
			name: "handshake_context_error",
			conn: mockTLSConn{
				handshakeError: context.DeadlineExceeded,
			},
			strictVerify: false,
			expectError:  true,
			expectedLog:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput.Reset()
			
			insecure, err := helper.PerformHandshakeWithFallback(ctx, &tt.conn, serverName, tt.strictVerify)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
			
			if insecure != tt.expectInsecure {
				t.Errorf("Expected insecure %v, got %v", tt.expectInsecure, insecure)
			}
			
			if tt.expectedLog != "" {
				logStr := logOutput.String()
				if !strings.Contains(logStr, tt.expectedLog) {
					t.Errorf("Expected log to contain %q, got: %s", tt.expectedLog, logStr)
				}
			}
		})
	}
}

func TestTLSHelper_LogTLSConnectionState(t *testing.T) {
	logOutput := &bytes.Buffer{}
	logger := logging.New("debug", "text", logOutput)
	helper := NewTLSHelper(logger)
	
	serverName := "example.com"
	
	tests := []struct {
		name        string
		state       tls.ConnectionState
		expectLog   bool
		expectedLog []string
	}{
		{
			name: "connection_with_certificate",
			state: tls.ConnectionState{
				Version:     tls.VersionTLS13,
				CipherSuite: tls.TLS_AES_128_GCM_SHA256,
				PeerCertificates: []*x509.Certificate{
					{
						Subject: pkix.Name{CommonName: "example.com"},
						Issuer:  pkix.Name{CommonName: "Test CA"},
						NotAfter: time.Now().Add(365 * 24 * time.Hour),
					},
				},
			},
			expectLog: true,
			expectedLog: []string{
				"TLS connection established",
				"TLS 1.3",
				"TLS_AES_128_GCM_SHA256",
				"example.com",
			},
		},
		{
			name: "connection_without_certificates",
			state: tls.ConnectionState{
				Version:          tls.VersionTLS12,
				CipherSuite:      tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				PeerCertificates: nil,
			},
			expectLog: false,
		},
		{
			name: "connection_with_empty_certificates",
			state: tls.ConnectionState{
				Version:          tls.VersionTLS12,
				CipherSuite:      tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				PeerCertificates: []*x509.Certificate{},
			},
			expectLog: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput.Reset()
			
			helper.LogTLSConnectionState(tt.state, serverName)
			
			logStr := logOutput.String()
			
			if tt.expectLog {
				for _, expected := range tt.expectedLog {
					if !strings.Contains(logStr, expected) {
						t.Errorf("Expected log to contain %q, got: %s", expected, logStr)
					}
				}
			} else {
				if logStr != "" {
					t.Errorf("Expected no log output, got: %s", logStr)
				}
			}
		})
	}
}

func TestTLSHelper_getTLSVersionString(t *testing.T) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	helper := NewTLSHelper(logger)
	
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x9999, "Unknown (0x9999)"}, // Unknown version
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := helper.getTLSVersionString(tt.version)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestTLSHelper_getCipherSuiteString(t *testing.T) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	helper := NewTLSHelper(logger)
	
	tests := []struct {
		suite    uint16
		expected string
	}{
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA"},
		{tls.TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA"},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		{tls.TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
		{tls.TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
		{tls.TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
		{0x8888, "Unknown (0x8888)"}, // Unknown cipher suite
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := helper.getCipherSuiteString(tt.suite)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// Test edge cases and error conditions
func TestTLSHelper_EdgeCases(t *testing.T) {
	logOutput := &bytes.Buffer{}
	logger := logging.New("debug", "text", logOutput)
	helper := NewTLSHelper(logger)
	
	t.Run("nil_logger", func(t *testing.T) {
		// Test that helper works with nil logger (should not panic)
		helperWithNilLogger := &TLSHelper{logger: nil}
		
		// These should not panic even with nil logger
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Function panicked with nil logger: %v", r)
			}
		}()
		
		_ = helperWithNilLogger.IsCertVerificationError(errors.New("test"))
		_ = helperWithNilLogger.BuildTLSConfig("test.com", nil, false)
		// Note: PerformHandshakeWithFallback and LogTLSConnectionState would panic with nil logger
		// due to logger method calls, which is expected behavior
	})
	
	t.Run("empty_server_name", func(t *testing.T) {
		config := helper.BuildTLSConfig("", nil, false)
		if config.ServerName != "" {
			t.Error("Expected empty ServerName to be preserved")
		}
	})
	
	t.Run("nil_root_cas", func(t *testing.T) {
		config := helper.BuildTLSConfig("test.com", nil, false)
		if config.RootCAs != nil {
			t.Error("Expected nil RootCAs to be preserved")
		}
	})
}

// Mock types for testing

type mockTLSConn struct {
	handshakeError error
	closed         bool
}

func (m *mockTLSConn) HandshakeContext(ctx context.Context) error {
	return m.handshakeError
}

func (m *mockTLSConn) Close() error {
	if m.closed {
		return errors.New("already closed")
	}
	m.closed = true
	return nil
}

// Benchmark tests
func BenchmarkTLSHelper_IsCertVerificationError(b *testing.B) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	helper := NewTLSHelper(logger)
	
	testErrors := []error{
		x509.UnknownAuthorityError{},
		x509.CertificateInvalidError{Reason: x509.Expired},
		x509.HostnameError{Host: "example.com"},
		errors.New("certificate verify failed"),
		errors.New("connection refused"),
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := testErrors[i%len(testErrors)]
		_ = helper.IsCertVerificationError(err)
	}
}

func BenchmarkTLSHelper_BuildTLSConfig(b *testing.B) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	helper := NewTLSHelper(logger)
	
	serverName := "example.com"
	rootCAs := x509.NewCertPool()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = helper.BuildTLSConfig(serverName, rootCAs, false)
	}
}

func BenchmarkTLSHelper_getTLSVersionString(b *testing.B) {
	logger := logging.New("info", "text", &bytes.Buffer{})
	helper := NewTLSHelper(logger)
	
	versions := []uint16{
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
		tls.VersionTLS13,
		0x9999, // Unknown
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		version := versions[i%len(versions)]
		_ = helper.getTLSVersionString(version)
	}
}

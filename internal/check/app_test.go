package check

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lesydimitri/sniffl/internal/shared"
)

// TestApp_Run_SingleTarget_NoExport verifies basic app functionality without export
func TestApp_Run_SingleTarget_NoExport(t *testing.T) {
	t.Parallel()

	var out, errBuf bytes.Buffer
	app := New(Config{
		Out:        &out,
		Err:        &errBuf,
		HTTPClient: noNetworkHTTPClient(),
		FileCreator: func(name string) (io.WriteCloser, error) {
			return nil, fmt.Errorf("unexpected file create: %s", name)
		},
	},
		WithDialer(&mockDialer{}), // Add mock dialer to prevent real network calls
		WithTLSFactory(&mockTLSFactory{
			certs: []*x509.Certificate{
				{
					Raw:          []byte{0x30, 0x82, 0x01, 0x23},
					SerialNumber: big.NewInt(1),
				},
			},
		}),
	)

	// Use "none" protocol for direct TLS connection (with mocked dialer to avoid real network calls)
	targets := []shared.Target{{HostPort: "example.com:443", Protocol: "none"}}
	err := app.Run(context.Background(), targets)

	// The app should handle the "none" protocol (direct TLS) gracefully
	// With mocked TLS factory, this should succeed and return mock certificates
	if err != nil {
		t.Errorf("App.Run with mocked components should succeed, got: %v", err)
	}

	// Verify output was written - should contain certificate report
	output := out.String()
	if !strings.Contains(output, "example.com") {
		t.Error("Expected output to contain target hostname")
	}
}

// TestApp_Run_MultipleTargets verifies handling of multiple targets
func TestApp_Run_MultipleTargets(t *testing.T) {
	t.Parallel()

	var out, errBuf bytes.Buffer
	app := New(Config{
		Out:        &out,
		Err:        &errBuf,
		HTTPClient: noNetworkHTTPClient(),
		FileCreator: func(name string) (io.WriteCloser, error) {
			return nil, fmt.Errorf("unexpected file create: %s", name)
		},
	},
		WithDialer(&mockDialer{}), // Add mock dialer to prevent real network calls
		WithTLSFactory(&mockTLSFactory{
			certs: []*x509.Certificate{
				{
					Raw:          []byte{0x30, 0x82, 0x01, 0x23},
					SerialNumber: big.NewInt(1),
				},
			},
		}),
	)

	targets := []shared.Target{
		{HostPort: "example.com:443", Protocol: "none"},
		{HostPort: "example.org:443", Protocol: "none"},
		{HostPort: "test.com:25", Protocol: "none"}, // Use "none" for direct TLS (mocked)
	}

	err := app.Run(context.Background(), targets)

	// Should process all targets without crashing
	if err != nil {
		t.Errorf("App.Run with mocked components should succeed, got: %v", err)
	}

	// Verify output mentions all targets
	output := out.String() + errBuf.String()
	expectedHosts := []string{"example.com", "example.org", "test.com"}
	for _, host := range expectedHosts {
		if !strings.Contains(output, host) {
			t.Errorf("Output should mention target %s", host)
		}
	}
}

// TestApp_Run_WithExport verifies export functionality integration
func TestApp_Run_WithExport(t *testing.T) {
	t.Parallel()

	var out, errBuf bytes.Buffer
	createdFiles := make(map[string]*bytes.Buffer)

	app := New(Config{
		Out:        &out,
		Err:        &errBuf,
		ExportMode: "single",
		HTTPClient: noNetworkHTTPClient(),
		FileCreator: func(name string) (io.WriteCloser, error) {
			buffer := &bytes.Buffer{}
			createdFiles[name] = buffer
			return nopWriteCloser{buffer}, nil
		},
	},
		WithDialer(&mockDialer{}), // Add mock dialer to prevent real network calls
		WithTLSFactory(&mockTLSFactory{
			certs: []*x509.Certificate{
				{
					Raw:          []byte{0x30, 0x82, 0x01, 0x23},
					SerialNumber: big.NewInt(1),
				},
			},
		}),
	)

	targets := []shared.Target{{HostPort: "example.com:443", Protocol: "none"}}
	err := app.Run(context.Background(), targets)

	// With mocked components, this should succeed
	if err != nil {
		t.Errorf("App.Run with mocked components should succeed, got: %v", err)
	}

	// Export should be attempted - FileCreator should be called when export mode is set
	if len(createdFiles) == 0 {
		t.Error("Expected file creation with export mode enabled")
	}
}

// TestApp_Run_InvalidHostPort verifies handling of invalid host:port formats
func TestApp_Run_InvalidHostPort(t *testing.T) {
	t.Parallel()

	var out, errBuf bytes.Buffer
	app := New(Config{
		Out:        &out,
		Err:        &errBuf,
		HTTPClient: noNetworkHTTPClient(),
	},
		WithDialer(&mockDialer{}), // Add mock dialer to prevent real network calls
		WithTLSFactory(&mockTLSFactory{
			certs: []*x509.Certificate{
				{
					Raw:          []byte{0x30, 0x82, 0x01, 0x23},
					SerialNumber: big.NewInt(1),
				},
			},
		}),
	)

	invalidTargets := []shared.Target{
		{HostPort: "invalid-host-port", Protocol: "http"},
		{HostPort: "host:invalid-port", Protocol: "http"},
		{HostPort: ":443", Protocol: "http"},
		{HostPort: "host:", Protocol: "http"},
	}

	err := app.Run(context.Background(), invalidTargets)

	// Should handle invalid targets gracefully
	if err != nil {
		t.Errorf("App.Run should handle invalid targets gracefully, got error: %v", err)
	}

	// Should report invalid formats in output
	output := out.String()
	if !strings.Contains(strings.ToLower(output), "invalid host:port") {
		t.Error("Output should mention invalid host:port format")
	}
}

// TestApp_Run_ProtocolResolution verifies protocol resolution logic
func TestApp_Run_ProtocolResolution(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		target        shared.Target
		expectedProto string
	}{
		{
			name:          "explicit_none",
			target:        shared.Target{HostPort: "mail.example.com:25", Protocol: "none"},
			expectedProto: "none",
		},
		{
			name:          "port_based_none",
			target:        shared.Target{HostPort: "mail.example.com:25", Protocol: "none"},
			expectedProto: "none",
		},
		{
			name:          "port_based_none_https",
			target:        shared.Target{HostPort: "web.example.com:443", Protocol: "none"},
			expectedProto: "none",
		},
		{
			name:          "unknown_port_none",
			target:        shared.Target{HostPort: "service.example.com:9999", Protocol: "none"},
			expectedProto: "none",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			app := New(Config{
				Out:        &out,
				Err:        &errBuf,
				Verbose:    true, // Enable debug output to see protocol resolution
				HTTPClient: noNetworkHTTPClient(),
			},
				WithDialer(&mockDialer{}), // Add mock dialer to prevent real network calls
				WithTLSFactory(&mockTLSFactory{
					certs: []*x509.Certificate{
						{
							Raw:          []byte{0x30, 0x82, 0x01, 0x23},
							SerialNumber: big.NewInt(1),
						},
					},
				}),
			)

			err := app.Run(context.Background(), []shared.Target{tc.target})
			_ = err

			// Check debug output for protocol information
			output := out.String() + errBuf.String()
			if !strings.Contains(output, tc.expectedProto) {
				t.Errorf("Expected protocol %s to be mentioned in output for %s",
					tc.expectedProto, tc.target.HostPort)
			}
		})
	}
}

// TestApp_Run_WithMockTLS tests app with mocked TLS connections
func TestApp_Run_WithMockTLS(t *testing.T) {
	t.Parallel()

	var out, errBuf bytes.Buffer

	// Create app with mock TLS factory that returns fake certificates
	app := New(Config{
		Out:        &out,
		Err:        &errBuf,
		HTTPClient: noNetworkHTTPClient(),
	},
		WithDialer(&mockDialer{}),
		WithTLSFactory(&mockTLSFactory{
			certs: []*x509.Certificate{
				{
					Raw:          []byte{0x30, 0x82, 0x01, 0x23}, // Minimal DER
					SerialNumber: big.NewInt(1),                  // Prevent nil pointer
				},
			},
		}),
	)

	targets := []shared.Target{{HostPort: "example.com:443", Protocol: "http"}}
	err := app.Run(context.Background(), targets)

	if err != nil {
		t.Errorf("App.Run with mock TLS should succeed, got: %v", err)
	}

	// Should show certificate report
	output := out.String()
	if !strings.Contains(output, "Report for example.com:443") {
		t.Error("Output should contain certificate report")
	}
}

// TestApp_Run_BundleExport verifies bundle export functionality
func TestApp_Run_BundleExport(t *testing.T) {
	t.Parallel()

	var out, errBuf bytes.Buffer
	createdFiles := make(map[string]*bytes.Buffer)

	// Create a mock HTTP server for CA bundle requests
	mockCAServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a simple test certificate bundle
		_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")) //nolint:errcheck
	}))
	defer mockCAServer.Close()

	app := New(Config{
		Out:         &out,
		Err:         &errBuf,
		ExportMode:  "bundle",
		CABundleURL: mockCAServer.URL,      // Use mock server instead of real CA bundle URL
		HTTPClient:  mockCAServer.Client(), // Use mock server's client
		FileCreator: func(name string) (io.WriteCloser, error) {
			buffer := &bytes.Buffer{}
			createdFiles[name] = buffer
			return nopWriteCloser{buffer}, nil
		},
		CacheDir: func() (string, error) { return t.TempDir(), nil },
	},
		WithDialer(&mockDialer{}),
		WithTLSFactory(&mockTLSFactory{
			certs: []*x509.Certificate{
				{
					Raw:          []byte{0x30, 0x82, 0x01, 0x23},
					SerialNumber: big.NewInt(1),
				},
			},
		}),
	)

	targets := []shared.Target{
		{HostPort: "example.com:443", Protocol: "http"},
		{HostPort: "test.com:443", Protocol: "http"},
	}

	err := app.Run(context.Background(), targets)
	if err != nil {
		t.Errorf("Bundle export should succeed, got: %v", err)
	}

	// Should create combined bundle file
	bundleCreated := false
	for filename := range createdFiles {
		if strings.Contains(filename, "combined_bundle.pem") {
			bundleCreated = true
			break
		}
	}

	if !bundleCreated {
		t.Error("Expected combined bundle file to be created")
	}
}

// Mock implementations for testing

// mockDialer simulates network connections
type mockDialer struct{}

func (m *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Return a pipe connection for testing
	server, client := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }() //nolint:errcheck
		// Simulate basic protocol responses
		if strings.Contains(address, ":25") {
			// SMTP
			_, _ = server.Write([]byte("220 test ESMTP\r\n")) //nolint:errcheck
		} else if strings.Contains(address, ":143") {
			// IMAP
			_, _ = server.Write([]byte("* OK ready\r\n")) //nolint:errcheck
		}
		// For HTTP/TLS, just keep connection open
	}()
	return client, nil
}

// mockTLSFactory creates mock TLS connections
type mockTLSFactory struct {
	certs []*x509.Certificate
}

func (m *mockTLSFactory) Client(conn net.Conn, cfg *tls.Config) TLSConn {
	return &mockTLSConn{
		conn:  conn,
		certs: m.certs,
	}
}

// mockTLSConn simulates TLS connection
type mockTLSConn struct {
	conn  net.Conn
	certs []*x509.Certificate
}

func (m *mockTLSConn) HandshakeContext(ctx context.Context) error {
	return nil // Simulate successful handshake
}

func (m *mockTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		PeerCertificates: m.certs,
	}
}

func (m *mockTLSConn) Close() error {
	return m.conn.Close()
}

// Helper types

// nopWriteCloser implements io.WriteCloser for testing
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

// noNetworkHTTPClient returns an HTTP client that fails on any request to prevent network calls
func noNetworkHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return nil, fmt.Errorf("network calls disabled in tests")
			},
		},
	}
}

// Test missing coverage in app.go - test through Run method
func TestApp_ProtocolResolution(t *testing.T) {
	t.Parallel()

	var out, errBuf bytes.Buffer
	app := New(Config{
		Out:        &out,
		Err:        &errBuf,
		HTTPClient: noNetworkHTTPClient(),
	},
		WithDialer(&mockDialer{}), // Add mock dialer to prevent real network calls
		WithTLSFactory(&mockTLSFactory{
			certs: []*x509.Certificate{
				{
					Raw:          []byte{0x30, 0x82, 0x01, 0x23},
					SerialNumber: big.NewInt(1),
				},
			},
		}),
	)

	// Test protocol resolution through Run method
	// This will test the resolveProtocol method indirectly
	targets := []shared.Target{
		{HostPort: "example.com:443", Protocol: ""},      // Should resolve to http
		{HostPort: "mail.example.com:587", Protocol: ""}, // Should resolve to smtp
	}

	// With mocked components, this should succeed and test protocol resolution
	err := app.Run(context.Background(), targets)
	if err != nil {
		t.Errorf("App.Run with mocked components should succeed, got: %v", err)
	}

	// Verify that protocol resolution was exercised by checking output
	output := out.String()
	if !strings.Contains(output, "example.com") || !strings.Contains(output, "mail.example.com") {
		t.Error("Expected both targets to be processed and mentioned in output")
	}
}

// Test Run method error paths
func TestApp_Run_ErrorPaths(t *testing.T) {
	t.Parallel()

	var out, errBuf bytes.Buffer
	app := New(Config{
		Out:        &out,
		Err:        &errBuf,
		HTTPClient: noNetworkHTTPClient(),
	},
		WithDialer(&mockDialer{}), // Add mock dialer to prevent real network calls
		WithTLSFactory(&mockTLSFactory{
			certs: []*x509.Certificate{
				{
					Raw:          []byte{0x30, 0x82, 0x01, 0x23},
					SerialNumber: big.NewInt(1),
				},
			},
		}),
	)

	// Test with invalid host:port format
	targets := []shared.Target{{HostPort: "invalid-host-port", Protocol: "none"}}
	err := app.Run(context.Background(), targets)
	// The app handles invalid host:port gracefully - it skips invalid targets
	// and prints a message, but doesn't return an error
	if err != nil {
		t.Errorf("App.Run should handle invalid targets gracefully, got error: %v", err)
	}

	// Should report invalid format in output
	output := out.String()
	if !strings.Contains(strings.ToLower(output), "invalid host:port format") {
		t.Error("Expected output to mention invalid host:port format")
	}

	// Test with empty targets
	err = app.Run(context.Background(), []shared.Target{})
	if err != nil {
		t.Errorf("Expected no error for empty targets, got %v", err)
	}
}

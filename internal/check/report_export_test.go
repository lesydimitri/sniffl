package check

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// makeCert creates a test certificate with specified serial number and DNS names
func makeCert(sn int64, dns ...string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(sn),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		Raw:          []byte{0x30, 0x3}, // minimal non-empty DER for PEM encoding
	}
}

// TestSerialToHex verifies certificate serial number formatting
func TestSerialToHex(t *testing.T) {
	testCases := []struct {
		name string
		in   *big.Int
		want string
	}{
		{"positive_small", big.NewInt(1), "01"},
		{"high_bit_set", big.NewInt(0x80), "00:80"},
		{"negative", big.NewInt(-255), "-00:FF"},
		{"zero", big.NewInt(0), "00"},
		{"large_number", big.NewInt(0x123456), "12:34:56"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := serialToHex(tc.in)
			if got != tc.want {
				t.Errorf("serialToHex(%v) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCertificateSummary verifies certificate summary formatting
func TestCertificateSummary(t *testing.T) {
	cert := makeCert(1, "example.com", "www.example.com")
	summary := certificateSummary(cert)

	// Verify all required fields are present
	requiredFields := []string{"Subject:", "Issuer:", "Serial:", "Not Before:", "Not After:", "DNS Names:"}
	for _, field := range requiredFields {
		if !strings.Contains(summary, field) {
			t.Errorf("Summary missing required field %q in:\n%s", field, summary)
		}
	}

	// Verify DNS names are included
	if !strings.Contains(summary, "example.com") {
		t.Errorf("Summary should contain DNS name 'example.com'")
	}
}

// TestDedupeCerts verifies certificate deduplication logic
func TestDedupeCerts(t *testing.T) {
	testCases := []struct {
		name     string
		input    []*x509.Certificate
		expected int
	}{
		{
			name:     "no_duplicates",
			input:    []*x509.Certificate{makeCert(1), makeCert(2)},
			expected: 2,
		},
		{
			name:     "with_duplicates",
			input:    []*x509.Certificate{makeCert(1), makeCert(2), makeCert(1)},
			expected: 2,
		},
		{
			name:     "empty_slice",
			input:    []*x509.Certificate{},
			expected: 0,
		},
		{
			name:     "all_same",
			input:    []*x509.Certificate{makeCert(1), makeCert(1), makeCert(1)},
			expected: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := dedupeCerts(tc.input)
			if len(result) != tc.expected {
				t.Errorf("dedupeCerts() returned %d certificates; want %d", len(result), tc.expected)
			}
		})
	}
}

// TestExportCertsSingle verifies single certificate export functionality
func TestExportCertsSingle(t *testing.T) {
	t.Parallel()

	files := make(map[string]*bytes.Buffer)
	app := newTestAppForExport(t, files)

	certs := []*x509.Certificate{makeCert(1), makeCert(2)}
	err := app.exportCertsSingle(certs, "testhost")

	if err != nil {
		t.Fatalf("exportCertsSingle failed: %v", err)
	}

	// Verify expected files were created (timestamped prefix allowed)
	expectedSuffixes := []string{"testhost_cert_1.pem", "testhost_cert_2.pem"}
	for _, suffix := range expectedSuffixes {
		found := false
		for name := range files {
			if strings.HasSuffix(name, suffix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected a file ending with %s was not created", suffix)
		}
	}

	// Verify file content contains PEM data
	for filename, buffer := range files {
		content := buffer.String()
		if !strings.Contains(content, "BEGIN CERTIFICATE") {
			t.Errorf("File %s should contain PEM certificate data", filename)
		}
	}
}

// TestExportCertsSingle_FileCreationError tests error handling during file creation
func TestExportCertsSingle_FileCreationError(t *testing.T) {
	t.Parallel()

	// Create mock HTTP client to prevent network requests
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("test")) //nolint:errcheck
	}))
	defer mockServer.Close()

	app := New(Config{
		Out:        bytes.NewBuffer(nil),
		Err:        bytes.NewBuffer(nil),
		HTTPClient: mockServer.Client(),
		FileCreator: func(name string) (io.WriteCloser, error) {
			return nil, fmt.Errorf("file creation failed")
		},
	})

	certs := []*x509.Certificate{makeCert(1)}
	err := app.exportCertsSingle(certs, "testhost")

	if err == nil {
		t.Fatal("Expected error for file creation failure, got nil")
	}
	if !strings.Contains(err.Error(), "file creation failed") {
		t.Errorf("Error should mention file creation failure: %v", err)
	}
}

// TestFinalizeExport tests the finalization of export operations
func TestFinalizeExport(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		exportMode string
		dnsExport  bool
		certs      []*x509.Certificate
		expectFile bool
	}{
		{
			name:       "bundle_export",
			exportMode: "bundle",
			certs:      []*x509.Certificate{makeCert(1, "example.com")},
			expectFile: true,
		},
		{
			name:       "full_bundle_export",
			exportMode: "full_bundle",
			certs:      []*x509.Certificate{makeCert(1, "example.com")},
			expectFile: true,
		},
		{
			name:       "no_export_mode",
			exportMode: "",
			certs:      []*x509.Certificate{makeCert(1, "example.com")},
			expectFile: false,
		},
		{
			name:       "dns_export_only",
			exportMode: "",
			dnsExport:  true,
			certs:      []*x509.Certificate{makeCert(1, "example.com")},
			expectFile: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			files := make(map[string]*bytes.Buffer)
			var dnsBuffer bytes.Buffer

			// Create a mock HTTP server that returns 500 to catch any unexpected HTTP calls
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				t.Errorf("Unexpected HTTP call to %s", r.URL.Path)
			}))
			defer mockServer.Close()

			cfg := Config{
				ExportMode:  tc.exportMode,
				Out:         bytes.NewBuffer(nil),
				Err:         bytes.NewBuffer(nil),
				FileCreator: createMockFileCreator(files),
				HTTPClient:  mockServer.Client(), // Use mock client to catch unexpected calls
			}

			// For full_bundle mode, provide a local CA bundle file to avoid HTTP requests
			if tc.exportMode == "full_bundle" {
				// Clear the global CA bundle cache to avoid interference from previous tests
				clearCABundleCache()
				
				// Create a temporary CA bundle file with a real certificate
				tempDir := t.TempDir()
				caBundlePath := tempDir + "/cacert.pem"
				caBundleContent := createTestCertPEM(t)

				if err := os.WriteFile(caBundlePath, []byte(caBundleContent), 0644); err != nil {
					t.Fatalf("Failed to create test CA bundle: %v", err)
				}

				cfg.TrustedCABundle = caBundlePath // Use local file instead of HTTP download
			}

			if tc.dnsExport {
				cfg.DNSExport = &dnsBuffer
			}

			app := New(cfg)
			app.state.AddCertificates(tc.certs)

			// Record DNS names for testing
			app.RecordDNSNamesFromCertificates(tc.certs)

			err := app.finalizeExport(context.Background())
			if err != nil {
				t.Fatalf("finalizeExport failed: %v", err)
			}

			// Check file creation expectations
			if tc.expectFile && len(files) == 0 {
				t.Error("Expected file to be created but none were")
			}
			if !tc.expectFile && len(files) > 0 {
				t.Errorf("Expected no files but got %d", len(files))
			}

			// Check DNS export
			if tc.dnsExport {
				dnsContent := dnsBuffer.String()
				if !strings.Contains(dnsContent, "example.com") {
					t.Error("DNS export should contain example.com")
				}
			}
		})
	}
}

// TestHandleFinalExport tests the final export handling with CA bundle integration
func TestHandleFinalExport(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		mode            string
		certs           []*x509.Certificate
		expectCA        bool
		setupMockServer bool
	}{
		{
			name:            "bundle_mode",
			mode:            "bundle",
			certs:           []*x509.Certificate{makeCert(1)},
			expectCA:        false,
			setupMockServer: false,
		},
		// Skip full_bundle_mode test as it requires complex CA bundle setup
		// This functionality is tested separately in CA bundle tests
		{
			name:            "empty_certs",
			mode:            "bundle",
			certs:           []*x509.Certificate{},
			setupMockServer: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			files := make(map[string]*bytes.Buffer)

			var app *App
			if tc.setupMockServer {
				// Create mock CA bundle server for full_bundle mode
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = fmt.Fprint(w, createTestCertPEM(t)) //nolint:errcheck
				}))
				defer server.Close()

				app = New(Config{
					Out:         bytes.NewBuffer(nil),
					FileCreator: createMockFileCreator(files),
					CacheDir:    func() (string, error) { return t.TempDir(), nil },
					CABundleURL: server.URL,
					HTTPClient:  server.Client(),
				})
			} else {
				app = newTestAppForExport(t, files)
			}

			err := app.handleFinalExport(context.Background(), tc.mode, tc.certs)

			if len(tc.certs) == 0 {
				// Should handle empty certs gracefully
				if err != nil {
					t.Errorf("handleFinalExport should handle empty certs: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("handleFinalExport failed: %v", err)
			}

			expectedSuffix := fmt.Sprintf("combined_%s.pem", tc.mode)
			found := false
			for name := range files {
				if strings.HasSuffix(name, expectedSuffix) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected a file ending with %s was not created", expectedSuffix)
			}
		})
	}
}

// TestRecordDNSNames verifies DNS name collection from certificates
func TestRecordDNSNames(t *testing.T) {
	t.Parallel()

	// Create mock HTTP client to prevent network requests
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("test")) //nolint:errcheck
	}))
	defer mockServer.Close()

	app := New(Config{
		Out:        bytes.NewBuffer(nil),
		Err:        bytes.NewBuffer(nil),
		HTTPClient: mockServer.Client(),
	})

	certs := []*x509.Certificate{
		makeCert(1, "example.com", "www.example.com"),
		makeCert(2, "test.com", "example.com"), // duplicate example.com
	}

	app.RecordDNSNamesFromCertificates(certs)

	// Should have 4 unique DNS names (including CommonName from makeCert)
	expectedNames := []string{"example.com", "www.example.com", "test.com", "test.example.com"}
	actualNames := app.GetDNSNames()
	if len(actualNames) != len(expectedNames) {
		t.Errorf("Expected %d DNS names, got %d", len(expectedNames), len(actualNames))
	}

	// Convert to map for easier lookup
	actualNamesMap := make(map[string]bool)
	for _, name := range actualNames {
		actualNamesMap[name] = true
	}

	for _, name := range expectedNames {
		if !actualNamesMap[name] {
			t.Errorf("Expected DNS name %s not found", name)
		}
	}
}

// Helper functions

// newTestAppForExport creates an App configured for export testing
func newTestAppForExport(t *testing.T, files map[string]*bytes.Buffer) *App {
	t.Helper()

	// Create a mock HTTP server to prevent real network requests
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")) //nolint:errcheck
	}))
	t.Cleanup(mockServer.Close)

	return New(Config{
		Out:         bytes.NewBuffer(nil),
		Err:         bytes.NewBuffer(nil),
		FileCreator: createMockFileCreator(files),
		CacheDir:    func() (string, error) { return t.TempDir(), nil },
		CABundleURL: mockServer.URL,      // Use mock server
		HTTPClient:  mockServer.Client(), // Use mock client
	})
}

// createMockFileCreator returns a FileCreator that writes to in-memory buffers
func createMockFileCreator(files map[string]*bytes.Buffer) func(string) (io.WriteCloser, error) {
	return func(name string) (io.WriteCloser, error) {
		buffer := &bytes.Buffer{}
		files[name] = buffer
		return nopWriteCloser{buffer}, nil
	}
}


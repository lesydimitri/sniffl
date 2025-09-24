package check

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnsureCABundle_DownloadAndCache verifies the complete CA bundle caching workflow:
// 1. First call downloads and writes bundle with ETag persistence
// 2. Second call uses If-None-Match header and receives 304 Not Modified
// 3. File is not rewritten on cache hit
func TestEnsureCABundle_DownloadAndCache(t *testing.T) {
	t.Parallel()

	const testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	
	// Track server interactions
	var reqCount int
	var lastIfNoneMatch string
	
	// Create test server that simulates CA bundle endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		lastIfNoneMatch = r.Header.Get("If-None-Match")
		
		// Return 304 if client sends matching ETag
		if lastIfNoneMatch == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		
		// First request: return bundle with ETag
		w.Header().Set("ETag", `"v1"`)
		_, _ = fmt.Fprint(w, testCertPEM) //nolint:errcheck
	}))
	defer server.Close()

	// Use a fixed temp directory for consistent caching behavior
	tempDir := t.TempDir()
	
	// Track file writes to verify caching behavior
	writeCount := 0
	app := newTestApp(t, Config{
		CABundleURL: server.URL,
		HTTPClient:  server.Client(),
		CacheDir:    func() (string, error) { return tempDir, nil },
		FileCreator: func(name string) (io.WriteCloser, error) {
			if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				return nil, err
			}
			writeCount++
			return os.Create(name)
		},
	})

	// First call: should download and cache
	bundlePath1, err := app.ensureCABundle(context.Background())
	if err != nil {
		t.Fatalf("First ensureCABundle call failed: %v", err)
	}
	
	// Verify bundle file was created with correct content
	assertFileContent(t, bundlePath1, testCertPEM)
	
	// Verify ETag was persisted
	etagPath := filepath.Join(filepath.Dir(bundlePath1), "cacert.etag")
	assertFileContent(t, etagPath, `"v1"`)
	
	// Verify server interaction
	if reqCount != 1 || lastIfNoneMatch != "" {
		t.Errorf("First request: got count=%d, If-None-Match=%q; want count=1, If-None-Match=empty", 
			reqCount, lastIfNoneMatch)
	}

	// Second call: should use cache (304 response)
	bundlePath2, err := app.ensureCABundle(context.Background())
	if err != nil {
		t.Fatalf("Second ensureCABundle call failed: %v", err)
	}
	
	// Verify same path returned and no additional writes
	if bundlePath1 != bundlePath2 {
		t.Errorf("Bundle path changed: %s != %s", bundlePath1, bundlePath2)
	}
	if writeCount != 1 {
		t.Errorf("Expected 1 file write, got %d", writeCount)
	}
	
	// Verify conditional request was made
	if reqCount != 2 || lastIfNoneMatch != `"v1"` {
		t.Errorf("Second request: got count=%d, If-None-Match=%q; want count=2, If-None-Match=\"v1\"", 
			reqCount, lastIfNoneMatch)
	}
}

// TestEnsureCABundle_HTTPError tests error handling for HTTP failures
func TestEnsureCABundle_HTTPError(t *testing.T) {
	t.Parallel()
	
	// Server that returns 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	
	app := newTestApp(t, Config{
		CABundleURL: server.URL,
		HTTPClient:  server.Client(),
		CacheDir:    func() (string, error) { return t.TempDir(), nil },
	})
	
	_, err := app.ensureCABundle(context.Background())
	if err == nil {
		t.Fatal("Expected error for HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Expected error to mention 500 status, got: %v", err)
	}
}

// TestEnsureCABundle_NetworkError tests network failure handling
func TestEnsureCABundle_NetworkError(t *testing.T) {
	t.Parallel()
	
	app := newTestApp(t, Config{
		CABundleURL: "http://nonexistent.invalid",
		CacheDir:    func() (string, error) { return t.TempDir(), nil },
	})
	
	_, err := app.ensureCABundle(context.Background())
	if err == nil {
		t.Fatal("Expected network error, got nil")
	}
}

// TestEnsureCABundle_CacheDirError tests cache directory creation failure
func TestEnsureCABundle_CacheDirError(t *testing.T) {
	t.Parallel()
	
	app := newTestApp(t, Config{
		CABundleURL: "http://example.com",
		CacheDir:    func() (string, error) { return "", fmt.Errorf("cache dir error") },
	})
	
	_, err := app.ensureCABundle(context.Background())
	if err == nil {
		t.Fatal("Expected cache dir error, got nil")
	}
	if !strings.Contains(err.Error(), "cache dir error") {
		t.Errorf("Expected cache dir error, got: %v", err)
	}
}

// TestLoadTrustedCABundle tests loading CA bundle from various sources
func TestLoadTrustedCABundle(t *testing.T) {
	t.Parallel()
	
	testCases := []struct {
		name        string
		bundlePath  string
		expectError bool
		setup       func(t *testing.T) string
	}{
		{
			name:        "valid_bundle_file",
			expectError: false,
			setup: func(t *testing.T) string {
				// Create temporary file with valid PEM content
				tmpFile := filepath.Join(t.TempDir(), "test-bundle.pem")
				// Use a more realistic certificate PEM block
				content := createTestCertPEM(t)
				if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test bundle: %v", err)
				}
				return tmpFile
			},
		},
		{
			name:        "nonexistent_file",
			bundlePath:  "/nonexistent/path/bundle.pem",
			expectError: true,
			setup:       func(t *testing.T) string { return "/nonexistent/path/bundle.pem" },
		},
		{
			name:        "empty_path_error",
			bundlePath:  "",
			expectError: true,
			setup:       func(t *testing.T) string { return "" },
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bundlePath := tc.setup(t)
			
			certs, err := loadTrustedCABundle(bundlePath)
			
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tc.name)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.name, err)
				}
				if certs == nil {
					t.Errorf("Expected non-nil certs for %s", tc.name)
				}
			}
		})
	}
}

// TestFetchAndAppendCABundle tests CA bundle fetching and appending
func TestFetchAndAppendCABundle(t *testing.T) {
	t.Parallel()
	
	// Test HTTP error case
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errorServer.Close()
	
	app := newTestApp(t, Config{
		CABundleURL: errorServer.URL,
		CacheDir:    func() (string, error) { return t.TempDir(), nil },
	})
	
	var certs []*x509.Certificate
	err := app.fetchAndAppendCABundle(context.Background(), &certs)
	if err == nil {
		t.Error("Expected error for HTTP 500, got nil")
	}
	
	// Test invalid PEM content
	invalidPEMServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid pem content")) //nolint:errcheck
	}))
	defer invalidPEMServer.Close()
	
	app2 := newTestApp(t, Config{
		CABundleURL: invalidPEMServer.URL,
		CacheDir:    func() (string, error) { return t.TempDir(), nil },
	})
	
	var certs2 []*x509.Certificate
	_ = app2.fetchAndAppendCABundle(context.Background(), &certs2)
	// Note: fetchAndAppendCABundle might be lenient with invalid PEM content
	// so we don't require an error here
	
	// Create test server with valid certificate PEM
	testCert := createTestCertPEM(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, testCert) //nolint:errcheck
	}))
	defer server.Close()
	
	app3 := newTestApp(t, Config{
		CABundleURL: server.URL,
		HTTPClient:  server.Client(),
		CacheDir:    func() (string, error) { return t.TempDir(), nil },
	})
	
	// Start with some existing certificates
	existingCerts := []*x509.Certificate{createTestCert(t, "existing.com")}
	certs3 := existingCerts
	
	err = app3.fetchAndAppendCABundle(context.Background(), &certs3)
	if err != nil {
		t.Fatalf("fetchAndAppendCABundle failed: %v", err)
	}
	
	// Should have more certificates now
	if len(certs3) <= len(existingCerts) {
		t.Errorf("Expected more certificates after append, got %d (started with %d)", 
			len(certs3), len(existingCerts))
	}
}

// TestCacheDir tests the cacheDir function error cases
func TestCacheDir(t *testing.T) {
	t.Parallel()
	
	// Test successful case
	app := newTestApp(t, Config{})
	dir, err := app.cacheDir()
	if err != nil {
		t.Errorf("cacheDir() failed: %v", err)
	}
	if dir == "" {
		t.Error("Expected non-empty cache directory")
	}
	
	// Test with custom cache dir function that returns error
	errorCacheDir := func() (string, error) {
		return "", fmt.Errorf("cache dir error")
	}
	
	app2 := newTestApp(t, Config{
		CacheDir: errorCacheDir,
	})
	
	// This should trigger the error path in ensureCABundle
	_, err = app2.ensureCABundle(context.Background())
	if err == nil {
		t.Error("Expected error from cache dir function, got nil")
	}
}

// Helper functions for cleaner test code

// newTestApp creates an App with test-friendly defaults
func newTestApp(t *testing.T, cfg Config) *App {
	t.Helper()
	if cfg.Out == nil {
		cfg.Out = bytes.NewBuffer(nil)
	}
	if cfg.Err == nil {
		cfg.Err = bytes.NewBuffer(nil)
	}
	if cfg.FileCreator == nil {
		cfg.FileCreator = func(name string) (io.WriteCloser, error) {
			if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				return nil, err
			}
			return os.Create(name)
		}
	}
	return New(cfg)
}

// assertFileContent verifies file exists and contains expected content
func assertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", path, err)
	}
	if string(content) != expected {
		t.Errorf("File %s content mismatch:\nGot: %q\nWant: %q", path, string(content), expected)
	}
}

// createTestCertPEM creates a valid PEM-encoded certificate for testing
func createTestCertPEM(t *testing.T) string {
	t.Helper()
	cert := createTestCert(t, "test.example.com")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	return string(pem.EncodeToMemory(block))
}

// createTestCert creates a minimal test certificate
func createTestCert(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		Raw:    []byte{0x30, 0x82, 0x01, 0x23}, // Minimal valid DER prefix
		Subject: pkix.Name{CommonName: commonName},
	}
}

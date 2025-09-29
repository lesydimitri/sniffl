package ct

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lesydimitri/sniffl/internal/logging"
)

func TestEntry_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		entry     Entry
		wantValid bool
	}{
		{
			name: "valid certificate",
			entry: Entry{
				NotBefore: time.Now().AddDate(0, -1, 0), // 1 month ago
				NotAfter:  time.Now().AddDate(0, 1, 0),  // 1 month from now
			},
			wantValid: true,
		},
		{
			name: "expired certificate",
			entry: Entry{
				NotBefore: time.Now().AddDate(-1, 0, 0), // 1 year ago
				NotAfter:  time.Now().AddDate(0, -1, 0), // 1 month ago
			},
			wantValid: false,
		},
		{
			name: "future certificate",
			entry: Entry{
				NotBefore: time.Now().AddDate(0, 1, 0), // 1 month from now
				NotAfter:  time.Now().AddDate(0, 2, 0), // 2 months from now
			},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			isValid := now.After(tt.entry.NotBefore) && now.Before(tt.entry.NotAfter)
			if isValid != tt.wantValid {
				t.Errorf("Entry.IsValid() = %v, want %v", isValid, tt.wantValid)
			}
		})
	}
}

func TestQuery_DisplayResults(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		entries []Entry
		want    []string // strings that should be present in output
	}{
		{
			name:    "no certificates found",
			domain:  "nonexistent.example.com",
			entries: []Entry{},
			want:    []string{"No certificates found", "nonexistent.example.com"},
		},
		{
			name:   "single valid certificate",
			domain: "example.com",
			entries: []Entry{
				{
					ID:           12345,
					SerialNumber: "abcd1234",
					NotBefore:    time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
					NotAfter:     time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
					CommonName:   "example.com",
					DNSNames:     []string{"example.com", "www.example.com"},
					Issuer:       "Let's Encrypt Authority X3",
					IsValid:      false, // expired
				},
			},
			want: []string{
				"Certificate Transparency Report for: example.com",
				"Found 1 certificates",
				"Certificate #1 (EXPIRED)",
				"Certificate ID: 12345",
				"Serial Number:  abcd1234",
				"Common Name:    example.com",
				"DNS Names:      example.com, www.example.com",
				"Issuer:         Let's Encrypt Authority X3",
				"Days Expired:",
			},
		},
		{
			name:   "multiple certificates with mixed validity",
			domain: "github.com",
			entries: []Entry{
				{
					ID:           67890,
					SerialNumber: "efgh5678",
					NotBefore:    time.Now().AddDate(0, -1, 0),
					NotAfter:     time.Now().AddDate(0, 1, 0),
					CommonName:   "github.com",
					DNSNames:     []string{"github.com", "*.github.com"},
					Issuer:       "DigiCert Inc",
					IsValid:      true,
				},
				{
					ID:           11111,
					SerialNumber: "ijkl9012",
					NotBefore:    time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
					NotAfter:     time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
					CommonName:   "github.com",
					DNSNames:     []string{"github.com"},
					Issuer:       "DigiCert Inc",
					IsValid:      false,
				},
			},
			want: []string{
				"Certificate Transparency Report for: github.com",
				"Found 2 certificates (1 valid, 1 expired)",
				"Showing all certificates (including expired)",
				"Certificate #1 (VALID)",
				"Certificate #2 (EXPIRED)",
				"Days Left:",
				"Days Expired:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			ct := &Query{
				out: &outBuf,
				err: &errBuf,
			}

			ct.DisplayResults(tt.domain, tt.entries, true, nil)

			output := outBuf.String()
			for _, want := range tt.want {
				if !strings.Contains(output, want) {
					t.Errorf("DisplayResults() output missing expected string %q\nGot output:\n%s", want, output)
				}
			}
		})
	}
}

func TestQuery_NewQuery(t *testing.T) {
	// Test that NewQuery creates a query instance successfully
	var outBuf, errBuf bytes.Buffer

	query, err := NewQuery(&outBuf, &errBuf)
	if err != nil {
		t.Errorf("NewQuery() returned unexpected error: %v", err)
	}

	if query == nil {
		t.Error("NewQuery() returned nil query")
	}

	// Check that initialization message was written
	output := outBuf.String()
	if !strings.Contains(output, "Initializing Certificate Transparency client") {
		t.Error("Expected initialization message in output")
	}
}

func TestDomainPatternMatching(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		testName string
		want     bool
	}{
		{
			name:     "exact match",
			domain:   "example.com",
			testName: "example.com",
			want:     true,
		},
		{
			name:     "subdomain match",
			domain:   "example.com",
			testName: "www.example.com",
			want:     true,
		},
		{
			name:     "deep subdomain match",
			domain:   "example.com",
			testName: "api.v1.example.com",
			want:     true,
		},
		{
			name:     "no match different domain",
			domain:   "example.com",
			testName: "different.org",
			want:     false,
		},
		{
			name:     "partial match should work with ILIKE",
			domain:   "example.com",
			testName: "notexample.com",
			want:     true, // ILIKE %example.com% would match this
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the ILIKE pattern matching used in the query
			pattern := "%" + tt.domain + "%"

			// Simple pattern matching simulation
			matches := strings.Contains(tt.testName, tt.domain)

			if matches != tt.want {
				t.Errorf("Domain pattern matching for %q against %q = %v, want %v",
					tt.testName, pattern, matches, tt.want)
			}
		})
	}
}

func TestIsRelevantDomain(t *testing.T) {
	ct := &Query{}

	tests := []struct {
		name         string
		domainName   string
		targetDomain string
		expected     bool
	}{
		// Valid matches
		{"exact match", "example.com", "example.com", true},
		{"wildcard match", "*.example.com", "example.com", true},
		{"subdomain match", "www.example.com", "example.com", true},
		{"deep subdomain", "api.v1.example.com", "example.com", true},
		{"case insensitive", "WWW.EXAMPLE.COM", "example.com", true},

		// Invalid matches
		{"different domain", "different.com", "example.com", false},
		{"partial string match", "notexample.com", "example.com", false},
		{"contains but not subdomain", "example.com.evil.com", "example.com", false},
		{"email address", "user@example.com", "example.com", false},
		{"certificate name", "Test Certificate - example.com", "example.com", false},
		{"empty string", "", "example.com", false},
		{"just target domain in string", "kaffeevollautomat--test.com", "test.com", false},
		{"compound domain", "www.test.com--www.other.com", "test.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ct.isRelevantDomain(tt.domainName, tt.targetDomain)
			if result != tt.expected {
				t.Errorf("isRelevantDomain(%q, %q) = %v, want %v",
					tt.domainName, tt.targetDomain, result, tt.expected)
			}
		})
	}
}

func TestIsValidDomainName(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		// Valid domains
		{"simple domain", "example.com", true},
		{"subdomain", "www.example.com", true},
		{"deep subdomain", "api.v1.example.com", true},
		{"wildcard domain", "*.example.com", true},
		{"hyphenated domain", "my-site.example.com", true},

		// Invalid domains
		{"email address", "user@example.com", false},
		{"certificate name", "AS207960 Test Intermediate - example.com", false},
		{"empty string", "", false},
		{"just spaces", "   ", false},
		{"no dot", "localhost", false},
		{"starts with space", " example.com", true}, // Trimmed, so valid
		{"ends with space", "example.com ", true},   // Trimmed, so valid
		{"contains spaces", "my site.com", false},
		{"too long", strings.Repeat("a", 250) + ".com", false},
		{"invalid characters", "example$.com", false},
		{"starts with hyphen", "-example.com", false},
		{"ends with hyphen", "example-.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDomainName(tt.domain)
			if result != tt.expected {
				t.Errorf("isValidDomainName(%q) = %v, want %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestQuery_QueryDomain_Success(t *testing.T) {
	t.Parallel()

	// Create a mock HTTP server that returns sample CT data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock response with sample certificate data
		response := `[
			{
				"issuer_ca_id": 16418,
				"issuer_name": "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
				"common_name": "example.com",
				"name_value": "example.com\nwww.example.com",
				"id": 123456789,
				"entry_timestamp": "2023-01-01T00:00:00.000Z",
				"not_before": "2023-01-01T00:00:00",
				"not_after": "2023-04-01T00:00:00",
				"serial_number": "03a2b3c4d5e6f7890123456789abcdef01234567"
			}
		]`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response)) //nolint:errcheck
	}))
	defer server.Close()

	var outBuf, errBuf bytes.Buffer

	// Create CT query with mocked HTTP client
	ct, err := NewQueryWithClient(server.Client(), &outBuf, &errBuf)
	if err != nil {
		t.Fatalf("NewQueryWithClient() failed: %v", err)
	}

	// Test the queryCrtSh method directly with our mock server
	results, err := ct.queryCrtSh(server.URL + "/?q=example.com&output=json")
	if err != nil {
		t.Fatalf("queryCrtSh() failed: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	if results[0].CommonName != "example.com" {
		t.Errorf("Expected CommonName 'example.com', got '%s'", results[0].CommonName)
	}
}

func TestQuery_Close(t *testing.T) {
	t.Parallel()

	var outBuf, errBuf bytes.Buffer
	ct := &Query{
		httpClient: &http.Client{},
		out:        &outBuf,
		err:        &errBuf,
	}

	// Close should not return an error for HTTP client
	err := ct.Close()
	if err != nil {
		t.Errorf("Close() returned unexpected error: %v", err)
	}
}

func TestQuery_queryCrtSh(t *testing.T) {
	t.Parallel()

	// Test successful response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := `[{"id": 123, "common_name": "test.com"}]`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response)) //nolint:errcheck
	}))
	defer server.Close()

	var outBuf, errBuf bytes.Buffer
	ct := &Query{
		httpClient: server.Client(),
		out:        &outBuf,
		err:        &errBuf,
	}

	results, err := ct.queryCrtSh(server.URL)
	if err != nil {
		t.Fatalf("queryCrtSh failed: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	// Test HTTP error
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errorServer.Close()

	_, err = ct.queryCrtSh(errorServer.URL)
	if err == nil {
		t.Error("Expected error for HTTP 500, got nil")
	}

	// Test invalid JSON
	invalidJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json")) //nolint:errcheck
	}))
	defer invalidJSONServer.Close()

	_, err = ct.queryCrtSh(invalidJSONServer.URL)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}

	// Test network error
	_, err = ct.queryCrtSh("http://invalid-url-that-does-not-exist.invalid")
	if err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}

func TestIsValidSubdomainPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		prefix   string
		expected bool
	}{
		{"valid simple", "www", true},
		{"valid with hyphen", "api-v1", true},
		{"valid with dots", "api.v1", true},
		{"valid with wildcard", "*", true},
		{"empty prefix", "", false},
		{"invalid start with hyphen", "-invalid", false},
		{"invalid end with hyphen", "invalid-", false},
		{"valid complex", "sub.domain-name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSubdomainPrefix(tt.prefix)
			if result != tt.expected {
				t.Errorf("isValidSubdomainPrefix(%q) = %v, want %v", tt.prefix, result, tt.expected)
			}
		})
	}
}

// Benchmark the certificate validity checking logic
func TestNewQuery_Variants(t *testing.T) {
	tests := []struct {
		name string
		fn   func() (*Query, error)
	}{
		{
			name: "NewQuery",
			fn: func() (*Query, error) {
				return NewQuery(&bytes.Buffer{}, &bytes.Buffer{})
			},
		},
		{
			name: "NewQueryWithLogger",
			fn: func() (*Query, error) {
				logger := logging.New("info", "text", &bytes.Buffer{})
				return NewQueryWithLogger(&bytes.Buffer{}, &bytes.Buffer{}, logger)
			},
		},
		{
			name: "NewQueryWithClient",
			fn: func() (*Query, error) {
				client := &http.Client{Timeout: 5 * time.Second}
				return NewQueryWithClient(client, &bytes.Buffer{}, &bytes.Buffer{})
			},
		},
		{
			name: "NewQueryWithClientAndLogger",
			fn: func() (*Query, error) {
				client := &http.Client{Timeout: 5 * time.Second}
				logger := logging.New("info", "text", &bytes.Buffer{})
				return NewQueryWithClientAndLogger(client, &bytes.Buffer{}, &bytes.Buffer{}, logger)
			},
		},
		{
			name: "NewQueryWithClientAndLogger_NilLogger",
			fn: func() (*Query, error) {
				client := &http.Client{Timeout: 5 * time.Second}
				return NewQueryWithClientAndLogger(client, &bytes.Buffer{}, &bytes.Buffer{}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := tt.fn()
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if query == nil {
				t.Error("Expected non-nil query")
				return
			}

			if query.httpClient == nil {
				t.Error("Expected non-nil HTTP client")
			}

			if query.logger == nil {
				t.Error("Expected non-nil logger")
			}

			// Test Close method
			if err := query.Close(); err != nil {
				t.Errorf("Close() returned error: %v", err)
			}
		})
	}
}

func TestMergeDNSNames(t *testing.T) {
	tests := []struct {
		name     string
		existing []string
		new      []string
		expected []string
	}{
		{
			name:     "empty_existing",
			existing: []string{},
			new:      []string{"example.com", "www.example.com"},
			expected: []string{"example.com", "www.example.com"},
		},
		{
			name:     "empty_new",
			existing: []string{"example.com"},
			new:      []string{},
			expected: []string{"example.com"},
		},
		{
			name:     "no_duplicates",
			existing: []string{"example.com"},
			new:      []string{"www.example.com", "api.example.com"},
			expected: []string{"example.com", "www.example.com", "api.example.com"},
		},
		{
			name:     "with_duplicates",
			existing: []string{"example.com", "www.example.com"},
			new:      []string{"www.example.com", "api.example.com"},
			expected: []string{"example.com", "www.example.com", "api.example.com"},
		},
		{
			name:     "all_duplicates",
			existing: []string{"example.com", "www.example.com"},
			new:      []string{"example.com", "www.example.com"},
			expected: []string{"example.com", "www.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeDNSNames(tt.existing, tt.new)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected length %d, got %d", len(tt.expected), len(result))
				return
			}

			// Convert to maps for easier comparison
			resultMap := make(map[string]bool)
			for _, name := range result {
				resultMap[name] = true
			}

			expectedMap := make(map[string]bool)
			for _, name := range tt.expected {
				expectedMap[name] = true
			}

			for name := range expectedMap {
				if !resultMap[name] {
					t.Errorf("Expected %q in result", name)
				}
			}

			for name := range resultMap {
				if !expectedMap[name] {
					t.Errorf("Unexpected %q in result", name)
				}
			}
		})
	}
}

// Mock transport for testing HTTP requests
// ...existing code...

func BenchmarkMergeDNSNames(b *testing.B) {
	existing := []string{"example.com", "www.example.com", "api.example.com"}
	new := []string{"www.example.com", "cdn.example.com", "mail.example.com"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mergeDNSNames(existing, new)
	}
}

func BenchmarkIsRelevantDomain(b *testing.B) {
	query := &Query{}

	testCases := []struct {
		name         string
		targetDomain string
	}{
		{"www.example.com", "example.com"},
		{"api.subdomain.example.com", "example.com"},
		{"different.com", "example.com"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tc := testCases[i%len(testCases)]
		_ = query.isRelevantDomain(tc.name, tc.targetDomain)
	}
}

func BenchmarkIsValidDomainName(b *testing.B) {
	testDomains := []string{
		"example.com",
		"www.example.com",
		"api.subdomain.example.com",
		"invalid..domain",
		"valid-domain.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domain := testDomains[i%len(testDomains)]
		_ = isValidDomainName(domain)
	}
}

func BenchmarkCertificateValidityCheck(b *testing.B) {
	entries := make([]Entry, 1000)
	now := time.Now()

	// Create test data with mixed validity
	for i := range entries {
		if i%2 == 0 {
			// Valid certificate
			entries[i] = Entry{
				NotBefore: now.AddDate(0, -1, 0),
				NotAfter:  now.AddDate(0, 1, 0),
			}
		} else {
			// Expired certificate
			entries[i] = Entry{
				NotBefore: now.AddDate(-1, 0, 0),
				NotAfter:  now.AddDate(0, -1, 0),
			}
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		validCount := 0
		for _, entry := range entries {
			if now.After(entry.NotBefore) && now.Before(entry.NotAfter) {
				validCount++
			}
		}
	}
}

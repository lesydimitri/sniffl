package ct

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/lesydimitri/sniffl/internal/logging"
)

// Constants for CT operations
const (
	// DefaultTimeout is the default HTTP client timeout for CT queries
	DefaultTimeout = 30 * time.Second
)

// Entry represents a certificate transparency log entry
type Entry struct {
	ID             int64
	SerialNumber   string
	NotBefore      time.Time
	NotAfter       time.Time
	CommonName     string
	DNSNames       []string
	Issuer         string
	IsValid        bool
	EntryTimestamp *time.Time
	ResultCount    int64
}

// Query handles Certificate Transparency queries using crt.sh web API
type Query struct {
	httpClient *http.Client
	out        io.Writer
	err        io.Writer
	logger     *logging.Logger
}

// NewQuery creates a new Certificate Transparency query handler
func NewQuery(out, err io.Writer) (*Query, error) {
	return NewQueryWithClient(&http.Client{Timeout: DefaultTimeout}, out, err)
}

// NewQueryWithLogger creates a new Certificate Transparency query handler with logger
func NewQueryWithLogger(out, err io.Writer, logger *logging.Logger) (*Query, error) {
	return NewQueryWithClientAndLogger(&http.Client{Timeout: DefaultTimeout}, out, err, logger)
}

// NewQueryWithClient creates a new Certificate Transparency query handler with a custom HTTP client
func NewQueryWithClient(client *http.Client, out, err io.Writer) (*Query, error) {
	return NewQueryWithClientAndLogger(client, out, err, nil)
}

// NewQueryWithClientAndLogger creates a new Certificate Transparency query handler with client and logger
func NewQueryWithClientAndLogger(client *http.Client, out, err io.Writer, logger *logging.Logger) (*Query, error) {
	if logger == nil {
		logger = logging.New("info", "text", err)
	}

	logger.CT("Initializing Certificate Transparency client")
	if _, err := fmt.Fprintf(out, "[*] Initializing Certificate Transparency client\n"); err != nil {
		logger.Failure("Failed to write CT initialization message", "error", err)
	}

	return &Query{
		httpClient: client,
		out:        out,
		err:        err,
		logger:     logger,
	}, nil
}

// Close closes any open connections
func (ct *Query) Close() error {
	// Nothing to close in the web-based approach
	return nil
}

// QueryDomain queries Certificate Transparency logs for a domain and its subdomains
func (ct *Query) QueryDomain(domain string) ([]Entry, error) {
	// Start with the simplest possible query that we know works
	return ct.queryDomainSimple(domain)
}

// CrtShResponse represents the JSON response from crt.sh API
type CrtShResponse struct {
	IssuerCAID     int64   `json:"issuer_ca_id"`
	IssuerName     string  `json:"issuer_name"`
	CommonName     string  `json:"common_name"`
	NameValue      string  `json:"name_value"`
	ID             int64   `json:"id"`
	EntryTimestamp *string `json:"entry_timestamp"`
	NotBefore      string  `json:"not_before"`
	NotAfter       string  `json:"not_after"`
	SerialNumber   string  `json:"serial_number"`
}

// queryDomainSimple uses crt.sh's JSON API for reliable certificate discovery
func (ct *Query) queryDomainSimple(domain string) ([]Entry, error) {
	if _, err := fmt.Fprintf(ct.out, "[*] Querying Certificate Transparency logs for %s\n", domain); err != nil {
		ct.logger.Failure("Failed to write CT query message", "error", err)
	}

	// Query for exact domain and subdomains using proper domain matching
	// We'll make two queries: one for the exact domain and one for subdomains
	var allResults []CrtShResponse
	var queryErrors []error

	// Query 1: Exact domain match
	exactURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))
	exactResults, err := ct.queryCrtSh(exactURL)
	if err != nil {
		ct.logger.Warn("Failed to query exact domain", "domain", domain, "error", err)
		queryErrors = append(queryErrors, fmt.Errorf("exact domain query failed: %w", err))
	} else {
		allResults = append(allResults, exactResults...)
	}

	// Query 2: Subdomain match (*.domain.com)
	subdomainURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape("%."+domain))
	subdomainResults, err := ct.queryCrtSh(subdomainURL)
	if err != nil {
		ct.logger.Warn("Failed to query subdomains", "domain", domain, "error", err)
		queryErrors = append(queryErrors, fmt.Errorf("subdomain query failed: %w", err))
	} else {
		allResults = append(allResults, subdomainResults...)
	}

	// If both queries failed, return error
	if len(allResults) == 0 && len(queryErrors) > 0 {
		return nil, fmt.Errorf("all CT queries failed: %v", queryErrors)
	}

	// Aggregate unique certificates by identity (serial+issuer+notBefore+notAfter)
	type agg struct {
		entry Entry
		count int64
	}
	aggregates := make(map[string]*agg)

	for _, result := range allResults {
		// Parse timestamps used for identity and validity - handle parsing failures gracefully
		var notBefore, notAfter time.Time
		var parseErrors []string
		
		if t, err := time.Parse("2006-01-02T15:04:05", result.NotBefore); err == nil {
			notBefore = t
		} else {
			parseErrors = append(parseErrors, fmt.Sprintf("notBefore: %v", err))
			// Use a sentinel value for failed parsing to avoid zero-time issues
			notBefore = time.Unix(0, 0) // Unix epoch as sentinel
		}
		
		if t, err := time.Parse("2006-01-02T15:04:05", result.NotAfter); err == nil {
			notAfter = t
		} else {
			parseErrors = append(parseErrors, fmt.Sprintf("notAfter: %v", err))
			// Use a sentinel value for failed parsing
			notAfter = time.Unix(0, 0) // Unix epoch as sentinel
		}

		// Log parsing errors for debugging
		if len(parseErrors) > 0 {
			ct.logger.Debug("Timestamp parsing errors for certificate", 
				"cert_id", result.ID, 
				"serial", result.SerialNumber,
				"errors", strings.Join(parseErrors, "; "))
		}

		// Collect relevant DNS names
		var relevantNames []string
		if result.NameValue != "" {
			raw := strings.Split(result.NameValue, "\n")
			for _, name := range raw {
				name = strings.TrimSpace(name)
				if name != "" && ct.isRelevantDomain(name, domain) {
					relevantNames = append(relevantNames, name)
				}
			}
		}
		if len(relevantNames) == 0 {
			continue
		}

		// Identity key - include serial, issuer, and timestamps
		// Use Unix timestamps to handle zero-time consistently
		key := fmt.Sprintf("%s|%s|%d|%d",
			strings.ToLower(strings.TrimSpace(result.SerialNumber)),
			strings.ToLower(strings.TrimSpace(result.IssuerName)),
			notBefore.Unix(),
			notAfter.Unix(),
		)

		// Parse CT entry timestamp if present
		var entryTS *time.Time
		if result.EntryTimestamp != nil {
			if ts, err := time.Parse("2006-01-02T15:04:05", *result.EntryTimestamp); err == nil {
				entryTS = &ts
			}
		}

		if existing, ok := aggregates[key]; ok {
			// Merge DNS names efficiently using a set
			existing.entry.DNSNames = mergeDNSNames(existing.entry.DNSNames, relevantNames)
			
			// Keep latest EntryTimestamp
			if entryTS != nil {
				if existing.entry.EntryTimestamp == nil || entryTS.After(*existing.entry.EntryTimestamp) {
					existing.entry.EntryTimestamp = entryTS
				}
			}
			// Track duplicates; keep smallest ID for stability
			existing.count++
			if result.ID < existing.entry.ID {
				existing.entry.ID = result.ID
			}
			continue
		}

		// New aggregate
		aggregates[key] = &agg{
			entry: Entry{
				ID:             result.ID,
				SerialNumber:   strings.TrimSpace(result.SerialNumber),
				NotBefore:      notBefore,
				NotAfter:       notAfter,
				CommonName:     strings.TrimSpace(result.CommonName),
				DNSNames:       append([]string(nil), relevantNames...),
				Issuer:         strings.TrimSpace(result.IssuerName),
				EntryTimestamp: entryTS,
			},
			count: 1,
		}
	}

	// Build final unique entries, compute validity, and set ResultCount
	var entries []Entry
	now := time.Now()
	for _, ag := range aggregates {
		e := ag.entry
		// Handle zero-time sentinel values - treat as invalid
		if e.NotBefore.Unix() == 0 || e.NotAfter.Unix() == 0 {
			e.IsValid = false
		} else {
			e.IsValid = now.After(e.NotBefore) && now.Before(e.NotAfter)
		}
		e.ResultCount = ag.count
		entries = append(entries, e)
	}

	// Sort entries for deterministic output (by ID for consistency)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})

	return entries, nil
}

// mergeDNSNames efficiently merges two DNS name slices, removing duplicates
func mergeDNSNames(existing, new []string) []string {
	if len(new) == 0 {
		return existing
	}
	if len(existing) == 0 {
		return append([]string(nil), new...)
	}

	// Use map for efficient deduplication
	seen := make(map[string]bool, len(existing)+len(new))
	result := make([]string, 0, len(existing)+len(new))

	// Add existing names
	for _, name := range existing {
		if !seen[name] {
			seen[name] = true
			result = append(result, name)
		}
	}

	// Add new names
	for _, name := range new {
		if !seen[name] {
			seen[name] = true
			result = append(result, name)
		}
	}

	return result
}

// queryCrtSh makes a request to the crt.sh API and returns the results
func (ct *Query) queryCrtSh(apiURL string) ([]CrtShResponse, error) {
	resp, err := ct.httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query crt.sh API: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			ct.logger.Failure("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle empty responses gracefully
	if len(body) == 0 {
		return []CrtShResponse{}, nil
	}

	var results []CrtShResponse
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return results, nil
}

// isRelevantDomain checks if a domain name is actually a subdomain of the target domain
func (ct *Query) isRelevantDomain(name, targetDomain string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	targetDomain = strings.ToLower(strings.TrimSpace(targetDomain))

	// Skip invalid domain names
	if !isValidDomainName(name) {
		return false
	}

	// Exact match
	if name == targetDomain {
		return true
	}

	// Wildcard match (*.example.com)
	if name == "*."+targetDomain {
		return true
	}

	// Subdomain match (must end with .targetDomain)
	if strings.HasSuffix(name, "."+targetDomain) {
		// Make sure it's a proper subdomain, not just a string that ends with the domain
		// e.g., "notexample.com" should not match "example.com"
		prefix := strings.TrimSuffix(name, "."+targetDomain)
		// The prefix should be a valid subdomain part (no dots at the end, not empty)
		if prefix != "" && !strings.HasSuffix(prefix, ".") && isValidSubdomainPrefix(prefix) {
			return true
		}
	}

	return false
}

// isValidSubdomainPrefix checks if a string is a valid subdomain prefix
func isValidSubdomainPrefix(prefix string) bool {
	// Should not be empty
	if prefix == "" {
		return false
	}

	// Should not contain spaces or special characters except hyphens and dots for multi-level subdomains
	validPrefixPattern := regexp.MustCompile(`^[a-zA-Z0-9*]([a-zA-Z0-9\-\.]*[a-zA-Z0-9*])?$`)
	return validPrefixPattern.MatchString(prefix)
}

// isValidDomainName checks if a string is a valid domain name
func isValidDomainName(name string) bool {
	// Remove leading/trailing whitespace
	name = strings.TrimSpace(name)

	// Skip empty strings
	if name == "" {
		return false
	}

	// Skip email addresses (contains @)
	if strings.Contains(name, "@") {
		return false
	}

	// Skip strings with spaces (likely certificate names or descriptions)
	if strings.Contains(name, " ") {
		return false
	}

	// Skip strings that are too long (domain names have practical limits)
	if len(name) > 253 {
		return false
	}

	// Skip strings that don't contain a dot (except for single-word domains, but those are rare in certs)
	if !strings.Contains(name, ".") {
		return false
	}

	// Basic domain name pattern: letters, numbers, dots, hyphens, and wildcards
	validDomainPattern := regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$`)

	return validDomainPattern.MatchString(name)
}

// DisplayResults displays Certificate Transparency query results
func (ct *Query) DisplayResults(domain string, entries []Entry, showExpired bool, dnsFile *os.File) {
	// Collect unique DNS names for export
	uniqueDNSNames := make(map[string]bool)

	// Group by validity status
	validCerts := 0
	expiredCerts := 0
	var validEntries []Entry

	for _, entry := range entries {
		// Collect valid DNS names for export
		for _, dnsName := range entry.DNSNames {
			if isValidDomainName(dnsName) {
				uniqueDNSNames[dnsName] = true
			}
		}

		if entry.IsValid {
			validCerts++
			validEntries = append(validEntries, entry)
		} else {
			expiredCerts++
		}
	}

	// Export DNS names if requested
	if dnsFile != nil {
		// Sort DNS names for consistent output
		var sortedNames []string
		for dnsName := range uniqueDNSNames {
			sortedNames = append(sortedNames, dnsName)
		}
		sort.Strings(sortedNames)

		for _, dnsName := range sortedNames {
			if _, err := fmt.Fprintf(dnsFile, "%s\n", dnsName); err != nil {
				ct.logger.Failure("Failed to write DNS name to export file", "dns_name", dnsName, "error", err)
			}
		}
		if _, err := fmt.Fprintf(ct.out, "[*] Exported %d unique DNS names to file\n", len(uniqueDNSNames)); err != nil {
			ct.logger.Failure("Failed to write DNS export message", "error", err)
		}
	}

	if _, err := fmt.Fprintf(ct.out, "\n[*] Certificate Transparency Report for: %s\n", domain); err != nil {
		ct.logger.Failure("Failed to write CT report header", "error", err)
	}
	if _, err := fmt.Fprintf(ct.out, "[*] Found %d certificates (%d valid, %d expired)\n", len(entries), validCerts, expiredCerts); err != nil {
		ct.logger.Failure("Failed to write certificate count", "error", err)
	}

	// Determine which certificates to display
	var displayEntries []Entry
	if showExpired {
		displayEntries = entries
		if _, err := fmt.Fprintf(ct.out, "[*] Showing all certificates (including expired)\n\n"); err != nil {
			ct.logger.Failure("Failed to write certificate display message", "error", err)
		}
	} else {
		displayEntries = validEntries
		if expiredCerts > 0 {
			if _, err := fmt.Fprintf(ct.out, "[*] Showing only valid certificates (use -ct-show-expired to see all)\n\n"); err != nil {
				ct.logger.Failure("Failed to write certificate filter message", "error", err)
			}
		} else {
			if _, err := fmt.Fprintf(ct.out, "\n"); err != nil {
				ct.logger.Failure("Failed to write newline", "error", err)
			}
		}
	}

	if len(displayEntries) == 0 {
		if showExpired {
			if _, err := fmt.Fprintf(ct.out, "[-] No certificates found for domain %s\n", domain); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
		} else {
			if _, err := fmt.Fprintf(ct.out, "[-] No valid certificates found for domain %s\n", domain); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
			if expiredCerts > 0 {
				if _, err := fmt.Fprintf(ct.out, "[*] %d expired certificates available (use -ct-show-expired to view)\n", expiredCerts); err != nil {
					ct.logger.Warn("Failed to write output", "error", err)
				}
			}
		}
		return
	}

	// Display certificates
	for i, entry := range displayEntries {
		status := "EXPIRED"
		statusSymbol := "[-]"
		if entry.IsValid {
			status = "VALID"
			statusSymbol = "[+]"
		}

		if _, err := fmt.Fprintf(ct.out, "%s Certificate #%d (%s)\n", statusSymbol, i+1, status); err != nil {
			ct.logger.Warn("Failed to write output", "error", err)
		}
		if _, err := fmt.Fprintf(ct.out, "    Certificate ID: %d\n", entry.ID); err != nil {
			ct.logger.Warn("Failed to write output", "error", err)
		}
		if _, err := fmt.Fprintf(ct.out, "    Serial Number:  %s\n", entry.SerialNumber); err != nil {
			ct.logger.Warn("Failed to write output", "error", err)
		}
		if _, err := fmt.Fprintf(ct.out, "    Common Name:    %s\n", entry.CommonName); err != nil {
			ct.logger.Warn("Failed to write output", "error", err)
		}

		if len(entry.DNSNames) > 0 {
			if _, err := fmt.Fprintf(ct.out, "    DNS Names:      %s\n", strings.Join(entry.DNSNames, ", ")); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
		}

		if _, err := fmt.Fprintf(ct.out, "    Issuer:         %s\n", entry.Issuer); err != nil {
			ct.logger.Warn("Failed to write output", "error", err)
		}

		// Handle zero-time display gracefully
		if entry.NotBefore.Unix() == 0 {
			if _, err := fmt.Fprintf(ct.out, "    Valid From:     [Parse Error]\n"); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
		} else {
			if _, err := fmt.Fprintf(ct.out, "    Valid From:     %s\n", entry.NotBefore.Format("2006-01-02 15:04:05 UTC")); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
		}

		if entry.NotAfter.Unix() == 0 {
			if _, err := fmt.Fprintf(ct.out, "    Valid Until:    [Parse Error]\n"); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
		} else {
			if _, err := fmt.Fprintf(ct.out, "    Valid Until:    %s\n", entry.NotAfter.Format("2006-01-02 15:04:05 UTC")); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
		}

		if entry.EntryTimestamp != nil {
			if _, err := fmt.Fprintf(ct.out, "    CT Log Entry:   %s\n", entry.EntryTimestamp.Format("2006-01-02 15:04:05 UTC")); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
		}

		if entry.ResultCount > 1 {
			if _, err := fmt.Fprintf(ct.out, "    Duplicate Count: %d\n", entry.ResultCount); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
		}

		if entry.IsValid && entry.NotAfter.Unix() != 0 {
			daysLeft := int(time.Until(entry.NotAfter).Hours() / 24)
			if _, err := fmt.Fprintf(ct.out, "    Days Left:      %d\n", daysLeft); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
		} else if !entry.IsValid && entry.NotAfter.Unix() != 0 {
			daysExpired := int(time.Since(entry.NotAfter).Hours() / 24)
			if _, err := fmt.Fprintf(ct.out, "    Days Expired:   %d\n", daysExpired); err != nil {
				ct.logger.Warn("Failed to write output", "error", err)
			}
		}

		if _, err := fmt.Fprintf(ct.out, "\n"); err != nil {
			ct.logger.Warn("Failed to write output", "error", err)
		}
	}
}

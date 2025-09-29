package shared

import (
	"strings"
	"testing"
)

// TestIsValidHostPort verifies host:port validation for various formats
func TestIsValidHostPort(t *testing.T) {
	testCases := []struct {
		name     string
		hostPort string
		want     bool
	}{
		// Valid cases
		{"valid_domain_https", "example.com:443", true},
		{"valid_domain_smtp", "localhost:25", true},
		{"valid_ipv4", "127.0.0.1:8080", true},
		{"valid_ipv6", "[::1]:443", true},
		{"valid_ipv6_full", "[2001:db8::1]:443", true},

		// Invalid cases
		{"invalid_port_name", "example.com:port", false},
		{"missing_host", ":443", false},
		{"missing_port", "example.com:", false},
		{"missing_port_colon", "example.com", false},
		{"empty_string", "", false},
		{"only_colon", ":", false},
		{"port_too_high", "example.com:99999", true}, // net.SplitHostPort allows this
		{"port_zero", "example.com:0", true},         // net.SplitHostPort allows this
		{"negative_port", "example.com:-1", true},    // strconv.Atoi accepts negative numbers
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValidHostPort(tc.hostPort)
			if got != tc.want {
				t.Errorf("IsValidHostPort(%q) = %v; want %v", tc.hostPort, got, tc.want)
			}
		})
	}
}

// TestIsValidHostPort_Hardening verifies security-focused hostname validation
func TestIsValidHostPort_Hardening(t *testing.T) {
	testCases := []struct {
		name     string
		hostPort string
		want     bool
	}{
		// Invalid characters in hostname
		{"space_in_host", "bad host:443", false},
		{"tab_in_host", "bad\thost:443", false},
		{"carriage_return", "bad\rhost:443", false},
		{"line_feed", "bad\nhost:443", false},
		{"slash_in_host", "bad/host:443", false},

		// Invalid DNS label formats
		{"label_starts_hyphen", "-bad.example:443", false},
		{"label_ends_hyphen", "bad-.example:443", false},
		{"label_too_long", strings.Repeat("a", 64) + ".example:443", false},
		{"hostname_too_long", strings.Repeat("a", 254) + ":443", false},

		// Valid edge cases
		{"ipv6_literal", "[::1]:443", true},
		{"max_valid_port", "example.com:65535", true},
		{"single_char_host", "a:443", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValidHostPort(tc.hostPort)
			if got != tc.want {
				t.Errorf("IsValidHostPort(%q) = %v; want %v", tc.hostPort, got, tc.want)
			}
		})
	}
}

func TestGuessProtocol(t *testing.T) {
	cases := []struct {
		port string
		want string
	}{
		// STARTTLS email ports
		{"25", "smtp"},
		{"587", "smtp"},
		{"143", "imap"},
		{"110", "pop3"},
		// Direct TLS email ports (secure variants)
		{"465", "none"},
		{"993", "none"},
		{"995", "none"},
		// HTTP/HTTPS ports
		{"443", "http"},
		{"8080", "http"},
		{"8443", "http"},
		// Unknown ports
		{"", "none"},
		{"0", "none"},
		{"invalid", "none"},
	}
	for _, c := range cases {
		if got := GuessProtocol(c.port); got != c.want {
			t.Errorf("GuessProtocol(%q)=%q; want %q", c.port, got, c.want)
		}
	}
}

func TestParseTargets_FileReader(t *testing.T) {
	// Test case 1: Invalid host:port format
	in := `
# comment
host1:25 smtp
host2:143 imap
bad:port smtp
host3:110 pop3
`
	_, err := ParseTargets(strings.NewReader(in), "")
	if err == nil {
		t.Fatalf("ParseTargets expected error on invalid host:port")
	}

	// Test case 2: Default protocol applied
	in2 := `
host1:25 smtp
host2:143
`
	ts, err := ParseTargets(strings.NewReader(in2), "pop3")
	if err != nil {
		t.Fatalf("ParseTargets error: %v", err)
	}
	if len(ts) != 2 || ts[1].Protocol != "pop3" {
		t.Fatalf("unexpected parse result: %+v", ts)
	}

	// Test case 3: Empty input
	ts, err = ParseTargets(strings.NewReader(""), "http")
	if err != nil {
		t.Fatalf("ParseTargets error on empty input: %v", err)
	}
	if len(ts) != 0 {
		t.Fatalf("expected empty result for empty input, got: %+v", ts)
	}

	// Test case 4: Comments and whitespace handling
	in3 := `
# This is a comment
   # Indented comment
host1:443 http
   host2:25   smtp   
# Another comment
host3:110
`
	ts, err = ParseTargets(strings.NewReader(in3), "http")
	if err != nil {
		t.Fatalf("ParseTargets error: %v", err)
	}
	if len(ts) != 3 {
		t.Fatalf("expected 3 targets, got %d: %+v", len(ts), ts)
	}
	if ts[0].HostPort != "host1:443" || ts[0].Protocol != "http" {
		t.Errorf("unexpected first target: %+v", ts[0])
	}
	if ts[1].HostPort != "host2:25" || ts[1].Protocol != "smtp" {
		t.Errorf("unexpected second target: %+v", ts[1])
	}
	if ts[2].HostPort != "host3:110" || ts[2].Protocol != "http" {
		t.Errorf("unexpected third target: %+v", ts[2])
	}
}

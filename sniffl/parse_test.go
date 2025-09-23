package sniffl

import (
	"strings"
	"testing"
)

func TestIsValidHostPort(t *testing.T) {
	cases := []struct {
		hp   string
		want bool
	}{
		{"example.com:443", true},
		{"localhost:25", true},
		{"127.0.0.1:8080", true},
		{"[::1]:443", true},
		{"example.com:port", false},
		{":443", false},
		{"example.com:", false},
		{"example.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isValidHostPort(c.hp); got != c.want {
			t.Errorf("isValidHostPort(%q)=%v; want %v", c.hp, got, c.want)
		}
	}
}

func TestGuessProtocol(t *testing.T) {
	cases := []struct {
		port string
		want string
	}{
		{"25", "smtp"},
		{"587", "smtp"},
		{"465", "smtp"},
		{"143", "imap"},
		{"993", "imap"},
		{"110", "pop3"},
		{"995", "pop3"},
		{"443", "http"},
		{"8080", "http"},
		{"8443", "none"},
		{"", "none"},
		{"0", "none"},
		{"invalid", "none"},
	}
	for _, c := range cases {
		if got := guessProtocol(c.port); got != c.want {
			t.Errorf("guessProtocol(%q)=%q; want %q", c.port, got, c.want)
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

package check

import (
	"crypto/x509"
	"testing"
)

func TestConcurrentState_AddGetCertificatesAndDNSNames(t *testing.T) {
	cs := NewConcurrentState()

	// Create dummy certs
	cert1 := &x509.Certificate{Raw: []byte{0x1}, DNSNames: []string{"example.com"}}
	cert2 := &x509.Certificate{Raw: []byte{0x2}, DNSNames: []string{"api.example.com"}}

	cs.AddCertificates([]*x509.Certificate{cert1})
	cs.AddCertificates([]*x509.Certificate{cert2})

	all := cs.GetAllCertificates()
	if len(all) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(all))
	}

	// Add DNS names via AddDNSName and AddDNSNames
	cs.AddDNSName("") // should be ignored
	cs.AddDNSName("explicit.example")
	cs.AddDNSNames([]*x509.Certificate{cert1, cert2})

	names := cs.GetDNSNames()
	// We expect at least the two DNSNames from certs plus explicit one
	if len(names) < 3 {
		t.Fatalf("expected >=3 dns names, got %d: %v", len(names), names)
	}

	// ensure that containsDot/containsSpaces/isIPAddress helpers behave as expected
	if !isDNSName("example.com") {
		t.Error("example.com should be recognized as DNS name")
	}
	if isDNSName("localhost") {
		t.Error("localhost should not be considered a DNS name in this context")
	}
	if containsSpaces("a b") == false {
		t.Error("containsSpaces should detect spaces")
	}
}

func TestIsIPAddressVariants(t *testing.T) {
	cases := []struct {
		s  string
		ok bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"example.com", false},
		{"", false},
		{"256.256.256.256", false},
	}

	for _, c := range cases {
		got := isIPAddress(c.s)
		if got != c.ok {
			t.Fatalf("isIPAddress(%q) = %v, want %v", c.s, got, c.ok)
		}
	}
}

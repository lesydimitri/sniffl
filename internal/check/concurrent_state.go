package check

import (
	"crypto/x509"
	"net"
	"sync"
)

// ConcurrentState manages shared state safely across goroutines
type ConcurrentState struct {
	allCerts   []*x509.Certificate
	certsMu    sync.RWMutex
	dnsNames   map[string]struct{}
	dnsNamesMu sync.RWMutex
}

// NewConcurrentState creates a new thread-safe state manager
func NewConcurrentState() *ConcurrentState {
	return &ConcurrentState{
		allCerts: make([]*x509.Certificate, 0),
		dnsNames: make(map[string]struct{}),
	}
}

func (cs *ConcurrentState) AddCertificates(certs []*x509.Certificate) {
	cs.certsMu.Lock()
	defer cs.certsMu.Unlock()
	cs.allCerts = append(cs.allCerts, certs...)
}

func (cs *ConcurrentState) GetAllCertificates() []*x509.Certificate {
	cs.certsMu.RLock()
	defer cs.certsMu.RUnlock()
	result := make([]*x509.Certificate, len(cs.allCerts))
	copy(result, cs.allCerts)
	return result
}

func (cs *ConcurrentState) AddDNSName(name string) {
	if name == "" {
		return
	}
	cs.dnsNamesMu.Lock()
	defer cs.dnsNamesMu.Unlock()
	cs.dnsNames[name] = struct{}{}
}

func (cs *ConcurrentState) AddDNSNames(certs []*x509.Certificate) {
	cs.dnsNamesMu.Lock()
	defer cs.dnsNamesMu.Unlock()
	
	for _, cert := range certs {
		if cn := cert.Subject.CommonName; cn != "" && isDNSName(cn) {
			cs.dnsNames[cn] = struct{}{}
		}
		for _, san := range cert.DNSNames {
			if san != "" {
				cs.dnsNames[san] = struct{}{}
			}
		}
	}
}

func (cs *ConcurrentState) GetDNSNames() []string {
	cs.dnsNamesMu.RLock()
	defer cs.dnsNamesMu.RUnlock()
	names := make([]string, 0, len(cs.dnsNames))
	for name := range cs.dnsNames {
		names = append(names, name)
	}
	return names
}


func isDNSName(name string) bool {
	return len(name) > 0 && name != "localhost" && 
		   !containsSpaces(name) && (containsDot(name) || isIPAddress(name))
}

func containsSpaces(s string) bool {
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return true
		}
	}
	return false
}

func containsDot(s string) bool {
	for _, r := range s {
		if r == '.' {
			return true
		}
	}
	return false
}

func isIPAddress(s string) bool {
	// Use Go's built-in IP parsing which handles both IPv4 and IPv6
	return net.ParseIP(s) != nil
}

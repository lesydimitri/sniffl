package shared

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Constants for hostname validation
const (
	// MaxHostnameLength is the maximum allowed length for a hostname (RFC 1035)
	MaxHostnameLength = 253
	// MaxLabelLength is the maximum allowed length for a DNS label (RFC 1035)
	MaxLabelLength = 63
)

// Protocol port mappings for auto-detection
const (
	// STARTTLS email ports
	PortSMTP       = "25"
	PortSubmission = "587"
	PortIMAP       = "143"
	PortPOP3       = "110"
	// Direct TLS email ports (secure variants)
	PortSMTPS = "465"
	PortIMAPS = "993"
	PortPOP3S = "995"
	// HTTP/HTTPS ports
	PortHTTPS     = "443"
	PortHTTPAlt   = "8080"
	PortHTTPSAlt  = "8443"
)

// Target describes a destination as host:port with an optional protocol hint.
type Target struct {
	HostPort string
	Protocol string
}

// ParseTargets reads targets from r, one per line, in the form "host:port [protocol]".
// Lines starting with '#' and blank lines are ignored.
func ParseTargets(r io.Reader, defaultProtocol string) ([]Target, error) {
	var targets []Target
	sc := bufio.NewScanner(r)
	for lineNum := 1; sc.Scan(); lineNum++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		hp := fields[0]
		if !IsValidHostPort(hp) {
			return nil, fmt.Errorf("invalid host:port on line %d: %s", lineNum, line)
		}
		proto := defaultProtocol
		if len(fields) > 1 {
			p := strings.ToLower(fields[1])
			if !SupportedProtocols[p] {
				return nil, fmt.Errorf("invalid protocol on line %d: %s", lineNum, line)
			}
			proto = p
		}
		targets = append(targets, Target{HostPort: hp, Protocol: proto})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

// IsValidHostPort validates a host:port string
func IsValidHostPort(hp string) bool {
	h, p, err := net.SplitHostPort(hp)
	if err != nil || h == "" || p == "" {
		return false
	}
	if _, err := strconv.Atoi(p); err != nil {
		return false
	}
	return IsValidHostname(h)
}

// IsValidHostname validates that the host is either a valid IP address (v4/v6)
// or a reasonable DNS hostname. It rejects control characters, whitespace,
// slashes, and empty/oversized labels.
func IsValidHostname(h string) bool {
	// Accept IP literals (SplitHostPort removes IPv6 brackets).
	if ip := net.ParseIP(h); ip != nil {
		return true
	}
	// Reject obvious bad characters to prevent HTTP header/control injection.
	if strings.ContainsAny(h, " \t\r\n/\\") {
		return false
	}
	if len(h) == 0 || len(h) > MaxHostnameLength {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > MaxLabelLength {
			return false
		}
		// Labels must be alphanumeric or hyphen, not start/end with hyphen.
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// GuessProtocol determines the protocol based on port number
func GuessProtocol(port string) string {
	switch port {
	// STARTTLS email ports
	case PortSMTP, PortSubmission:
		return "smtp"
	case PortIMAP:
		return "imap"
	case PortPOP3:
		return "pop3"
	// Direct TLS email ports (secure variants)
	case PortSMTPS, PortIMAPS, PortPOP3S:
		return "none"
	// HTTP/HTTPS ports
	case PortHTTPS, PortHTTPAlt, PortHTTPSAlt:
		return "http"
	default:
		return "none"
	}
}

// SupportedProtocols maps protocol names to their validity
var SupportedProtocols = map[string]bool{
	"smtp": true, "imap": true, "pop3": true, "http": true, "none": true,
}

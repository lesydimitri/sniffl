// sniffl/parse.go
package sniffl

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

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
		if !isValidHostPort(hp) {
			return nil, fmt.Errorf("invalid host:port on line %d: %s", lineNum, line)
		}
		proto := defaultProtocol
		if len(fields) > 1 {
			p := strings.ToLower(fields[1])
			if !supportedProtocols[p] {
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

func isValidHostPort(hp string) bool {
	h, p, err := net.SplitHostPort(hp)
	if err != nil || h == "" || p == "" {
		return false
	}
	if _, err := strconv.Atoi(p); err != nil {
		return false
	}
	return true
}

func guessProtocol(port string) string {
	switch port {
	case "25", "587", "465":
		return "smtp"
	case "143", "993":
		return "imap"
	case "110", "995":
		return "pop3"
	case "443", "8080":
		return "http"
	default:
		return "none"
	}
}

// sniffl/net_tls.go
package sniffl

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

func (a *App) fetchCertsByProtocol(ctx context.Context, protocol, host, port, hostPort string) ([]*x509.Certificate, error) {
	switch protocol {
	case "none":
		return a.fetchTLS(ctx, host, port)
	case "smtp":
		return a.fetchTLSOverProtocol(ctx, host, port, smtpInit(host))
	case "imap":
		return a.fetchTLSOverProtocol(ctx, host, port, imapInit())
	case "pop3":
		return a.fetchTLSOverProtocol(ctx, host, port, pop3Init())
	case "http":
		return a.fetchTLSOverHTTP(ctx, host, port)
	default:
		return nil, fmt.Errorf("unsupported protocol %q for host %s", protocol, hostPort)
	}
}

func (a *App) fetchTLS(ctx context.Context, host, port string) ([]*x509.Certificate, error) {
	c, err := a.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("TLS dial error for %s:%s: %w", host, port, err)
	}
	tconn := a.tlsFactory.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tconn.HandshakeContext(ctx); err != nil {
		tconn.Close()
		return nil, fmt.Errorf("TLS handshake error: %w", err)
	}
	defer tconn.Close()
	return tconn.ConnectionState().PeerCertificates, nil
}

type initFunc func(*bufio.Writer, *bufio.Reader) error

func (a *App) fetchTLSOverProtocol(ctx context.Context, host, port string, init initFunc) ([]*x509.Certificate, error) {
	conn, err := a.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("TCP dial error for %s:%s: %w", host, port, err)
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	if err := init(writer, reader); err != nil {
		conn.Close()
		return nil, fmt.Errorf("STARTTLS/init error: %w", err)
	}
	tconn := a.tlsFactory.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tconn.HandshakeContext(ctx); err != nil {
		tconn.Close()
		return nil, fmt.Errorf("TLS handshake error: %w", err)
	}
	defer tconn.Close()
	return tconn.ConnectionState().PeerCertificates, nil
}

func (a *App) fetchTLSOverHTTP(ctx context.Context, host, port string) ([]*x509.Certificate, error) {
	addr := net.JoinHostPort(host, port)
	// If proxy is configured, re-use the existing manual CONNECT flow, but over injected dialer.
	var conn net.Conn
	var err error
	if a.cfg.HTTPSProxy != nil {
		conn, err = a.dialer.DialContext(ctx, "tcp", a.cfg.HTTPSProxy.Host)
		if err != nil {
			return nil, fmt.Errorf("cannot connect to proxy: %v", err)
		}
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
		if a.cfg.HTTPSProxy.User != nil {
			user := a.cfg.HTTPSProxy.User.Username()
			pass, _ := a.cfg.HTTPSProxy.User.Password()
			b64 := basicAuth(user, pass)
			connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", b64)
		}
		connectReq += "\r\n"
		if _, err := conn.Write([]byte(connectReq)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy write failed: %v", err)
		}
		br := bufio.NewReader(conn)
		statusLine, err := br.ReadString('\n')
		if err != nil || !strings.Contains(statusLine, "200") {
			conn.Close()
			return nil, fmt.Errorf("proxy connect failed: %s", strings.TrimSpace(statusLine))
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("proxy header read error: %v", err)
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
	} else {
		conn, err = a.dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("cannot connect directly to %s: %v", addr, err)
		}
	}
	tconn := a.tlsFactory.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tconn.HandshakeContext(ctx); err != nil {
		tconn.Close()
		return nil, fmt.Errorf("TLS handshake error: %v", err)
	}
	defer tconn.Close()
	return tconn.ConnectionState().PeerCertificates, nil
}

func basicAuth(user, pass string) string { return base64Encode(user + ":" + pass) }

// small seam for tests
var base64Encode = func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Protocol inits
func smtpInit(ehlo string) initFunc {
	return func(w *bufio.Writer, r *bufio.Reader) error {
		if _, err := r.ReadString('\n'); err != nil {
			return fmt.Errorf("error reading SMTP greeting: %w", err)
		}
		fmt.Fprintf(w, "EHLO %s\r\n", ehlo)
		w.Flush()
		starttls := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return fmt.Errorf("error reading SMTP EHLO response: %w", err)
			}
			if strings.Contains(line, "STARTTLS") {
				starttls = true
			}
			if strings.HasPrefix(line, "250 ") {
				break
			}
		}
		if !starttls {
			return fmt.Errorf("STARTTLS not supported")
		}
		fmt.Fprint(w, "STARTTLS\r\n")
		w.Flush()
		resp, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(resp, "220") {
			return fmt.Errorf("STARTTLS failed: %s", strings.TrimSpace(resp))
		}
		return nil
	}
}

func imapInit() initFunc {
	return func(w *bufio.Writer, r *bufio.Reader) error {
		if _, err := r.ReadString('\n'); err != nil {
			return fmt.Errorf("error reading IMAP greeting: %w", err)
		}
		fmt.Fprint(w, "A001 STARTTLS\r\n")
		w.Flush()
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return fmt.Errorf("error reading IMAP STARTTLS response: %w", err)
			}
			ul := strings.ToUpper(line)
			if strings.HasPrefix(ul, "A001 ") {
				if strings.Contains(ul, "OK") {
					return nil
				}
				return fmt.Errorf("STARTTLS rejected: %s", strings.TrimSpace(line))
			}
		}
	}
}

func pop3Init() initFunc {
	return func(w *bufio.Writer, r *bufio.Reader) error {
		if _, err := r.ReadString('\n'); err != nil {
			return fmt.Errorf("error reading POP3 greeting: %w", err)
		}
		fmt.Fprint(w, "STLS\r\n")
		w.Flush()
		resp, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading POP3 STLS response: %w", err)
		}
		if !strings.HasPrefix(resp, "+OK") {
			return fmt.Errorf("STLS failed: %s", strings.TrimSpace(resp))
		}
		return nil
	}
}

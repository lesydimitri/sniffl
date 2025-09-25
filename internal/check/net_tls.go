package check

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Constants for network operations
const (
	// Default ports for proxy connections
	DefaultHTTPPort  = "80"
	DefaultHTTPSPort = "443"
	// HTTP status codes
	HTTPStatusOK = "200"
	// SMTP status codes
	SMTPStatusReady = "220"
	SMTPStatusOK    = "250"
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
	addr := net.JoinHostPort(host, port)
	a.logger.Network("Establishing TCP connection", "address", addr)

	c, err := a.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		a.logger.Network("TCP connection failed", "address", addr, "error", err)
		return nil, fmt.Errorf("failed to establish TCP connection to %s: %w", addr, err)
	}

	a.logger.TLS("Starting TLS handshake", "server_name", host)
	tconn := a.tlsFactory.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tconn.HandshakeContext(ctx); err != nil {
		a.logger.TLS("TLS handshake failed", "server_name", host, "error", err)
		if closeErr := tconn.Close(); closeErr != nil {
			a.logger.TLS("Warning: failed to close TLS connection", "error", closeErr)
		}
		return nil, fmt.Errorf("TLS handshake failed for %s: %w", addr, err)
	}
	defer func() {
		if err := tconn.Close(); err != nil {
			a.logger.TLS("Warning: failed to close TLS connection", "error", err)
		}
	}()

	certs := tconn.ConnectionState().PeerCertificates
	a.logger.TLS("TLS handshake successful", "server_name", host, "certificates", len(certs))
	return certs, nil
}

type initFunc func(*bufio.Writer, *bufio.Reader) error

func (a *App) fetchTLSOverProtocol(ctx context.Context, host, port string, init initFunc) ([]*x509.Certificate, error) {
	addr := net.JoinHostPort(host, port)
	a.logger.Network("Establishing TCP connection for STARTTLS", "address", addr)

	conn, err := a.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to establish TCP connection to %s: %w", addr, err)
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	if err := init(writer, reader); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			a.logger.Network("Warning: failed to close connection", "error", closeErr)
		}
		return nil, fmt.Errorf("STARTTLS negotiation failed for %s: %w", addr, err)
	}
	tconn := a.tlsFactory.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tconn.HandshakeContext(ctx); err != nil {
		if closeErr := tconn.Close(); closeErr != nil {
			a.logger.TLS("Warning: failed to close TLS connection", "error", closeErr)
		}
		return nil, fmt.Errorf("TLS handshake failed for %s after STARTTLS: %w", addr, err)
	}
	defer func() {
		if err := tconn.Close(); err != nil {
			a.logger.TLS("Warning: failed to close TLS connection", "error", err)
		}
	}()
	return tconn.ConnectionState().PeerCertificates, nil
}

func (a *App) fetchTLSOverHTTP(ctx context.Context, host, port string) ([]*x509.Certificate, error) {
	conn, err := a.establishHTTPConnection(ctx, host, port)
	if err != nil {
		return nil, err
	}
	return a.performTLSHandshake(ctx, conn, host)
}

// establishHTTPConnection creates a connection to the target, either directly or via proxy
func (a *App) establishHTTPConnection(ctx context.Context, host, port string) (net.Conn, error) {
	addr := net.JoinHostPort(host, port)

	if a.cfg.HTTPSProxy != nil {
		return a.connectViaProxy(ctx, addr)
	}

	conn, err := a.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect directly to %s: %w", addr, err)
	}
	return conn, nil
}

// connectViaProxy establishes a connection through an HTTP/HTTPS proxy
func (a *App) connectViaProxy(ctx context.Context, targetAddr string) (net.Conn, error) {
	proxyHostPort, err := a.resolveProxyAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy address: %w", err)
	}

	// Connect to proxy
	conn, err := a.dialer.DialContext(ctx, "tcp", proxyHostPort)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxyHostPort, err)
	}

	// Wrap in TLS if HTTPS proxy
	if strings.EqualFold(a.cfg.HTTPSProxy.Scheme, "https") {
		conn, err = a.wrapProxyConnectionInTLS(ctx, conn)
		if err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				a.logger.Network("Warning: failed to close proxy connection", "error", closeErr)
			}
			return nil, fmt.Errorf("failed to establish TLS connection to HTTPS proxy: %w", err)
		}
	}

	// Send CONNECT request
	if err := a.sendCONNECTRequest(conn, targetAddr); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			a.logger.Network("Warning: failed to close connection", "error", closeErr)
		}
		return nil, fmt.Errorf("CONNECT request failed for target %s: %w", targetAddr, err)
	}

	return conn, nil
}

// resolveProxyAddress determines the proxy address with default ports
func (a *App) resolveProxyAddress() (string, error) {
	proxyHostPort := a.cfg.HTTPSProxy.Host
	proxyScheme := a.cfg.HTTPSProxy.Scheme

	// If no port provided, choose default based on scheme
	if _, _, err := net.SplitHostPort(proxyHostPort); err != nil {
		defaultPort := DefaultHTTPPort
		if proxyScheme == "https" {
			defaultPort = DefaultHTTPSPort
		}
		proxyHostPort = net.JoinHostPort(proxyHostPort, defaultPort)
	}

	return proxyHostPort, nil
}

// wrapProxyConnectionInTLS wraps the proxy connection in TLS for HTTPS proxies
func (a *App) wrapProxyConnectionInTLS(ctx context.Context, conn net.Conn) (net.Conn, error) {
	// Extract SNI server name (strip port if present)
	sni := a.cfg.HTTPSProxy.Host
	if h, _, err := net.SplitHostPort(sni); err == nil {
		sni = h
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake to HTTPS proxy %s failed: %w", sni, err)
	}

	return tlsConn, nil
}

// sendCONNECTRequest sends an HTTP CONNECT request to the proxy
func (a *App) sendCONNECTRequest(conn net.Conn, targetAddr string) error {
	// Build CONNECT request
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\n", targetAddr)
	fmt.Fprintf(&b, "Host: %s\r\n", targetAddr)

	// Add proxy authentication if configured
	if a.cfg.HTTPSProxy.User != nil {
		user := a.cfg.HTTPSProxy.User.Username()
		pass, _ := a.cfg.HTTPSProxy.User.Password()
		b64 := basicAuth(user, pass)
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", b64)
	}
	b.WriteString("\r\n")

	// Send request
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return fmt.Errorf("failed to write CONNECT request: %w", err)
	}

	// Read and validate response
	return a.validateCONNECTResponse(conn)
}

// validateCONNECTResponse reads and validates the proxy's CONNECT response
func (a *App) validateCONNECTResponse(conn net.Conn) error {
	br := bufio.NewReader(conn)

	// Read status line
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read CONNECT response status: %w", err)
	}

	// Parse HTTP status line: HTTP/1.1 200 Connection Established
	line := strings.TrimSpace(statusLine)
	parts := strings.Fields(line)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return fmt.Errorf("invalid proxy CONNECT status line: %s", line)
	}
	code, convErr := strconv.Atoi(parts[1])
	if convErr != nil || code != 200 {
		return fmt.Errorf("proxy CONNECT failed with status: %s", line)
	}

	// Read headers until empty line
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read CONNECT response headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	return nil
}

// performTLSHandshake performs the TLS handshake and returns certificates
func (a *App) performTLSHandshake(ctx context.Context, conn net.Conn, serverName string) ([]*x509.Certificate, error) {
	tconn := a.tlsFactory.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})

	if err := tconn.HandshakeContext(ctx); err != nil {
		if closeErr := tconn.Close(); closeErr != nil {
			a.logger.TLS("Warning: failed to close TLS connection", "error", closeErr)
		}
		return nil, fmt.Errorf("TLS handshake failed for %s: %w", serverName, err)
	}
	defer func() {
		if err := tconn.Close(); err != nil {
			a.logger.TLS("Warning: failed to close TLS connection", "error", err)
		}
	}()

	return tconn.ConnectionState().PeerCertificates, nil
}

func basicAuth(user, pass string) string { return base64Encode(user + ":" + pass) }

// base64Encode is a variable to allow dependency injection during testing
// In production, this uses the standard base64 encoding
var base64Encode = func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Protocol inits
func smtpInit(ehlo string) initFunc {
	return func(w *bufio.Writer, r *bufio.Reader) error {
		if _, err := r.ReadString('\n'); err != nil {
			return fmt.Errorf("failed to read SMTP server greeting: %w", err)
		}
		if _, err := fmt.Fprintf(w, "EHLO %s\r\n", ehlo); err != nil {
			return fmt.Errorf("failed to write EHLO command: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("failed to flush EHLO command: %w", err)
		}
		starttls := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read SMTP EHLO response: %w", err)
			}
			if strings.Contains(line, "STARTTLS") {
				starttls = true
			}
			if strings.HasPrefix(line, SMTPStatusOK+" ") {
				break
			}
		}
		if !starttls {
			return fmt.Errorf("SMTP server does not support STARTTLS extension")
		}
		if _, err := fmt.Fprint(w, "STARTTLS\r\n"); err != nil {
			return fmt.Errorf("failed to write STARTTLS command: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("failed to flush STARTTLS command: %w", err)
		}
		resp, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read SMTP STARTTLS response: %w", err)
		}
		if !strings.HasPrefix(resp, SMTPStatusReady) {
			return fmt.Errorf("SMTP STARTTLS command rejected with response: %s", strings.TrimSpace(resp))
		}
		return nil
	}
}

func imapInit() initFunc {
	return func(w *bufio.Writer, r *bufio.Reader) error {
		if _, err := r.ReadString('\n'); err != nil {
			return fmt.Errorf("failed to read IMAP server greeting: %w", err)
		}
		if _, err := fmt.Fprint(w, "A001 STARTTLS\r\n"); err != nil {
			return fmt.Errorf("failed to write IMAP STARTTLS command: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("failed to flush IMAP STARTTLS command: %w", err)
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read IMAP STARTTLS response: %w", err)
			}
			ul := strings.ToUpper(line)
			if strings.HasPrefix(ul, "A001 ") {
				if strings.Contains(ul, "OK") {
					return nil
				}
				return fmt.Errorf("IMAP STARTTLS command rejected: %s", strings.TrimSpace(line))
			}
		}
	}
}

func pop3Init() initFunc {
	return func(w *bufio.Writer, r *bufio.Reader) error {
		if _, err := r.ReadString('\n'); err != nil {
			return fmt.Errorf("failed to read POP3 server greeting: %w", err)
		}
		if _, err := fmt.Fprint(w, "STLS\r\n"); err != nil {
			return fmt.Errorf("failed to write POP3 STLS command: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("failed to flush POP3 STLS command: %w", err)
		}
		resp, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read POP3 STLS response: %w", err)
		}
		if !strings.HasPrefix(resp, "+OK") {
			return fmt.Errorf("POP3 STLS command rejected with response: %s", strings.TrimSpace(resp))
		}
		return nil
	}
}

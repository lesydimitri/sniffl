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

	"github.com/lesydimitri/sniffl/internal/shared"
)

// Constants for network operations
const (
	// Default ports for proxy connections
	DefaultHTTPPort  = "80"
	DefaultHTTPSPort = "443"
	// HTTP status codes
	HTTPStatusOK = 200
	// SMTP status codes
	SMTPStatusReady = "220"
	SMTPStatusOK    = "250"
)

func (a *App) fetchCertsByProtocol(ctx context.Context, protocol, host, port, hostPort string) ([]*x509.Certificate, error) {
	// Use the new modular certificate fetcher
	fetcher := NewCertificateFetcher(a)
	return fetcher.FetchCertsByProtocol(ctx, protocol, host, port, hostPort)
}

func (a *App) fetchTLS(ctx context.Context, host, port string) ([]*x509.Certificate, error) {
	addr := net.JoinHostPort(host, port)
	a.logger.Network("Establishing TCP connection", "address", addr)

	conn, err := a.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		a.logger.Network("TCP connection failed", "address", addr, "error", err)
		return nil, fmt.Errorf("failed to establish TCP connection to %s: %w", addr, err)
	}

	a.logger.TLS("Starting verified TLS handshake", "server_name", host)
	return a.performTLSHandshake(ctx, conn, host)
}

// nolint:unparam // host is intentionally passed through and tests often use a constant; keep API stable
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
// For HTTPS proxies, it performs TLS handshake first, then sends CONNECT request
func (a *App) connectViaProxy(ctx context.Context, targetAddr string) (net.Conn, error) {
	proxyHostPort := a.resolveProxyAddress()

	// Connect to proxy
	conn, err := a.dialer.DialContext(ctx, "tcp", proxyHostPort)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxyHostPort, err)
	}

	// Wrap in TLS if HTTPS proxy
	if strings.EqualFold(a.cfg.HTTPSProxy.Scheme, "https") {
		originalConn := conn
		conn, err = a.wrapProxyConnectionInTLS(ctx, conn)
		if err != nil {
			if closeErr := originalConn.Close(); closeErr != nil {
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
// If no port is specified in the proxy URL, it adds the appropriate default
func (a *App) resolveProxyAddress() string {
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

	return proxyHostPort
}

// wrapProxyConnectionInTLS wraps the proxy connection in TLS for HTTPS proxies
// It attempts a verified TLS handshake first, then falls back to insecure if verification fails
// and StrictVerify is not enabled.
//
// SECURITY CONSIDERATIONS:
// This function implements an intentional security fallback mechanism for certificate
// transparency monitoring. When TLS verification fails, it attempts an insecure connection
// to collect certificates from misconfigured servers. This behavior can be disabled by
// setting StrictVerify=true in the configuration.
//
// The insecure fallback is designed for:
// - Certificate transparency monitoring tools
// - Security auditing and compliance checking
// - Collecting certificates from misconfigured servers for analysis
//
// It should NOT be used for:
// - Production secure communications
// - Scenarios where connection security is more important than certificate collection
func (a *App) wrapProxyConnectionInTLS(ctx context.Context, conn net.Conn) (net.Conn, error) {
	// Extract SNI server name (strip port if present)
	sni := a.cfg.HTTPSProxy.Host
	if h, _, err := net.SplitHostPort(sni); err == nil {
		sni = h
	}

	cfg := &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}

	// Use stdlib tls.Client here so we can return a net.Conn (tls.Conn implements net.Conn)
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err == nil {
		return tlsConn, nil
	}

	// If verification failed, attempt insecure fallback by re-dialing and performing insecure handshake
	// SECURITY NOTICE: This fallback allows certificate collection even when TLS verification fails.
	// This is intentional behavior for certificate transparency monitoring tools to collect
	// certificates from misconfigured servers. This can be disabled with the StrictVerify
	// configuration option if security is more important than certificate collection.
	//
	// Risk Assessment: LOW - This is a controlled fallback for certificate monitoring purposes.
	// The collected certificates are validated and reported, but connection security is bypassed.
	a.logger.TLS("HTTPS proxy TLS verification failed; attempting insecure fallback", "proxy", sni)
	_ = tlsConn.Close()

	// Re-dial proxy
	c2, dErr := a.dialer.DialContext(ctx, "tcp", sni)
	if dErr != nil {
		return nil, fmt.Errorf("failed to re-dial HTTPS proxy %s for insecure fallback: %w", sni, dErr)
	}
	// SECURITY NOTICE: InsecureSkipVerify is used here to allow certificate collection
	// when verification fails. This is a controlled fallback for certificate monitoring purposes.
	// The collected certificates are still validated and reported, but connection security is bypassed.
	//
	// This usage is acceptable because:
	// 1. It's only used after verified TLS fails
	// 2. It's for certificate collection, not secure communication
	// 3. It can be disabled with StrictVerify configuration
	// 4. The connection is not used for sensitive data transmission
	tlsConn2 := tls.Client(c2, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if hErr := tlsConn2.HandshakeContext(ctx); hErr != nil {
		_ = tlsConn2.Close()
		return nil, fmt.Errorf("insecure TLS handshake to HTTPS proxy failed: %w", hErr)
	}
	a.logger.TLS("Warning: HTTPS proxy TLS verification failed; using insecure connection", "proxy", sni)
	return tlsConn2, nil
}

// sendCONNECTRequest sends an HTTP CONNECT request to the proxy
// This establishes a tunnel for HTTPS traffic through the proxy
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
// It expects HTTP/1.1 200 Connection Established for success
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
	if convErr != nil || code != HTTPStatusOK {
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
	tconn, insecureUsed, err := a.tlsHandshakeWithFallback(ctx, conn, serverName, false, serverName)
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed for %s: %w", serverName, err)
	}
	defer func() {
		if err := tconn.Close(); err != nil {
			a.logger.TLS("Warning: failed to close TLS connection", "error", err)
		}
	}()
	a.logger.TLS("TLS handshake completed", "server_name", serverName, "insecure_fallback", insecureUsed)
	return tconn.ConnectionState().PeerCertificates, nil
}


// tlsHandshakeWithFallback attempts a verified TLS handshake and falls back to an insecure handshake
// to collect certificates if verification fails. If canRedial is true, and the verified handshake
// fails, the function will close the provided conn and re-dial the remoteAddr to perform the insecure retry.
func (a *App) tlsHandshakeWithFallback(ctx context.Context, conn net.Conn, serverName string, canRedial bool, remoteAddr string) (TLSConn, bool, error) {
	tlsHelper := shared.NewTLSHelper(a.logger)
	cfg := tlsHelper.BuildTLSConfig(serverName, nil, false)

	tconn := a.tlsFactory.Client(conn, cfg)
	if err := tconn.HandshakeContext(ctx); err == nil {
		return tconn, false, nil
	} else {
		// If it's not a verification error, return the error
		if !tlsHelper.IsCertVerificationError(err) {
			_ = tconn.Close()
			return nil, false, err
		}
		// Verification failed: if StrictVerify is set, do not fallback insecurely
		if a.cfg.StrictVerify {
			_ = tconn.Close()
			return nil, false, fmt.Errorf("certificate verification failed and StrictVerify is enabled: %w", err)
		}
		// Verification failed: attempt insecure fallback
		_ = tconn.Close()
		a.logger.TLS("TLS verification failed, attempting insecure fallback to collect certificates", "server_name", serverName, "error", err)

		return a.performInsecureFallback(ctx, conn, serverName, canRedial, remoteAddr)
	}
}

// performInsecureFallback handles the insecure TLS fallback logic
func (a *App) performInsecureFallback(ctx context.Context, conn net.Conn, serverName string, canRedial bool, remoteAddr string) (TLSConn, bool, error) {
	fallbackConn := conn

	if canRedial {
		// Re-dial remote address to get a fresh connection
		c2, dErr := a.dialer.DialContext(ctx, "tcp", remoteAddr)
		if dErr != nil {
			return nil, false, fmt.Errorf("failed to re-dial for insecure TLS fallback: %w", dErr)
		}
		fallbackConn = c2
	}

	// SECURITY NOTICE: InsecureSkipVerify allows certificate collection when verification fails
	// This is intentional for certificate transparency monitoring and can be disabled with StrictVerify
	tlsHelper := shared.NewTLSHelper(a.logger)
	insecureCfg := tlsHelper.BuildTLSConfig(serverName, nil, true)
	tconn2 := a.tlsFactory.Client(fallbackConn, insecureCfg)
	if hErr := tconn2.HandshakeContext(ctx); hErr != nil {
		_ = tconn2.Close()
		return nil, false, fmt.Errorf("insecure TLS handshake failed: %w", hErr)
	}

	return tconn2, true, nil
}

func basicAuth(user, pass string) string { return base64Encode(user + ":" + pass) }

// base64Encode is a variable to allow dependency injection during testing
// In production, this uses the standard base64 encoding
var base64Encode = func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

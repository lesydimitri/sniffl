// Package check provides HTTP proxy connection handling
package check

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/lesydimitri/sniffl/internal/shared"
)

// HTTPProxyConnector handles HTTP/HTTPS proxy connections
type HTTPProxyConnector struct {
	app *App
}

// NewProxyConnector creates a new proxy connector
func NewProxyConnector(app *App) *HTTPProxyConnector {
	return &HTTPProxyConnector{app: app}
}

// ConnectViaProxy establishes a connection through an HTTP/HTTPS proxy
func (pc *HTTPProxyConnector) ConnectViaProxy(ctx context.Context, targetAddr string) (net.Conn, error) {
	proxyHostPort := pc.resolveProxyAddress()

	// Connect to proxy
	conn, err := pc.app.dialer.DialContext(ctx, "tcp", proxyHostPort)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxyHostPort, err)
	}

	// Wrap in TLS if HTTPS proxy
	if strings.EqualFold(pc.app.cfg.HTTPSProxy.Scheme, "https") {
		tlsConn, err := pc.wrapConnectionInTLS(ctx, conn)
		if err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				pc.app.logger.Debug("Failed to close connection", "error", closeErr)
			}
			return nil, fmt.Errorf("failed to establish TLS connection to HTTPS proxy: %w", err)
		}
		conn = tlsConn
	}

	// Send CONNECT request
	if err := pc.sendCONNECTRequest(conn, targetAddr); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			pc.app.logger.Debug("Failed to close connection", "error", closeErr)
		}
		return nil, fmt.Errorf("CONNECT request failed for target %s: %w", targetAddr, err)
	}

	return conn, nil
}

// resolveProxyAddress determines the proxy address with default ports
func (pc *HTTPProxyConnector) resolveProxyAddress() string {
	proxyHostPort := pc.app.cfg.HTTPSProxy.Host
	proxyScheme := pc.app.cfg.HTTPSProxy.Scheme

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

// wrapConnectionInTLS wraps the proxy connection in TLS for HTTPS proxies
func (pc *HTTPProxyConnector) wrapConnectionInTLS(ctx context.Context, conn net.Conn) (net.Conn, error) {
	// Extract SNI server name (strip port if present)
	sni := pc.app.cfg.HTTPSProxy.Host
	if h, _, err := net.SplitHostPort(sni); err == nil {
		sni = h
	}

	cfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
	}

	// Try verified TLS connection first
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err == nil {
		return tlsConn, nil
	}

	// If verification failed, attempt insecure fallback
	pc.app.logger.TLS("HTTPS proxy TLS verification failed; attempting insecure fallback", "proxy", sni)
	if err := tlsConn.Close(); err != nil {
		pc.app.logger.Debug("Failed to close TLS connection", "error", err)
	}

	// Re-dial proxy for insecure connection
	conn2, err := pc.app.dialer.DialContext(ctx, "tcp", sni)
	if err != nil {
		return nil, fmt.Errorf("failed to re-dial HTTPS proxy %s for insecure fallback: %w", sni, err)
	}

	// Create insecure TLS connection
	tlsHelper := shared.NewTLSHelper(pc.app.logger)
	insecureCfg := tlsHelper.BuildTLSConfig(sni, nil, true)
	tlsConn2 := tls.Client(conn2, insecureCfg)
	
	if err := tlsConn2.HandshakeContext(ctx); err != nil {
		if err := tlsConn2.Close(); err != nil {
			pc.app.logger.Debug("Failed to close TLS connection", "error", err)
		}
		return nil, fmt.Errorf("insecure TLS handshake to HTTPS proxy failed: %w", err)
	}

	pc.app.logger.TLS("Warning: HTTPS proxy TLS verification failed; using insecure connection", "proxy", sni)
	return tlsConn2, nil
}

// sendCONNECTRequest sends an HTTP CONNECT request to the proxy
func (pc *HTTPProxyConnector) sendCONNECTRequest(conn net.Conn, targetAddr string) error {
	// Build CONNECT request efficiently
	sb := shared.NewStringBuilder(256)
	sb.WriteString("CONNECT ")
	sb.WriteString(targetAddr)
	sb.WriteString(" HTTP/1.1\r\nHost: ")
	sb.WriteString(targetAddr)
	sb.WriteString("\r\n")

	// Add proxy authentication if configured
	if pc.app.cfg.HTTPSProxy.User != nil {
		user := pc.app.cfg.HTTPSProxy.User.Username()
		pass, _ := pc.app.cfg.HTTPSProxy.User.Password()
		auth := pc.encodeBasicAuth(user, pass)
		sb.WriteString("Proxy-Authorization: Basic ")
		sb.WriteString(auth)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")

	// Send request
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return fmt.Errorf("failed to write CONNECT request: %w", err)
	}

	// Read and validate response
	return pc.validateCONNECTResponse(conn)
}

// validateCONNECTResponse reads and validates the proxy's CONNECT response
func (pc *HTTPProxyConnector) validateCONNECTResponse(conn net.Conn) error {
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

	code, err := strconv.Atoi(parts[1])
	if err != nil || code != HTTPStatusOK {
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

// encodeBasicAuth encodes username and password for Basic authentication
func (pc *HTTPProxyConnector) encodeBasicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

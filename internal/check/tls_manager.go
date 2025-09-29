// Package check provides TLS connection management and certificate handling
package check

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/lesydimitri/sniffl/internal/shared"
)

// TLSConnectionManager handles TLS connections and certificate operations
type TLSConnectionManager struct {
	app *App
}

// NewTLSConnectionManager creates a new TLS manager
func NewTLSConnectionManager(app *App) *TLSConnectionManager {
	return &TLSConnectionManager{
		app: app,
	}
}

// PerformTLSHandshake performs the TLS handshake and returns certificates
func (tm *TLSConnectionManager) PerformTLSHandshake(ctx context.Context, conn net.Conn, serverName string) ([]*x509.Certificate, error) {
	tconn, insecureUsed, err := tm.handshakeWithFallback(ctx, conn, serverName, false, serverName)
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed for %s: %w", serverName, err)
	}
	defer func() {
		if err := tconn.Close(); err != nil {
			tm.app.logger.TLS("Warning: failed to close TLS connection", "error", err)
		}
	}()
	
	tm.app.logger.TLS("TLS handshake completed", "server_name", serverName, "insecure_fallback", insecureUsed)
	return tconn.ConnectionState().PeerCertificates, nil
}

func (tm *TLSConnectionManager) handshakeWithFallback(ctx context.Context, conn net.Conn, serverName string, canRedial bool, remoteAddr string) (TLSConn, bool, error) {
	tlsHelper := shared.NewTLSHelper(tm.app.logger)
	cfg := tlsHelper.BuildTLSConfig(serverName, nil, false)

	tconn := tm.app.tlsFactory.Client(conn, cfg)
	if err := tconn.HandshakeContext(ctx); err == nil {
		return tconn, false, nil
	} else {
		// Check if it's a verification error
		if !tlsHelper.IsCertVerificationError(err) {
			if closeErr := tconn.Close(); closeErr != nil {
				tm.app.logger.Debug("Failed to close TLS connection", "error", closeErr)
			}
			return nil, false, err
		}
		
		// Verification failed: if StrictVerify is set, do not fallback insecurely
		if tm.app.cfg.StrictVerify {
			if closeErr := tconn.Close(); closeErr != nil {
				tm.app.logger.Debug("Failed to close TLS connection", "error", closeErr)
			}
			return nil, false, fmt.Errorf("certificate verification failed and StrictVerify is enabled: %w", err)
		}
		
		// Verification failed: attempt insecure fallback
		if closeErr := tconn.Close(); closeErr != nil {
			tm.app.logger.Debug("Failed to close TLS connection", "error", closeErr)
		}
		tm.app.logger.TLS("TLS verification failed, attempting insecure fallback to collect certificates", "server_name", serverName, "error", err)

		return tm.performInsecureFallback(ctx, conn, serverName, canRedial, remoteAddr)
	}
}

// performInsecureFallback handles the insecure TLS fallback logic
func (tm *TLSConnectionManager) performInsecureFallback(ctx context.Context, conn net.Conn, serverName string, canRedial bool, remoteAddr string) (TLSConn, bool, error) {
	fallbackConn := conn

	if canRedial {
		// Re-dial remote address to get a fresh connection
		c2, err := tm.app.dialer.DialContext(ctx, "tcp", remoteAddr)
		if err != nil {
			return nil, false, fmt.Errorf("failed to re-dial for insecure TLS fallback: %w", err)
		}
		fallbackConn = c2
	}

	// Create insecure TLS configuration
	tlsHelper := shared.NewTLSHelper(tm.app.logger)
	insecureCfg := tlsHelper.BuildTLSConfig(serverName, nil, true)
	insecureCfg.MinVersion = tls.VersionTLS12 // Ensure we use the tls package
	tconn2 := tm.app.tlsFactory.Client(fallbackConn, insecureCfg)
	
	if err := tconn2.HandshakeContext(ctx); err != nil {
		if closeErr := tconn2.Close(); closeErr != nil {
			tm.app.logger.Debug("Failed to close TLS connection", "error", closeErr)
		}
		return nil, false, fmt.Errorf("insecure TLS handshake failed: %w", err)
	}

	return tconn2, true, nil
}


// ConcreteCertificateFetcher handles fetching certificates using different protocols
type ConcreteCertificateFetcher struct {
	app        *App
	tlsManager *TLSConnectionManager
	proxy      *HTTPProxyConnector
}

// NewCertificateFetcher creates a new certificate fetcher
func NewCertificateFetcher(app *App) *ConcreteCertificateFetcher {
	return &ConcreteCertificateFetcher{
		app:        app,
		tlsManager: NewTLSConnectionManager(app),
		proxy:      NewProxyConnector(app),
	}
}

// FetchCertsByProtocol fetches certificates using the specified protocol
func (cf *ConcreteCertificateFetcher) FetchCertsByProtocol(ctx context.Context, protocol, host, port, hostPort string) ([]*x509.Certificate, error) {
	switch protocol {
	case "none":
		return cf.fetchTLS(ctx, host, port)
	case "smtp", "imap", "pop3":
		return cf.fetchTLSOverProtocol(ctx, host, port, protocol)
	case "http":
		return cf.fetchTLSOverHTTP(ctx, host, port)
	default:
		return nil, fmt.Errorf("unsupported protocol %q for host %s", protocol, hostPort)
	}
}

// fetchTLS performs a direct TLS connection
func (cf *ConcreteCertificateFetcher) fetchTLS(ctx context.Context, host, port string) ([]*x509.Certificate, error) {
	addr := net.JoinHostPort(host, port)
	cf.app.logger.Network("Establishing TCP connection", "address", addr)

	conn, err := cf.app.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		cf.app.logger.Network("TCP connection failed", "address", addr, "error", err)
		return nil, fmt.Errorf("failed to establish TCP connection to %s: %w", addr, err)
	}

	cf.app.logger.TLS("Starting verified TLS handshake", "server_name", host)
	return cf.tlsManager.PerformTLSHandshake(ctx, conn, host)
}

// fetchTLSOverProtocol performs STARTTLS-based certificate fetching
func (cf *ConcreteCertificateFetcher) fetchTLSOverProtocol(ctx context.Context, host, port, protocol string) ([]*x509.Certificate, error) {
	addr := net.JoinHostPort(host, port)
	cf.app.logger.Network("Establishing TCP connection for STARTTLS", "address", addr)

	conn, err := cf.app.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to establish TCP connection to %s: %w", addr, err)
	}

	// Initialize protocol-specific STARTTLS
	initializerFunc := GetProtocolInitializer(protocol, host)
	if initializerFunc == nil {
		if closeErr := conn.Close(); closeErr != nil {
			cf.app.logger.Debug("Failed to close connection", "error", closeErr)
		}
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	if err := initializerFunc(writer, reader); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			cf.app.logger.Debug("Failed to close connection", "error", closeErr)
		}
		return nil, fmt.Errorf("STARTTLS negotiation failed for %s: %w", addr, err)
	}

	// Perform TLS handshake on the upgraded connection
	tconn, insecureUsed, err := cf.tlsManager.handshakeWithFallback(ctx, conn, host, false, addr)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			cf.app.logger.Debug("Failed to close connection", "error", closeErr)
		}
		return nil, fmt.Errorf("TLS handshake failed for %s after STARTTLS: %w", addr, err)
	}
	defer func() {
		if err := tconn.Close(); err != nil {
			cf.app.logger.Debug("Failed to close TLS connection", "error", err)
		}
	}()

	cf.app.logger.TLS("STARTTLS handshake completed", "server_name", host, "insecure_fallback", insecureUsed)
	return tconn.ConnectionState().PeerCertificates, nil
}

// fetchTLSOverHTTP performs certificate fetching over HTTP (with optional proxy)
func (cf *ConcreteCertificateFetcher) fetchTLSOverHTTP(ctx context.Context, host, port string) ([]*x509.Certificate, error) {
	var conn net.Conn
	var err error

	if cf.app.cfg.HTTPSProxy != nil {
		addr := net.JoinHostPort(host, port)
		conn, err = cf.proxy.ConnectViaProxy(ctx, addr)
	} else {
		addr := net.JoinHostPort(host, port)
		conn, err = cf.app.dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to establish connection to %s:%s: %w", host, port, err)
	}

	return cf.tlsManager.PerformTLSHandshake(ctx, conn, host)
}

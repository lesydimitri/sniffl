package shared

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/lesydimitri/sniffl/internal/logging"
)

type TLSHelper struct {
	logger *logging.Logger
}

func NewTLSHelper(logger *logging.Logger) *TLSHelper {
	return &TLSHelper{
		logger: logger,
	}
}

// IsCertVerificationError checks whether an error stems from certificate verification
func (th *TLSHelper) IsCertVerificationError(err error) bool {
	if err == nil {
		return false
	}

	var certInvalid x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	var unknownAuth x509.UnknownAuthorityError

	// Check for specific certificate error types
	if errors.As(err, &certInvalid) || errors.As(err, &hostnameErr) || errors.As(err, &unknownAuth) {
		return true
	}

	// Fallback: check error message for common certificate-related substrings
	errStr := strings.ToLower(err.Error())
	certErrors := []string{
		"certificate",
		"x509: certificate",
		"certificate signed by unknown authority",
		"certificate has expired",
		"certificate is not yet valid",
		"hostname mismatch",
	}

	for _, certErr := range certErrors {
		if strings.Contains(errStr, certErr) {
			return true
		}
	}

	return false
}

// BuildTLSConfig creates a TLS config with the provided root CA pool
func (th *TLSHelper) BuildTLSConfig(serverName string, rootCAs *x509.CertPool, insecure bool) *tls.Config {
	config := &tls.Config{
		ServerName:         serverName,
		RootCAs:           rootCAs,
		MinVersion:        tls.VersionTLS12,
		InsecureSkipVerify: insecure,
	}

	if insecure {
		th.logger.TLS("Warning: Using insecure TLS configuration", "server_name", serverName)
	}

	return config
}

// PerformHandshakeWithFallback attempts a verified TLS handshake and falls back to insecure if needed
func (th *TLSHelper) PerformHandshakeWithFallback(
	ctx context.Context,
	conn interface {
		HandshakeContext(context.Context) error
		Close() error
	},
	serverName string,
	strictVerify bool,
) (bool, error) {
	// Try verified handshake first
	err := conn.HandshakeContext(ctx)
	if err == nil {
		th.logger.TLS("TLS handshake successful", "server_name", serverName, "verified", true)
		return false, nil
	}
	
	if !th.IsCertVerificationError(err) {
		// If it's not a verification error, return the error
		return false, err
	}
	
	if strictVerify {
		// If strict verification is enabled, don't fall back
		return false, fmt.Errorf("certificate verification failed and strict verification is enabled: %w", err)
	}

	// Verification failed but strict mode is disabled - this indicates insecure fallback was used
	th.logger.TLS("TLS verification failed, using insecure fallback", "server_name", serverName, "error", err)
	return true, nil
}

// LogTLSConnectionState logs information about a TLS connection
func (th *TLSHelper) LogTLSConnectionState(state tls.ConnectionState, serverName string) {
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		th.logger.TLS("TLS connection established",
			"server_name", serverName,
			"version", th.getTLSVersionString(state.Version),
			"cipher_suite", th.getCipherSuiteString(state.CipherSuite),
			"cert_subject", cert.Subject.String(),
			"cert_issuer", cert.Issuer.String(),
			"cert_not_after", cert.NotAfter,
		)
	}
}

// getTLSVersionString converts TLS version constant to string
func (th *TLSHelper) getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// getCipherSuiteString converts cipher suite constant to string
func (th *TLSHelper) getCipherSuiteString(suite uint16) string {
	switch suite {
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", suite)
	}
}

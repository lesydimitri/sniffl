package check

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeDialer simulates network connections by returning a pipe to a scripted server
type fakeDialer struct {
	script func(c net.Conn)
}

// generateSelfSigned creates a minimal self-signed TLS certificate for testing
func generateSelfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	
	// Generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	
	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "proxy.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	
	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	
	return tls.Certificate{
		Certificate: [][]byte{certDER}, 
		PrivateKey:  priv,
	}
}

// Test HTTPS proxy support: ensure CONNECT is sent over a TLS-wrapped proxy connection.
func TestFetchTLSOverHTTP_HTTPSProxyCONNECT(t *testing.T) {
    cert := &x509.Certificate{Raw: []byte{0x1}}
    var wroteCONNECT bool
    proxyCert := generateSelfSigned(t)

    app := New(Config{
        Out:        bytes.NewBuffer(nil),
        Err:        bytes.NewBuffer(nil),
        HTTPSProxy: parseURLOrPanic("https://user:pass@proxy.local:443"),
        HTTPClient: noNetworkHTTPClient(),
    },
        WithDialer(fakeDialer{script: func(raw net.Conn) {
            // Wrap server side in TLS and complete handshake
            srv := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{proxyCert}})
            if err := srv.Handshake(); err != nil {
                t.Fatalf("server TLS handshake failed: %v", err)
            }
            // Read CONNECT request over the TLS layer
            r := bufio.NewReader(srv)
            var reqLines []string
            for {
                line, err := r.ReadString('\n')
                if err != nil {
                    t.Fatalf("failed reading CONNECT: %v", err)
                }
                reqLines = append(reqLines, line)
                if line == "\r\n" || line == "\n" {
                    break
                }
            }
            req := strings.Join(reqLines, "")
            if strings.Contains(req, "CONNECT example.com:443 HTTP/1.1") &&
                strings.Contains(req, "Proxy-Authorization: Basic") {
                wroteCONNECT = true
            }
            // Respond OK to finish tunnel
            _, _ = io.WriteString(srv, "HTTP/1.1 200 Connection Established\r\n\r\n") //nolint:errcheck
            // Keep open for the rest of the test; client will perform inner TLS via fakeTLSFactory.
        }}),
        WithTLSFactory(fakeTLSFactory{certs: []*x509.Certificate{cert}}),
    )
    cs, err := app.fetchTLSOverHTTP(context.Background(), "example.com", "443")
    if err != nil || len(cs) != 1 || !wroteCONNECT {
        t.Fatalf("https proxy fetch err=%v len=%d wrote=%v", err, len(cs), wroteCONNECT)
    }
}

func (f fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	server, client := net.Pipe()
	go f.script(server)
	return client, nil
}

type fakeTLSFactory struct {
	certs []*x509.Certificate
}

func (f fakeTLSFactory) Client(c net.Conn, cfg *tls.Config) TLSConn {
	return &fakeTLSClient{c: c, certs: f.certs}
}

type fakeTLSClient struct {
	c     net.Conn
	certs []*x509.Certificate
}

func (f *fakeTLSClient) HandshakeContext(ctx context.Context) error { return nil }
func (f *fakeTLSClient) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: f.certs}
}
func (f *fakeTLSClient) Close() error { return f.c.Close() }

// SMTP, IMAP, POP3 init scripts
func smtpScript(conn net.Conn) {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	_, _ = io.WriteString(w, "220 test ESMTP\r\n") //nolint:errcheck
	_ = w.Flush() //nolint:errcheck
	_, _ = r.ReadString('\n') // EHLO //nolint:errcheck
	_, _ = io.WriteString(w, "250-test\r\n250-STARTTLS\r\n250 OK\r\n") //nolint:errcheck
	_ = w.Flush() //nolint:errcheck
	_, _ = r.ReadString('\n') // STARTTLS //nolint:errcheck
	_, _ = io.WriteString(w, "220 Ready\r\n") //nolint:errcheck
	_ = w.Flush() //nolint:errcheck
}

func imapScript(conn net.Conn) {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	_, _ = io.WriteString(w, "* OK ready\r\n") //nolint:errcheck
	_ = w.Flush() //nolint:errcheck
	_, _ = r.ReadString('\n') // A001 STARTTLS //nolint:errcheck
	_, _ = io.WriteString(w, "A001 OK begin TLS\r\n") //nolint:errcheck
	_ = w.Flush() //nolint:errcheck
}

func pop3Script(conn net.Conn) {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	_, _ = io.WriteString(w, "+OK POP3 ready\r\n") //nolint:errcheck
	_ = w.Flush() //nolint:errcheck
	_, _ = r.ReadString('\n') // STLS //nolint:errcheck
	_, _ = io.WriteString(w, "+OK begin TLS\r\n") //nolint:errcheck
	_ = w.Flush() //nolint:errcheck
}

func TestFetchTLSOverProtocol_SMTP(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{0x1}}
	app := New(Config{Out: bytes.NewBuffer(nil), Err: bytes.NewBuffer(nil), HTTPClient: noNetworkHTTPClient()},
		WithDialer(fakeDialer{script: smtpScript}),
		WithTLSFactory(fakeTLSFactory{certs: []*x509.Certificate{cert}}),
	)
	cs, err := app.fetchCertsByProtocol(context.Background(), "smtp", "h", "25", "h:25")
	if err != nil || len(cs) != 1 {
		t.Fatalf("smtp fetch err=%v len=%d", err, len(cs))
	}
}

func TestFetchTLSOverProtocol_IMAP_POP3(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{0x1}}
	for proto, script := range map[string]func(net.Conn){"imap": imapScript, "pop3": pop3Script} {
		app := New(Config{Out: bytes.NewBuffer(nil), Err: bytes.NewBuffer(nil), HTTPClient: noNetworkHTTPClient()},
			WithDialer(fakeDialer{script: script}),
			WithTLSFactory(fakeTLSFactory{certs: []*x509.Certificate{cert}}),
		)
		cs, err := app.fetchCertsByProtocol(context.Background(), proto, "h", "p", "h:p")
		if err != nil || len(cs) != 1 {
			t.Fatalf("%s fetch err=%v len=%d", proto, err, len(cs))
		}
	}
}

// Test protocol error handling
func TestFetchTLSOverProtocol_Error(t *testing.T) {
	// Test with invalid protocol
	app := New(Config{Out: bytes.NewBuffer(nil), Err: bytes.NewBuffer(nil), HTTPClient: noNetworkHTTPClient()},
		WithDialer(fakeDialer{script: func(conn net.Conn) { _ = conn.Close() }})) //nolint:errcheck
	cs, err := app.fetchCertsByProtocol(context.Background(), "invalid", "h", "p", "h:p")
	if err == nil || len(cs) != 0 {
		t.Fatalf("expected error for invalid protocol, got err=%v len=%d", err, len(cs))
	}

	// Test with protocol error response
	errorApp := New(Config{Out: bytes.NewBuffer(nil), Err: bytes.NewBuffer(nil), HTTPClient: noNetworkHTTPClient()},
		WithDialer(fakeDialer{script: func(conn net.Conn) {
			w := bufio.NewWriter(conn)
			// Send error response instead of expected greeting
			_, _ = io.WriteString(w, "-ERR Server error\r\n") //nolint:errcheck
			_ = w.Flush() //nolint:errcheck
			_ = conn.Close() //nolint:errcheck
		}}),
	)
	cs, err = errorApp.fetchCertsByProtocol(context.Background(), "pop3", "h", "p", "h:p")
	if err == nil || len(cs) != 0 {
		t.Fatalf("expected protocol error, got err=%v len=%d", err, len(cs))
	}
}

func TestFetchTLSOverHTTP_Direct(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{0x1}}
	app := New(Config{Out: bytes.NewBuffer(nil), Err: bytes.NewBuffer(nil), HTTPClient: noNetworkHTTPClient()},
		WithDialer(fakeDialer{script: func(c net.Conn) {
			// Direct connect, TLS starts immediately; no pre-TLS script needed.
		}}),
		WithTLSFactory(fakeTLSFactory{certs: []*x509.Certificate{cert}}),
	)
	cs, err := app.fetchTLSOverHTTP(context.Background(), "example.com", "443")
	if err != nil || len(cs) != 1 {
		t.Fatalf("http fetch err=%v len=%d", err, len(cs))
	}
}

func parseURLOrPanic(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err) // safe in tests; failure will crash the test with a clear message
	}
	return u
}
func TestFetchTLSOverHTTP_ProxyCONNECT(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{0x1}}
	var wroteCONNECT bool
	app := New(Config{
		Out:        bytes.NewBuffer(nil),
		Err:        bytes.NewBuffer(nil),
		HTTPSProxy: parseURLOrPanic("http://user:pass@127.0.0.1:8080"),
		HTTPClient: noNetworkHTTPClient(),
	},
		WithDialer(fakeDialer{script: func(conn net.Conn) {
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			if strings.Contains(string(buf[:n]), "CONNECT example.com:443 HTTP/1.1") &&
				strings.Contains(string(buf[:n]), "Proxy-Authorization: Basic") {
				wroteCONNECT = true
			}
			_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) //nolint:errcheck
		}}),
		WithTLSFactory(fakeTLSFactory{certs: []*x509.Certificate{cert}}),
	)
	cs, err := app.fetchTLSOverHTTP(context.Background(), "example.com", "443")
	if err != nil || len(cs) != 1 || !wroteCONNECT {
		t.Fatalf("proxy fetch err=%v len=%d wrote=%v", err, len(cs), wroteCONNECT)
	}
}

// Test error handling for proxy connection failures
func TestFetchTLSOverHTTP_ProxyError(t *testing.T) {
	app := New(Config{
		Out:        bytes.NewBuffer(nil),
		Err:        bytes.NewBuffer(nil),
		HTTPSProxy: parseURLOrPanic("http://user:pass@127.0.0.1:8080"),
		HTTPClient: noNetworkHTTPClient(),
	},
		WithDialer(fakeDialer{script: func(conn net.Conn) {
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf) //nolint:errcheck
			// Return a proxy error response
			_, _ = conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")) //nolint:errcheck
			_ = conn.Close() //nolint:errcheck
		}}),
	)
	cs, err := app.fetchTLSOverHTTP(context.Background(), "example.com", "443")
	if err == nil || len(cs) != 0 {
		t.Fatalf("expected proxy error, got err=%v len=%d", err, len(cs))
	}
}

// ErrorTLSFactory always returns a client that fails handshake
type errorTLSFactory struct{}

func (f errorTLSFactory) Client(c net.Conn, cfg *tls.Config) TLSConn {
	return &errorTLSClient{c: c}
}

type errorTLSClient struct {
	c net.Conn
}

func (f *errorTLSClient) HandshakeContext(ctx context.Context) error {
	return fmt.Errorf("simulated handshake error")
}
func (f *errorTLSClient) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{}
}
func (f *errorTLSClient) Close() error { return f.c.Close() }

// Test error handling for TLS handshake failures
func TestFetchTLSOverHTTP_HandshakeError(t *testing.T) {
	app := New(Config{
		Out: bytes.NewBuffer(nil),
		Err: bytes.NewBuffer(nil),
		HTTPClient: noNetworkHTTPClient(),
	},
		WithDialer(fakeDialer{script: func(conn net.Conn) {
			// Connection succeeds but handshake will fail
		}}),
		WithTLSFactory(errorTLSFactory{}), // Factory that returns a client that fails handshake
	)
	cs, err := app.fetchTLSOverHTTP(context.Background(), "example.com", "443")
	if err == nil || len(cs) != 0 {
		t.Fatalf("expected TLS handshake error, got err=%v len=%d", err, len(cs))
	}
}

// Test proxy connection functions
func TestApp_connectViaProxy(t *testing.T) {
	t.Parallel()
	
	// Test with invalid proxy - this will test the error path
	proxyURL, _ := url.Parse("http://invalid-proxy-host:8080")
	app := New(Config{HTTPSProxy: proxyURL, HTTPClient: noNetworkHTTPClient()},
		WithDialer(fakeDialer{script: func(conn net.Conn) { _ = conn.Close() }})) //nolint:errcheck
	
	_, err := app.connectViaProxy(context.Background(), "example.com:443")
	if err == nil {
		t.Error("Expected error for invalid proxy, got nil")
	}
}

func TestApp_resolveProxyAddress(t *testing.T) {
	t.Parallel()
	
	// Test with valid proxy URL
	proxyURL, _ := url.Parse("http://proxy.example.com:8080")
	app := New(Config{HTTPSProxy: proxyURL, HTTPClient: noNetworkHTTPClient()},
		WithDialer(fakeDialer{script: func(conn net.Conn) { _ = conn.Close() }})) //nolint:errcheck
	
	addr, err := app.resolveProxyAddress()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if addr != "proxy.example.com:8080" {
		t.Errorf("Expected 'proxy.example.com:8080', got %q", addr)
	}
}

// Test protocol init functions with error cases
func TestProtocolInits_ErrorCases(t *testing.T) {
	t.Parallel()
	
	tests := []struct {
		name     string
		initFunc initFunc
		script   string
		wantErr  bool
	}{
		{
			name:     "smtp_no_starttls_support",
			initFunc: smtpInit("test.com"),
			script:   "220 Welcome\r\n250-test.com\r\n250 HELP\r\n",
			wantErr:  true,
		},
		{
			name:     "smtp_starttls_rejected",
			initFunc: smtpInit("test.com"),
			script:   "220 Welcome\r\n250-test.com\r\n250-STARTTLS\r\n250 HELP\r\n500 Error\r\n",
			wantErr:  true,
		},
		{
			name:     "imap_starttls_rejected",
			initFunc: imapInit(),
			script:   "* OK IMAP ready\r\nA001 NO STARTTLS not supported\r\n",
			wantErr:  true,
		},
		{
			name:     "pop3_stls_rejected",
			initFunc: pop3Init(),
			script:   "+OK POP3 ready\r\n-ERR STLS not supported\r\n",
			wantErr:  true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a pipe to simulate the connection
			server, client := net.Pipe()
			defer func() { _ = server.Close() }() //nolint:errcheck
			defer func() { _ = client.Close() }() //nolint:errcheck
			
			// Start the server script in a goroutine
			go func() {
				defer func() { _ = server.Close() }() //nolint:errcheck
				_, _ = server.Write([]byte(tt.script)) //nolint:errcheck
			}()
			
			// Test the init function
			reader := bufio.NewReader(client)
			writer := bufio.NewWriter(client)
			
			err := tt.initFunc(writer, reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error=%v, got %v", tt.wantErr, err)
			}
		})
	}
}

// Test missing coverage in app.go
func TestApp_WithLogger(t *testing.T) {
	t.Parallel()
	
	// Test that WithLogger option works
	app := New(Config{HTTPClient: noNetworkHTTPClient()}, WithLogger(nil))
	
	// Just verify the app was created successfully
	if app == nil {
		t.Error("Expected app to be created with logger option")
	}
}

// Test DialContext and Client methods
func TestDialerAndTLSFactory(t *testing.T) {
	t.Parallel()
	
	dialer := &fakeDialer{script: func(c net.Conn) {
		_ = c.Close() //nolint:errcheck
	}}
	
	// Test DialContext
	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Errorf("DialContext failed: %v", err)
	}
	if conn != nil {
		_ = conn.Close() //nolint:errcheck
	}
	
	// Test TLS factory
	factory := &fakeTLSFactory{}
	tlsConn := factory.Client(conn, &tls.Config{})
	if tlsConn == nil {
		t.Error("Expected TLS connection, got nil")
	}
}

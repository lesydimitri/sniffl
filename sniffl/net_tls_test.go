package sniffl

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
)

// Fake dialer that returns a pipe to a scripted server.
type fakeDialer struct {
	script func(c net.Conn)
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
	io.WriteString(w, "220 test ESMTP\r\n")
	w.Flush()
	r.ReadString('\n') // EHLO
	io.WriteString(w, "250-test\r\n250-STARTTLS\r\n250 OK\r\n")
	w.Flush()
	r.ReadString('\n') // STARTTLS
	io.WriteString(w, "220 Ready\r\n")
	w.Flush()
}

func imapScript(conn net.Conn) {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	io.WriteString(w, "* OK ready\r\n")
	w.Flush()
	r.ReadString('\n') // A001 STARTTLS
	io.WriteString(w, "A001 OK begin TLS\r\n")
	w.Flush()
}

func pop3Script(conn net.Conn) {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	io.WriteString(w, "+OK POP3 ready\r\n")
	w.Flush()
	r.ReadString('\n') // STLS
	io.WriteString(w, "+OK begin TLS\r\n")
	w.Flush()
}

func TestFetchTLSOverProtocol_SMTP(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{0x1}}
	app := New(Config{Out: bytes.NewBuffer(nil), Err: bytes.NewBuffer(nil)},
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
		app := New(Config{Out: bytes.NewBuffer(nil), Err: bytes.NewBuffer(nil)},
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
	app := New(Config{Out: bytes.NewBuffer(nil), Err: bytes.NewBuffer(nil)})
	cs, err := app.fetchCertsByProtocol(context.Background(), "invalid", "h", "p", "h:p")
	if err == nil || len(cs) != 0 {
		t.Fatalf("expected error for invalid protocol, got err=%v len=%d", err, len(cs))
	}

	// Test with protocol error response
	errorApp := New(Config{Out: bytes.NewBuffer(nil), Err: bytes.NewBuffer(nil)},
		WithDialer(fakeDialer{script: func(conn net.Conn) {
			w := bufio.NewWriter(conn)
			// Send error response instead of expected greeting
			io.WriteString(w, "-ERR Server error\r\n")
			w.Flush()
			conn.Close()
		}}),
	)
	cs, err = errorApp.fetchCertsByProtocol(context.Background(), "pop3", "h", "p", "h:p")
	if err == nil || len(cs) != 0 {
		t.Fatalf("expected protocol error, got err=%v len=%d", err, len(cs))
	}
}

func TestFetchTLSOverHTTP_Direct(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{0x1}}
	app := New(Config{Out: bytes.NewBuffer(nil), Err: bytes.NewBuffer(nil)},
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
	},
		WithDialer(fakeDialer{script: func(conn net.Conn) {
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			if strings.Contains(string(buf[:n]), "CONNECT example.com:443 HTTP/1.1") &&
				strings.Contains(string(buf[:n]), "Proxy-Authorization: Basic") {
				wroteCONNECT = true
			}
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
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
	},
		WithDialer(fakeDialer{script: func(conn net.Conn) {
			buf := make([]byte, 4096)
			conn.Read(buf)
			// Return a proxy error response
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			conn.Close()
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

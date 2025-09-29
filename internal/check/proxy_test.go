package check

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// instrumentedDialer simulates a dialer that behaves differently on the first
// and subsequent calls. The counter is stored externally so tests can observe it.
type instrumentedDialer struct {
	calls *int32
}

func (d instrumentedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	n := atomic.AddInt32(d.calls, 1)
	if n == 1 {
		srv, cli := net.Pipe()
		// server side: close immediately to cause client-side handshake error
		go func() { _ = srv.Close() }()
		return cli, nil
	}
	return nil, fmt.Errorf("simulated redial error")
}

func TestHTTPProxyConnector_encodeBasicAuth(t *testing.T) {
	// Simple table-driven test for encodeBasicAuth
	pc := &HTTPProxyConnector{}

	cases := []struct {
		user string
		pass string
		want string
	}{
		{"user", "pass", base64.StdEncoding.EncodeToString([]byte("user:pass"))},
		{"", "", base64.StdEncoding.EncodeToString([]byte(":"))},
		{"u@host", "p:word", base64.StdEncoding.EncodeToString([]byte("u@host:p:word"))},
	}

	for _, c := range cases {
		got := pc.encodeBasicAuth(c.user, c.pass)
		if got != c.want {
			t.Fatalf("encodeBasicAuth(%q,%q) = %q, want %q", c.user, c.pass, got, c.want)
		}
	}
}

func TestBasicAuth_injectableBase64Encode(t *testing.T) {
	// Save original and restore
	orig := base64Encode
	defer func() { base64Encode = orig }()

	// Inject a deterministic encoder
	base64Encode = func(s string) string { return "ENC(" + s + ")" }

	if want := "ENC(user:pass)"; basicAuth("user", "pass") != want {
		t.Fatalf("basicAuth with injected encoder = %q, want %q", basicAuth("user", "pass"), want)
	}
}

// TestWrapConnectionInTLS_Fallback simulates a TLS verification failure on the
// first handshake and verifies that the insecure fallback path is used.
func TestWrapConnectionInTLS_Fallback(t *testing.T) {
	t.Parallel()

	// Use an instrumented dialer: first call returns a client side of a pipe whose
	// server end immediately closes (causing the client's TLS handshake to fail).
	// Second call returns an explicit error, which should trigger the
	// "failed to re-dial" path in wrapConnectionInTLS.
	var calls int32
	app := New(Config{Out: nil, Err: nil, HTTPClient: noNetworkHTTPClient(), HTTPSProxy: parseURLOrPanic("https://proxy.local:443")},
		WithDialer(instrumentedDialer{calls: &calls}),
		WithTLSFactory(simTLSFactory{}),
	)

	pc := NewProxyConnector(app)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	clientConn, err := app.dialer.DialContext(ctx, "tcp", "proxy.local:443")
	if err != nil {
		t.Fatalf("initial dial failed: %v", err)
	}
		defer func() { _ = clientConn.Close() }()

	_, err = pc.wrapConnectionInTLS(ctx, clientConn)
	if err == nil || !strings.Contains(err.Error(), "failed to re-dial") {
		t.Fatalf("expected re-dial error path, got err=%v, calls=%d", err, atomic.LoadInt32(&calls))
	}
}

// TestValidateCONNECTResponse_Malformed tests various malformed or non-200
// CONNECT responses to ensure validateCONNECTResponse correctly returns errors.
func TestValidateCONNECTResponse_Malformed(t *testing.T) {
	t.Parallel()

	pc := &HTTPProxyConnector{}

	cases := []struct{
		name string
		resp string
	}{
		{"empty", ""},
		{"nonhttp", "NOTHTTP/1.0 200 OK\r\n\r\n"},
		{"nonumeric", "HTTP/1.1 twohundred OK\r\n\r\n"},
		{"not200", "HTTP/1.1 502 Bad Gateway\r\n\r\n"},
		{"noeol", "HTTP/1.1 200 Connection Established"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, w := net.Pipe()
			// write response from "server" side
			go func() {
				if c.resp != "" {
					_, _ = w.Write([]byte(c.resp))
				}
				_ = w.Close()
			}()

			defer func() { _ = r.Close() }()

			if err := pc.validateCONNECTResponse(r); err == nil {
				t.Fatalf("expected error for case %s, got nil", c.name)
			}
		})
	}
}

// TestSendCONNECTRequest_ProxyAuth ensures the Proxy-Authorization header is
// included when proxy userinfo is present and omitted otherwise.
func TestSendCONNECTRequest_ProxyAuth(t *testing.T) {
	t.Parallel()

	// Set up an app with config containing proxy credentials
	app := New(Config{})
	pc := NewProxyConnector(app)

	// helper to capture what the client writes and respond with 200
	runCase := func(userInfo string) (written string, err error) {
		serverConn, clientConn := net.Pipe()
		// server goroutine: read request then write a 200 response
		go func() {
			defer func() { _ = serverConn.Close() }()
			buf := make([]byte, 4096)
			n, _ := serverConn.Read(buf)
			written = string(buf[:n])
			// Write a successful CONNECT response
			_, _ = serverConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		}()

		// adjust app config userinfo
		if userInfo != "" {
			u, _ := url.Parse("http://" + userInfo + "@proxy")
			app.cfg.HTTPSProxy = u
		} else {
			app.cfg.HTTPSProxy = &url.URL{Host: "proxy:8080", Scheme: "http"}
		}

		// use the clientConn as the connection to send request
		err = pc.sendCONNECTRequest(clientConn, "target:443")
		// close client connection after send; ignore close error
		_ = clientConn.Close()
		return
	}

	// Case: no credentials
	written, err := runCase("")
	if err != nil {
		t.Fatalf("sendCONNECTRequest no-creds returned error: %v", err)
	}
	if strings.Contains(written, "Proxy-Authorization:") {
		t.Fatalf("unexpected Proxy-Authorization header present: %q", written)
	}

	// Case: with credentials
	written, err = runCase("user:pass")
	if err != nil {
		t.Fatalf("sendCONNECTRequest with-creds returned error: %v", err)
	}
	if !strings.Contains(written, "Proxy-Authorization: Basic ") {
		t.Fatalf("expected Proxy-Authorization header, got: %q", written)
	}
}

// TestSendCONNECTRequest_Format verifies the CONNECT request line and Host header format.
func TestSendCONNECTRequest_Format(t *testing.T) {
	t.Parallel()

	app := New(Config{})
	pc := NewProxyConnector(app)

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	// Ensure proxy URL is present so sendCONNECTRequest doesn't deref nil
	app.cfg.HTTPSProxy = &url.URL{Host: "proxy:8080", Scheme: "http"}

	// Server reads request and returns 200
	go func() {
	defer func() { _ = serverConn.Close() }()
		buf := make([]byte, 4096)
		n, _ := serverConn.Read(buf)
		req := string(buf[:n])
		if !strings.HasPrefix(req, "CONNECT target:443 HTTP/1.1") {
			t.Errorf("CONNECT line malformed: %q", req)
		}
		if !strings.Contains(req, "Host: target:443") {
			t.Errorf("Host header missing or malformed: %q", req)
		}
		_, _ = serverConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}()

	if err := pc.sendCONNECTRequest(clientConn, "target:443"); err != nil {
		t.Fatalf("sendCONNECTRequest returned error: %v", err)
	}
}

// TestValidateCONNECTResponse_PartialRead simulates a truncated status line to
// ensure validateCONNECTResponse returns an error rather than hanging.
func TestValidateCONNECTResponse_PartialRead(t *testing.T) {
	t.Parallel()

	pc := &HTTPProxyConnector{}
	r, w := net.Pipe()
	defer func() { _ = r.Close() }()

	// Write partial status line and close
	go func() {
		_, _ = w.Write([]byte("HTTP/1.1 200"))
		_ = w.Close()
	}()

	if err := pc.validateCONNECTResponse(r); err == nil {
		t.Fatalf("expected error for partial response, got nil")
	}
}

// TestValidateCONNECTResponse_Success verifies that a well-formed response is accepted.
func TestValidateCONNECTResponse_Success(t *testing.T) {
	t.Parallel()

	pc := &HTTPProxyConnector{}
	r, w := net.Pipe()
	defer func() { _ = r.Close() }()

	go func() {
		defer w.Close()
		_, _ = w.Write([]byte("HTTP/1.1 200 Connection Established\r\nSome-Header: val\r\n\r\n"))
	}()

	if err := pc.validateCONNECTResponse(r); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

// TestSendCONNECTRequest_LongCredentials ensures very long credentials are
// encoded and included without causing buffer/formatting issues.
func TestSendCONNECTRequest_LongCredentials(t *testing.T) {
	t.Parallel()

	app := New(Config{})
	pc := NewProxyConnector(app)

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	// Provide a very long username and password
	longUser := strings.Repeat("u", 1024)
	longPass := strings.Repeat("p", 1024)
	u, _ := url.Parse("http://" + longUser + ":" + longPass + "@proxy")
	app.cfg.HTTPSProxy = u

	// Server reads request and ensures Proxy-Authorization header present and decodable
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 8192)
		n, _ := serverConn.Read(buf)
		req := string(buf[:n])
		if !strings.Contains(req, "Proxy-Authorization: Basic ") {
			t.Errorf("expected Proxy-Authorization header, got: %q", req)
			return
		}
		// Extract and decode the auth token
		idx := strings.Index(req, "Proxy-Authorization: Basic ")
		if idx == -1 {
			return
		}
		token := strings.Fields(req[idx:])[2]
		dec, derr := base64.StdEncoding.DecodeString(token)
		if derr != nil {
			t.Errorf("failed to base64-decode token: %v", derr)
			return
		}
		if string(dec) != longUser+":"+longPass {
			t.Errorf("decoded credentials mismatch; len=%d", len(dec))
		}
		_, _ = serverConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}()

	if err := pc.sendCONNECTRequest(clientConn, "target:443"); err != nil {
		t.Fatalf("sendCONNECTRequest returned error: %v", err)
	}
}

// TestValidateCONNECTResponse_NoFinalBlankLine simulates a response where the
// status line and headers are sent but the final blank line is missing; the
// function should error rather than block forever.
func TestValidateCONNECTResponse_NoFinalBlankLine(t *testing.T) {
	t.Parallel()

	pc := &HTTPProxyConnector{}
	r, w := net.Pipe()
	defer func() { _ = r.Close() }()

	go func() {
		defer w.Close()
		// Send status and a header but omit the terminating CRLF CRLF
		_, _ = w.Write([]byte("HTTP/1.1 200 Connection Established\r\nSome-Header: val\r\n"))
		// Close without sending final blank line
	}()

	if err := pc.validateCONNECTResponse(r); err == nil {
		t.Fatalf("expected error for missing final blank line, got nil")
	}
}

// TestValidateCONNECTResponse_LongHeader verifies that very long header lines
// are handled correctly (do not cause buffer issues) and a proper final blank
// line allows successful validation.
func TestValidateCONNECTResponse_LongHeader(t *testing.T) {
	t.Parallel()

	pc := &HTTPProxyConnector{}
	r, w := net.Pipe()
	defer func() { _ = r.Close() }()

	go func() {
		defer w.Close()
		longVal := strings.Repeat("x", 10_000)
		_, _ = w.Write([]byte("HTTP/1.1 200 Connection Established\r\n"))
		_, _ = w.Write([]byte("X-Long-Header: " + longVal + "\r\n"))
		_, _ = w.Write([]byte("\r\n"))
	}()

	if err := pc.validateCONNECTResponse(r); err != nil {
		t.Fatalf("expected success for long header, got error: %v", err)
	}
}

// TestValidateCONNECTResponse_LFOnly ensures responses using only LF line
// endings are accepted by the parser (ReadString handles '\n').
func TestValidateCONNECTResponse_LFOnly(t *testing.T) {
	t.Parallel()

	pc := &HTTPProxyConnector{}
	r, w := net.Pipe()
	defer r.Close()

	go func() {
		defer w.Close()
		_, _ = w.Write([]byte("HTTP/1.1 200 Connection Established\nSome-Header: val\n\n"))
	}()

	if err := pc.validateCONNECTResponse(r); err != nil {
		t.Fatalf("expected success for LF-only response, got error: %v", err)
	}
}

func TestResolveProxyAddress_DefaultPortSelection(t *testing.T) {
	app := New(Config{})
	pc := NewProxyConnector(app)

	// No port, http scheme -> default 80
	app.cfg.HTTPSProxy = &url.URL{Host: "proxy.local", Scheme: "http"}
	if got := pc.resolveProxyAddress(); !strings.HasSuffix(got, ":80") {
		t.Fatalf("expected default :80, got %q", got)
	}

	// No port, https scheme -> default 443
	app.cfg.HTTPSProxy = &url.URL{Host: "secureproxy.local", Scheme: "https"}
	if got := pc.resolveProxyAddress(); !strings.HasSuffix(got, ":443") {
		t.Fatalf("expected default :443, got %q", got)
	}
}

func TestResolveProxyAddress_PreservePort(t *testing.T) {
	app := New(Config{})
	pc := NewProxyConnector(app)

	app.cfg.HTTPSProxy = &url.URL{Host: "proxy:8080", Scheme: "http"}
	if got := pc.resolveProxyAddress(); got != "proxy:8080" {
		t.Fatalf("expected proxy:8080, got %q", got)
	}
}

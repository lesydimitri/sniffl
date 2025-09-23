// sniffl/app.go
package sniffl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Target struct {
	HostPort string
	Protocol string
}

type Config struct {
	ExportMode      string // "", "single", "bundle", "full_bundle"
	DNSExport       io.Writer
	HTTPSProxy      *url.URL
	Verbose         bool
	TimeNow         func() time.Time
	Out             io.Writer
	Err             io.Writer
	HTTPClient      *http.Client
	FileOpener      func(name string) (io.ReadCloser, error) // for -F
	FileCreator     func(name string) (io.WriteCloser, error)
	CacheDir        func() (string, error)
	TrustedCABundle string // override path or empty to fetch
	CABundleURL     string
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type TLSClientFactory interface {
	Client(conn net.Conn, cfg *tls.Config) TLSConn
}

type TLSConn interface {
	HandshakeContext(ctx context.Context) error
	ConnectionState() tls.ConnectionState
	Close() error
}

// Defaults
type stdDialer struct{ d net.Dialer }

func (s stdDialer) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	return s.d.DialContext(ctx, n, a)
}

type stdTLSFactory struct{}

func (stdTLSFactory) Client(c net.Conn, cfg *tls.Config) TLSConn { return tls.Client(c, cfg) }

// App owns dependencies and state for a run.
type App struct {
	cfg        Config
	dialer     Dialer
	tlsFactory TLSClientFactory
	logger     *log.Logger
	allCerts   []*x509.Certificate
	dnsNames   map[string]struct{}
}

func (a *App) debugf(format string, args ...interface{}) {
	if a.cfg.Verbose {
		a.logger.Printf("[DEBUG] "+format, args...)
	}
}

func New(cfg Config, opts ...Option) *App {
	a := &App{
		cfg:        cfg,
		dialer:     stdDialer{},
		tlsFactory: stdTLSFactory{},
		logger:     log.New(cfg.Err, "", 0),
		dnsNames:   make(map[string]struct{}),
	}
	for _, o := range opts {
		o(a)
	}
	if a.cfg.TimeNow == nil {
		a.cfg.TimeNow = time.Now
	}
	if a.cfg.HTTPClient == nil {
		a.cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return a
}

type Option func(*App)

func WithDialer(d Dialer) Option               { return func(a *App) { a.dialer = d } }
func WithTLSFactory(f TLSClientFactory) Option { return func(a *App) { a.tlsFactory = f } }
func WithLogger(l *log.Logger) Option          { return func(a *App) { a.logger = l } }

// Run processes targets and performs export per config.
func (a *App) Run(ctx context.Context, targets []Target) error {
	for _, t := range targets {
		if !isValidHostPort(t.HostPort) {
			fmt.Fprintf(a.cfg.Out, "[-] Invalid host:port format: %s (skipped)\n", t.HostPort)
			continue
		}
		host, port, _ := net.SplitHostPort(t.HostPort)
		proto := a.resolveProtocol(t.Protocol, port, t.HostPort)
		certs, err := a.fetchCertsByProtocol(ctx, proto, host, port, t.HostPort)
		if err != nil {
			fmt.Fprintf(a.cfg.Out, "[-] Failed to fetch certs from %s (protocol %s): %v\n", t.HostPort, proto, err)
			continue
		}
		a.displayCertReport(t.HostPort, certs)
		a.recordDNSNames(certs)
		if a.cfg.ExportMode == "single" {
			_ = a.exportCertsSingle(certs, host) // errors printed inside
		}
		if a.cfg.ExportMode == "bundle" || a.cfg.ExportMode == "full_bundle" {
			a.allCerts = append(a.allCerts, certs...)
		}
	}
	return a.finalizeExport(ctx)
}

func (a *App) resolveProtocol(proto, port, hostPort string) string {
	if proto != "" && supportedProtocols[proto] {
		return proto
	}
	return guessProtocol(port)
}

var supportedProtocols = map[string]bool{
	"smtp": true, "imap": true, "pop3": true, "http": true, "none": true,
}

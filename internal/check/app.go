package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/lesydimitri/sniffl/internal/logging"
	"github.com/lesydimitri/sniffl/internal/shared"
)
type Config struct {
	ExportMode      string // "", "single", "bundle", "full_bundle"
	DNSExport       io.Writer
	HTTPSProxy      *url.URL
	Verbose         bool
	Concurrency     int // number of concurrent operations (default: 1 for sequential)
	Out             io.Writer
	Err             io.Writer
	HTTPClient      *http.Client
	FileCreator     func(name string) (io.WriteCloser, error)
	CacheDir        func() (string, error)
	TrustedCABundle string // override path or empty to fetch
	CABundleURL     string
	Logger          *logging.Logger // structured logger
}

// Dialer abstracts TCP dialing.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// TLSClientFactory creates TLS client connections from a net.Conn.
type TLSClientFactory interface {
	Client(conn net.Conn, cfg *tls.Config) TLSConn
}

// TLSConn is the minimal TLS client interface used by App.
type TLSConn interface {
	HandshakeContext(ctx context.Context) error
	ConnectionState() tls.ConnectionState
	Close() error
}

// Default implementations.
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
	logger     *logging.Logger
	allCerts   []*x509.Certificate
	dnsNames   map[string]struct{}
}

// New constructs an App with sensible defaults, applying any options.
func New(cfg Config, opts ...Option) *App {
	a := &App{
		cfg:        cfg,
		dialer:     stdDialer{},
		tlsFactory: stdTLSFactory{},
		logger:     cfg.Logger,
		dnsNames:   make(map[string]struct{}),
	}
	
	// Fallback to a basic logger if none provided
	if a.logger == nil {
		a.logger = logging.New("info", "text", cfg.Err)
	}
	
	for _, o := range opts {
		o(a)
	}
	if a.cfg.HTTPClient == nil {
		a.cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return a
}

// Option configures an App.
type Option func(*App)

// WithDialer sets the network dialer used by the app.
func WithDialer(d Dialer) Option { return func(a *App) { a.dialer = d } }

// WithTLSFactory sets the TLS client factory used by the app.
func WithTLSFactory(f TLSClientFactory) Option { return func(a *App) { a.tlsFactory = f } }

// WithLogger sets the logger used by the app.
func WithLogger(l *logging.Logger) Option { return func(a *App) { a.logger = l } }

// Run processes targets and performs export per config.
func (a *App) Run(ctx context.Context, targets []shared.Target) error {
	a.logger.Info("Starting certificate check", "targets", len(targets), "concurrency", a.cfg.Concurrency)
	
	// Determine concurrency level (default to 1 if not set)
	concurrency := a.cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	
	// If concurrency is 1, use sequential processing for simplicity
	if concurrency == 1 {
		return a.runSequential(ctx, targets)
	}
	
	// Use concurrent processing
	return a.runConcurrent(ctx, targets, concurrency)
}

// runSequential processes targets one by one (original behavior)
func (a *App) runSequential(ctx context.Context, targets []shared.Target) error {
	for _, t := range targets {
		if err := a.processTarget(ctx, t); err != nil {
			// Continue processing other targets even if one fails
			continue
		}
	}
	
	a.logger.Info("Finalizing export", "mode", a.cfg.ExportMode)
	return a.finalizeExport(ctx)
}

// runConcurrent processes targets concurrently with specified concurrency level
func (a *App) runConcurrent(ctx context.Context, targets []shared.Target, concurrency int) error {
	// Channel to send targets to workers
	targetChan := make(chan shared.Target, len(targets))
	
	// WaitGroup to wait for all workers to complete
	var wg sync.WaitGroup
	
	// Mutex to protect shared data (allCerts, dnsNames)
	var mu sync.Mutex
	
	// Start worker goroutines
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			a.logger.Debug("Worker started", "worker_id", workerID)
			
			for target := range targetChan {
				select {
				case <-ctx.Done():
					a.logger.Debug("Worker cancelled", "worker_id", workerID)
					return
				default:
					// Process target and handle shared data access
					if err := a.processTargetConcurrent(ctx, target, &mu); err != nil {
						// Continue processing other targets even if one fails
						continue
					}
				}
			}
			
			a.logger.Debug("Worker finished", "worker_id", workerID)
		}(i)
	}
	
	// Send all targets to the channel
	for _, target := range targets {
		targetChan <- target
	}
	close(targetChan)
	
	// Wait for all workers to complete
	wg.Wait()
	
	a.logger.Info("Finalizing export", "mode", a.cfg.ExportMode)
	return a.finalizeExport(ctx)
}

// processTarget handles a single target (used by sequential processing)
func (a *App) processTarget(ctx context.Context, t shared.Target) error {
	targetLogger := a.logger.WithTarget(t.HostPort)
	
	if !shared.IsValidHostPort(t.HostPort) {
		targetLogger.Warn("Invalid host:port format, skipping", "hostport", t.HostPort)
		if _, err := fmt.Fprintf(a.cfg.Out, "[-] Invalid host:port format: %s (skipped)\n", t.HostPort); err != nil {
			targetLogger.Warn("Failed to write output", "error", err)
		}
		return fmt.Errorf("invalid host:port format: %s", t.HostPort)
	}
	
	host, port, _ := net.SplitHostPort(t.HostPort)
	proto := a.resolveProtocol(t.Protocol, port)
	protocolLogger := targetLogger.WithProtocol(proto)
	
	protocolLogger.Debug("Processing target", "host", host, "port", port)
	
	certs, err := a.fetchCertsByProtocol(ctx, proto, host, port, t.HostPort)
	if err != nil {
		protocolLogger.Failure("Failed to fetch certificates", "error", err)
		if _, writeErr := fmt.Fprintf(a.cfg.Out, "[-] Failed to fetch certificates from %s using %s protocol: %v\n", t.HostPort, proto, err); writeErr != nil {
			protocolLogger.Warn("Failed to write output", "error", writeErr)
		}
		return err
	}
	
	protocolLogger.Success("Successfully fetched certificates", "count", len(certs))
	a.displayCertReport(t.HostPort, certs)
	a.recordDNSNames(certs)
	
	if a.cfg.ExportMode == "single" {
		if err := a.exportCertsSingle(certs, host); err != nil {
			protocolLogger.Failure("Failed to export certificates", "error", err)
			if _, writeErr := fmt.Fprintf(a.cfg.Out, "[-] Failed to export certificates for %s: %v\n", t.HostPort, err); writeErr != nil {
				protocolLogger.Warn("Failed to write output", "error", writeErr)
			}
			return err
		}
	}
	if a.cfg.ExportMode == "bundle" || a.cfg.ExportMode == "full_bundle" {
		a.allCerts = append(a.allCerts, certs...)
	}
	
	return nil
}

// processTargetConcurrent handles a single target with mutex protection for shared data
func (a *App) processTargetConcurrent(ctx context.Context, t shared.Target, mu *sync.Mutex) error {
	targetLogger := a.logger.WithTarget(t.HostPort)
	
	if !shared.IsValidHostPort(t.HostPort) {
		targetLogger.Warn("Invalid host:port format, skipping", "hostport", t.HostPort)
		// Protect output writing with mutex
		mu.Lock()
		if _, err := fmt.Fprintf(a.cfg.Out, "[-] Invalid host:port format: %s (skipped)\n", t.HostPort); err != nil {
			targetLogger.Warn("Failed to write output", "error", err)
		}
		mu.Unlock()
		return fmt.Errorf("invalid host:port format: %s", t.HostPort)
	}
	
	host, port, _ := net.SplitHostPort(t.HostPort)
	proto := a.resolveProtocol(t.Protocol, port)
	protocolLogger := targetLogger.WithProtocol(proto)
	
	protocolLogger.Debug("Processing target", "host", host, "port", port)
	
	certs, err := a.fetchCertsByProtocol(ctx, proto, host, port, t.HostPort)
	if err != nil {
		protocolLogger.Failure("Failed to fetch certificates", "error", err)
		// Protect output writing with mutex
		mu.Lock()
		if _, writeErr := fmt.Fprintf(a.cfg.Out, "[-] Failed to fetch certificates from %s using %s protocol: %v\n", t.HostPort, proto, err); writeErr != nil {
			protocolLogger.Warn("Failed to write output", "error", writeErr)
		}
		mu.Unlock()
		return err
	}
	
	protocolLogger.Success("Successfully fetched certificates", "count", len(certs))
	
	// Protect shared data access with mutex
	mu.Lock()
	a.displayCertReport(t.HostPort, certs)
	a.recordDNSNames(certs)
	
	if a.cfg.ExportMode == "single" {
		if err := a.exportCertsSingle(certs, host); err != nil {
			protocolLogger.Failure("Failed to export certificates", "error", err)
			if _, writeErr := fmt.Fprintf(a.cfg.Out, "[-] Failed to export certificates for %s: %v\n", t.HostPort, err); writeErr != nil {
				protocolLogger.Warn("Failed to write output", "error", writeErr)
			}
			mu.Unlock()
			return err
		}
	}
	if a.cfg.ExportMode == "bundle" || a.cfg.ExportMode == "full_bundle" {
		a.allCerts = append(a.allCerts, certs...)
	}
	mu.Unlock()
	
	return nil
}

func (a *App) resolveProtocol(proto, port string) string {
	if proto != "" && shared.SupportedProtocols[proto] {
		return proto
	}
	return shared.GuessProtocol(port)
}

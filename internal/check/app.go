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
	"sync/atomic"
	"time"

	"github.com/lesydimitri/sniffl/internal/logging"
	"github.com/lesydimitri/sniffl/internal/shared"
)

type Config struct {
	ExportMode string // "", "single", "bundle", "full_bundle"
	DNSExport  io.Writer
	HTTPSProxy *url.URL
	Verbose    bool
	// StrictVerify, when true, disables insecure TLS fallback and enforces certificate verification.
	StrictVerify    bool
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
	cfg              Config
	dialer           Dialer
	tlsFactory       TLSClientFactory
	logger           *logging.Logger
	state            *ConcurrentState  // Thread-safe shared state
	errorHandler     *shared.ErrorHandler
	caBundleOnce     sync.Once        // Ensure CA bundle is downloaded only once
	caBundlePath     string           // Cached CA bundle path
	caBundleErr      error            // Cached CA bundle error
	processedTargets int64            // Atomic counter for processed targets
	failedTargets    int64            // Atomic counter for failed targets
}

// New constructs an App with sensible defaults, applying any options.
func New(cfg Config, opts ...Option) *App {
	a := &App{
		cfg:        cfg,
		dialer:     stdDialer{},
		tlsFactory: stdTLSFactory{},
		logger:     cfg.Logger,
		state:      NewConcurrentState(),
	}

	// Fallback to a basic logger if none provided
	if a.logger == nil {
		a.logger = logging.New("info", "text", cfg.Err)
	}

	// Initialize helper utilities
	a.errorHandler = shared.NewErrorHandler(a.logger, cfg.Out)

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

	// Reset counters
	atomic.StoreInt64(&a.processedTargets, 0)
	atomic.StoreInt64(&a.failedTargets, 0)

	// Validate targets before processing
	validTargets := make([]shared.Target, 0, len(targets))
	for _, target := range targets {
		if err := a.validateTarget(target); err != nil {
			_ = a.errorHandler.HandleValidationError(err.Error(), target.HostPort)
			atomic.AddInt64(&a.failedTargets, 1)
			continue
		}
		validTargets = append(validTargets, target)
	}

	if len(validTargets) == 0 {
		a.logger.Warn("No valid targets to process", "total", len(targets), "failed", len(targets))
		return nil // Don't fail completely, just warn
	}

	// Determine concurrency level (default to 1 if not set)
	concurrency := a.cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	// Pre-warm CA bundle in concurrent mode to avoid race conditions
	if concurrency > 1 {
		a.ensureCABundleOnce(ctx)
	}

	// If concurrency is 1, use sequential processing for simplicity
	if concurrency == 1 {
		return a.runSequential(ctx, validTargets)
	}

	// Use concurrent processing
	return a.runConcurrent(ctx, validTargets, concurrency)
}

// validateTarget performs comprehensive target validation
func (a *App) validateTarget(target shared.Target) error {
	if !shared.IsValidHostPort(target.HostPort) {
		return fmt.Errorf("invalid host:port format")
	}

	host, port, err := net.SplitHostPort(target.HostPort)
	if err != nil {
		return fmt.Errorf("failed to parse host:port: %w", err)
	}

	// Validate host (allow private IPs for certificate checking)
	if host == "" {
		return fmt.Errorf("empty host")
	}

	// Validate port
	if port == "" {
		return fmt.Errorf("empty port")
	}

	// Validate protocol if specified
	if target.Protocol != "" && !shared.SupportedProtocols[target.Protocol] {
		return fmt.Errorf("unsupported protocol: %s", target.Protocol)
	}

	return nil
}

// ensureCABundleOnce ensures CA bundle is downloaded only once
func (a *App) ensureCABundleOnce(ctx context.Context) {
	a.caBundleOnce.Do(func() {
		a.caBundlePath, a.caBundleErr = a.ensureCABundle(ctx)
		if a.caBundleErr != nil {
			a.logger.Warn("Failed to ensure CA bundle", "error", a.caBundleErr)
		} else {
			a.logger.Debug("CA bundle ready", "path", a.caBundlePath)
		}
	})
}

// runSequential processes targets one by one (original behavior)
func (a *App) runSequential(ctx context.Context, targets []shared.Target) error {
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			a.logger.Info("Context cancelled, stopping sequential processing")
			break
		}

		if err := a.processTarget(ctx, t); err != nil {
			a.logger.Warn("Failed to process target", "target", t.HostPort, "error", err)
			atomic.AddInt64(&a.failedTargets, 1)
			// Continue processing other targets even if one fails
			continue
		}
		atomic.AddInt64(&a.processedTargets, 1)
	}

	return a.finalizeExportWithStats(ctx)
}

// runConcurrent processes targets concurrently with specified concurrency level
func (a *App) runConcurrent(ctx context.Context, targets []shared.Target, concurrency int) error {
	targetChan := make(chan shared.Target, len(targets))
	var wg sync.WaitGroup
	
	// Use a single output mutex for all output operations
	var outputMu sync.Mutex

	// Start workers
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
					if err := a.processTargetConcurrent(ctx, target, &outputMu); err != nil {
						a.logger.Warn("Failed to process target", "target", target.HostPort, "error", err, "worker_id", workerID)
						atomic.AddInt64(&a.failedTargets, 1)
						continue
					}
					atomic.AddInt64(&a.processedTargets, 1)
				}
			}

			a.logger.Debug("Worker finished", "worker_id", workerID)
		}(i)
	}

	// Send targets to workers
	for _, target := range targets {
		select {
		case targetChan <- target:
		case <-ctx.Done():
			close(targetChan)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(targetChan)
	wg.Wait()

	return a.finalizeExportWithStats(ctx)
}

// processTarget handles a single target (used by sequential processing)
func (a *App) processTarget(ctx context.Context, t shared.Target) error {
	targetLogger := a.logger.WithTarget(t.HostPort)

	host, port, _ := net.SplitHostPort(t.HostPort)
	proto := a.resolveProtocol(t.Protocol, port)
	protocolLogger := targetLogger.WithProtocol(proto)

	protocolLogger.Debug("Processing target", "host", host, "port", port)

	certs, err := a.fetchCertsByProtocol(ctx, proto, host, port, t.HostPort)
	if err != nil {
		return a.errorHandler.HandleNetworkError(fmt.Sprintf("Certificate fetch from %s using %s protocol", t.HostPort, proto), t.HostPort, err)
	}

	protocolLogger.Success("Successfully fetched certificates", "count", len(certs))
	if err := a.DisplayCertificateReport(t.HostPort, certs); err != nil {
		a.logger.Warn("Failed to display certificate report", "target", t.HostPort, "error", err)
	}

	// Process certificates for export and DNS collection
	a.processCertificates(certs, host)

	return nil
}

// processTargetConcurrent handles a single target in concurrent mode
func (a *App) processTargetConcurrent(ctx context.Context, t shared.Target, outputMu *sync.Mutex) error {
	targetLogger := a.logger.WithTarget(t.HostPort)

	host, port, _ := net.SplitHostPort(t.HostPort)
	proto := a.resolveProtocol(t.Protocol, port)
	protocolLogger := targetLogger.WithProtocol(proto)

	protocolLogger.Debug("Processing target", "host", host, "port", port)

	// Fetch certificates without holding any locks
	certs, err := a.fetchCertsByProtocol(ctx, proto, host, port, t.HostPort)
	if err != nil {
		// Protect output writing with dedicated mutex
		outputMu.Lock()
		handledErr := a.errorHandler.HandleNetworkError(fmt.Sprintf("Certificate fetch from %s using %s protocol", t.HostPort, proto), t.HostPort, err)
		outputMu.Unlock()
		return handledErr
	}

	protocolLogger.Success("Successfully fetched certificates", "count", len(certs))

	// Protect output operations
	outputMu.Lock()
	if err := a.DisplayCertificateReport(t.HostPort, certs); err != nil {
		a.logger.Warn("Failed to display certificate report", "target", t.HostPort, "error", err)
	}
	outputMu.Unlock()

	// Process certificates for export and DNS collection (thread-safe)
	a.processCertificates(certs, host)

	return nil
}

// processCertificates handles certificate processing for both sequential and concurrent modes
func (a *App) processCertificates(certs []*x509.Certificate, host string) {
	// Export single certificates if requested
	if a.cfg.ExportMode == "single" {
		if err := a.exportCertsSingle(certs, host); err != nil {
			a.logger.Warn("Failed to export certificates", "host", host, "error", err)
		}
	}

	// Add to bundle if requested
	if a.cfg.ExportMode == "bundle" || a.cfg.ExportMode == "full_bundle" {
		a.state.AddCertificates(certs)
	}
	
	// Record DNS names from certificates (only once)
	a.state.AddDNSNames(certs)
}

// resolveProtocol resolves the protocol with better fallback logic
func (a *App) resolveProtocol(proto, port string) string {
	if proto != "" && shared.SupportedProtocols[proto] {
		return proto
	}
	
	// Enhanced protocol guessing with fallback
	guessed := shared.GuessProtocol(port)
	if guessed != "none" {
		return guessed
	}
	
	// Default fallback based on common ports
	switch port {
	case "443", "8443":
		return "none" // Direct TLS
	case "80", "8080", "8000":
		return "http"
	case "25", "587":
		return "smtp"
	case "143", "993":
		return "imap"
	case "110", "995":
		return "pop3"
	default:
		return "none" // Default to direct TLS
	}
}

// finalizeExportWithStats finalizes export and reports statistics
func (a *App) finalizeExportWithStats(ctx context.Context) error {
	processed := atomic.LoadInt64(&a.processedTargets)
	failed := atomic.LoadInt64(&a.failedTargets)
	
	a.logger.Info("Processing complete", 
		"processed", processed, 
		"failed", failed, 
		"success_rate", fmt.Sprintf("%.1f%%", float64(processed)/float64(processed+failed)*100))

	a.logger.Info("Finalizing export", "mode", a.cfg.ExportMode)
	return a.finalizeExport(ctx)
}

// GetAllCertificates returns all collected certificates (for testing)
func (a *App) GetAllCertificates() []*x509.Certificate {
	return a.state.GetAllCertificates()
}

// GetDNSNames returns all collected DNS names (for testing)
func (a *App) GetDNSNames() []string {
	return a.state.GetDNSNames()
}

// GetProcessingStats returns processing statistics
func (a *App) GetProcessingStats() (processed, failed int64) {
	return atomic.LoadInt64(&a.processedTargets), atomic.LoadInt64(&a.failedTargets)
}

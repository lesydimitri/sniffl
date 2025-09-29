package screenshot

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// AdaptiveConcurrencyManager manages concurrency based on system resources
type AdaptiveConcurrencyManager struct {
	baseConcurrency int
	maxConcurrency  int
	minConcurrency  int
}

// NewAdaptiveConcurrencyManager creates a new adaptive concurrency manager
func NewAdaptiveConcurrencyManager() *AdaptiveConcurrencyManager {
	cpuCount := runtime.NumCPU()

	// Base concurrency on CPU count with reasonable limits
	baseConcurrency := cpuCount
	if baseConcurrency < 2 {
		baseConcurrency = 2 // Minimum for reasonable performance
	} else if baseConcurrency > 16 {
		baseConcurrency = 16 // Cap at 16 to avoid overwhelming systems
	}

	return &AdaptiveConcurrencyManager{
		baseConcurrency: baseConcurrency,
		maxConcurrency:  baseConcurrency * 2, // Allow up to 2x CPU count for burst capacity
		minConcurrency:  1,                   // Minimum concurrency
	}
}

// GetRecommendedConcurrency returns the recommended concurrency level for the given operation
func (acm *AdaptiveConcurrencyManager) GetRecommendedConcurrency(operationType string, targetCount int) int {
	base := acm.baseConcurrency

	// Adjust based on operation type
	switch operationType {
	case "screenshot":
		// Screenshots are memory and CPU intensive
		base = base / 2
		if base < 1 {
			base = 1
		}
	case "connectivity_check":
		// Connectivity checks are network intensive but lightweight
		base = base * 2
		if base > acm.maxConcurrency {
			base = acm.maxConcurrency
		}
	case "batch":
		// Batch operations can use higher concurrency
		base = base * 3 / 2
		if base > acm.maxConcurrency {
			base = acm.maxConcurrency
		}
	}

	// Adjust based on target count
	if targetCount <= 5 {
		// Small batches use fewer resources
		base = base / 2
		if base < acm.minConcurrency {
			base = acm.minConcurrency
		}
	} else if targetCount > 100 {
		// Large batches can benefit from higher concurrency
		base = base + 2
		if base > acm.maxConcurrency {
			base = acm.maxConcurrency
		}
	}

	return base
}

// GetScreenshotConcurrency returns the recommended concurrency for screenshot operations
func (acm *AdaptiveConcurrencyManager) GetScreenshotConcurrency(targetCount int) int {
	return acm.GetRecommendedConcurrency("screenshot", targetCount)
}

// GetConnectivityCheckConcurrency returns the recommended concurrency for connectivity checks
func (acm *AdaptiveConcurrencyManager) GetConnectivityCheckConcurrency(targetCount int) int {
	return acm.GetRecommendedConcurrency("connectivity_check", targetCount)
}

// GetSystemInfo returns information about the system for debugging
func (acm *AdaptiveConcurrencyManager) GetSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"cpu_count":       runtime.NumCPU(),
		"go_max_procs":    runtime.GOMAXPROCS(0),
		"base_concurrency": acm.baseConcurrency,
		"max_concurrency":  acm.maxConcurrency,
		"min_concurrency":  acm.minConcurrency,
	}
}

// ChromePoolConfig represents configuration for Chrome instance pooling
type ChromePoolConfig struct {
	MaxInstances    int
	MaxIdleTime     int
	MaxUseCount     int
	ViewportWidth   int
	ViewportHeight  int
	UserAgent       string
	IdleTimeout     int
	StartupTimeout  int
	ShutdownTimeout int
}

// DefaultChromePoolConfig returns default Chrome pool configuration
func DefaultChromePoolConfig() *ChromePoolConfig {
	return &ChromePoolConfig{
		MaxInstances:    runtime.NumCPU(),
		MaxIdleTime:     300, // 5 minutes
		MaxUseCount:     100, // Max uses before recycling
		ViewportWidth:   1920,
		ViewportHeight:  1080,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		IdleTimeout:     300, // 5 minutes
		StartupTimeout:  30,  // 30 seconds
		ShutdownTimeout: 10,  // 10 seconds
	}
}

// ChromePool interface for managing Chrome instances
type ChromePool interface {
	Get() (ChromeInstance, error)
	Put(ChromeInstance) error
	Close() error
	Stats() PoolStats
}

// ChromeInstance represents a Chrome browser instance
type ChromeInstance interface {
	Navigate(url string) error
	Screenshot() ([]byte, error)
	Close() error
	IsHealthy() bool
	GetUseCount() int
}

// PoolStats provides statistics about the Chrome pool
type PoolStats struct {
	ActiveInstances int
	IdleInstances   int
	TotalCreated    int
	TotalDestroyed  int
}

// MockChromePool is a mock implementation for testing
type MockChromePool struct{}

// NewMockChromePool creates a new mock Chrome pool
func NewMockChromePool() ChromePool {
	return &MockChromePool{}
}

func (m *MockChromePool) Get() (ChromeInstance, error) {
	return &MockChromeInstance{useCount: 0}, nil
}

func (m *MockChromePool) Put(ChromeInstance) error {
	return nil
}

func (m *MockChromePool) Close() error {
	return nil
}

func (m *MockChromePool) Stats() PoolStats {
	return PoolStats{
		ActiveInstances: 1,
		IdleInstances:   0,
		TotalCreated:    1,
		TotalDestroyed:  0,
	}
}

// MockChromeInstance is a mock Chrome instance for testing
type MockChromeInstance struct {
	useCount int
}

func (m *MockChromeInstance) Navigate(url string) error {
	return nil
}

func (m *MockChromeInstance) Screenshot() ([]byte, error) {
	return []byte("mock screenshot data"), nil
}

func (m *MockChromeInstance) Close() error {
	return nil
}

func (m *MockChromeInstance) IsHealthy() bool {
	return true
}

func (m *MockChromeInstance) GetUseCount() int {
	return m.useCount
}


// RealChromePool implements ChromePool with actual Chrome instance management
type RealChromePool struct {
	config        *ChromePoolConfig
	instances     chan ChromeInstance
	activeCount   int
	totalCreated  int
	totalDestroyed int
	chromePath    string
	mu            sync.RWMutex
	closed        bool
}

// NewRealChromePool creates a new Chrome pool with real Chrome instances
func NewRealChromePool(config *ChromePoolConfig, chromePath string) ChromePool {
	pool := &RealChromePool{
		config:     config,
		instances:  make(chan ChromeInstance, config.MaxInstances),
		chromePath: chromePath,
	}
	return pool
}

func (p *RealChromePool) Get() (ChromeInstance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.closed {
		return nil, fmt.Errorf("chrome pool is closed")
	}
	
	// Try to get an existing instance from the pool
	select {
	case instance := <-p.instances:
		if instance.IsHealthy() && instance.GetUseCount() < p.config.MaxUseCount {
			p.activeCount++
			return instance, nil
		}
		// Instance is unhealthy or overused, close it and create a new one
		_ = instance.Close()
		p.totalDestroyed++
	default:
		// No instances available in pool
	}
	
	// Create a new instance
	instance, err := p.createInstance()
	if err != nil {
		return nil, fmt.Errorf("failed to create Chrome instance: %w", err)
	}
	
	p.activeCount++
	p.totalCreated++
	return instance, nil
}

func (p *RealChromePool) Put(instance ChromeInstance) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.closed {
		_ = instance.Close()
		return fmt.Errorf("chrome pool is closed")
	}
	
	p.activeCount--
	
	// Check if instance is still healthy and under use limit
	if instance.IsHealthy() && instance.GetUseCount() < p.config.MaxUseCount {
		// Try to return to pool
		select {
		case p.instances <- instance:
			return nil
		default:
			// Pool is full, close the instance
			_ = instance.Close()
			p.totalDestroyed++
		}
	} else {
		// Instance is unhealthy or overused, close it
		_ = instance.Close()
		p.totalDestroyed++
	}
	
	return nil
}

func (p *RealChromePool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.closed {
		return nil
	}
	
	p.closed = true
	
	// Close all instances in the pool
	close(p.instances)
	for instance := range p.instances {
		_ = instance.Close()
		p.totalDestroyed++
	}
	
	return nil
}

func (p *RealChromePool) Stats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	return PoolStats{
		ActiveInstances: p.activeCount,
		IdleInstances:   len(p.instances),
		TotalCreated:    p.totalCreated,
		TotalDestroyed:  p.totalDestroyed,
	}
}

func (p *RealChromePool) createInstance() (ChromeInstance, error) {
	return NewRealChromeInstance(p.chromePath, p.config)
}

// RealChromeInstance implements ChromeInstance with actual Chrome browser control
type RealChromeInstance struct {
	ctx        context.Context
	cancel     context.CancelFunc
	useCount   int
	healthy    bool
	config     *ChromePoolConfig
	mu         sync.Mutex
	createdAt  time.Time
}

// NewRealChromeInstance creates a new Chrome instance
func NewRealChromeInstance(chromePath string, config *ChromePoolConfig) (ChromeInstance, error) {
	// Create Chrome options with comprehensive flags to suppress warnings and improve stability
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.WindowSize(config.ViewportWidth, config.ViewportHeight),
		chromedp.UserAgent(config.UserAgent),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		// Suppress network-related warnings and errors
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-features", "VizDisplayCompositor,PrivateNetworkAccessSendPreflights,PrivateNetworkAccessRespectPreflightResults"),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("ignore-ssl-errors", true),
		chromedp.Flag("ignore-certificate-errors-spki-list", true),
		chromedp.Flag("allow-running-insecure-content", true),
		// Reduce logging noise
		chromedp.Flag("log-level", "3"), // Only fatal errors
		chromedp.Flag("silent", true),
		chromedp.Flag("disable-logging", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-sync", true),
		// Performance optimizations
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-client-side-phishing-detection", true),
		chromedp.Flag("disable-component-extensions-with-background-pages", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
	)

	// Create allocator context
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	
	// Create Chrome context with timeout and disable logging
	ctx, ctxCancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))
	
	// Combine cancel functions
	combinedCancel := func() {
		ctxCancel()
		cancel()
	}

	instance := &RealChromeInstance{
		ctx:       ctx,
		cancel:    combinedCancel,
		useCount:  0,
		healthy:   true,
		config:    config,
		createdAt: time.Now(),
	}

	// Test the instance by navigating to about:blank
	if err := chromedp.Run(ctx, chromedp.Navigate("about:blank")); err != nil {
		combinedCancel()
		return nil, fmt.Errorf("failed to initialize Chrome instance: %w", err)
	}

	return instance, nil
}

func (c *RealChromeInstance) Navigate(url string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.healthy {
		return fmt.Errorf("chrome instance is not healthy")
	}
	
	// Use shorter timeout for initial navigation to fail fast on connection issues
	timeout := 10 * time.Second
	if strings.Contains(url, "https://") {
		// HTTPS connections might need slightly more time for TLS handshake
		timeout = 15 * time.Second
	}
	
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()
	
	err := chromedp.Run(ctx, chromedp.Navigate(url))
	if err != nil {
		// Check if it's a connection error (fail fast) vs other errors
		if isConnectionError(err) {
			return fmt.Errorf("connection failed: %w", err)
		}
		c.healthy = false
		return fmt.Errorf("navigation failed: %w", err)
	}
	
	return nil
}

// isConnectionError checks if the error is a connection-related error that should fail fast
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	connectionErrors := []string{
		"connection refused",
		"connection closed",
		"connection reset",
		"no route to host",
		"host unreachable",
		"timeout",
		"net::err_connection_refused",
		"net::err_connection_closed",
		"net::err_connection_reset",
		"net::err_timed_out",
		"net::err_address_unreachable",
	}
	
	for _, connErr := range connectionErrors {
		if strings.Contains(errStr, connErr) {
			return true
		}
	}
	return false
}

func (c *RealChromeInstance) Screenshot() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.healthy {
		return nil, fmt.Errorf("chrome instance is not healthy")
	}
	
	// Take screenshot with timeout
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	
	var buf []byte
	err := chromedp.Run(ctx, 
		chromedp.Sleep(2*time.Second), // Wait for page to load
		chromedp.FullScreenshot(&buf, 90), // 90% quality
	)
	
	if err != nil {
		c.healthy = false
		return nil, fmt.Errorf("screenshot failed: %w", err)
	}
	
	c.useCount++
	return buf, nil
}

func (c *RealChromeInstance) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.healthy = false
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	return nil
}

func (c *RealChromeInstance) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Check if instance is healthy and not too old
	maxAge := time.Duration(c.config.MaxIdleTime) * time.Second
	if time.Since(c.createdAt) > maxAge {
		c.healthy = false
	}
	
	return c.healthy
}

func (c *RealChromeInstance) GetUseCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.useCount
}


package check

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const caBundleURL = "https://curl.se/ca/cacert.pem"

// OS detection functions
func isWindows() bool {
	return runtime.GOOS == "windows"
}

func isDarwin() bool {
	return runtime.GOOS == "darwin"
}

var (
	// Global CA bundle cache to prevent multiple downloads
	caBundleCache struct {
		sync.RWMutex
		path      string
		certs     []*x509.Certificate
		timestamp time.Time
		err       error
	}
)

func (a *App) fetchAndAppendCABundle(ctx context.Context, certs *[]*x509.Certificate) error {
	// Load system certificates first
	if err := a.loadSystemCertificates(certs); err != nil {
		a.logger.Debug("Failed to load system certificates", "error", err)
	}

	// Get CA bundle (with caching and race condition protection)
	bundleCerts, err := a.getCachedCABundle(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CA bundle: %w", err)
	}

	*certs = append(*certs, bundleCerts...)
	return nil
}

// loadSystemCertificates loads certificates from system certificate stores
func (a *App) loadSystemCertificates(certs *[]*x509.Certificate) error {
	var errors []error

	if isWindows() {
		if winRoots, err := a.getWindowsCertStoreRoots(); err == nil {
			*certs = append(*certs, winRoots...)
			a.logger.Debug("Loaded Windows certificate store", "count", len(winRoots))
		} else {
			errors = append(errors, fmt.Errorf("windows cert store: %w", err))
		}
	}

	if isDarwin() {
		if macRoots, err := a.getMacOSCertStoreRoots(); err == nil {
			*certs = append(*certs, macRoots...)
			a.logger.Debug("Loaded macOS certificate store", "count", len(macRoots))
		} else {
			errors = append(errors, fmt.Errorf("macOS cert store: %w", err))
		}
	}

	// Return first error if any, but don't fail completely
	if len(errors) > 0 {
		a.logger.Debug("Some system certificate stores failed to load", "errors", len(errors))
		return errors[0]
	}

	return nil
}

// getCachedCABundle gets CA bundle with caching and race condition protection
func (a *App) getCachedCABundle(ctx context.Context) ([]*x509.Certificate, error) {
	// If the user provided a local TrustedCABundle path, prefer that and
	// bypass the global network-backed cache. This ensures tests (and users)
	// that specify a local bundle are not affected by previous cache errors
	// or network activity.
	if a.cfg.TrustedCABundle != "" {
		a.logger.Debug("Using configured TrustedCABundle path directly, bypassing global cache", "path", a.cfg.TrustedCABundle)
		certs, err := loadTrustedCABundle(a.cfg.TrustedCABundle)
		if err != nil {
			return nil, err
		}
		return certs, nil
	}
	// Check cache first (read lock)
	caBundleCache.RLock()
	if caBundleCache.certs != nil && time.Since(caBundleCache.timestamp) < time.Hour {
		certs := make([]*x509.Certificate, len(caBundleCache.certs))
		copy(certs, caBundleCache.certs)
		caBundleCache.RUnlock()
		a.logger.Debug("Using cached CA bundle", "count", len(certs))
		return certs, nil
	}
	if caBundleCache.err != nil && time.Since(caBundleCache.timestamp) < 5*time.Minute {
		err := caBundleCache.err
		caBundleCache.RUnlock()
		return nil, err
	}
	caBundleCache.RUnlock()

	// Need to update cache (write lock)
	caBundleCache.Lock()
	defer caBundleCache.Unlock()

	// Double-check after acquiring write lock
	if caBundleCache.certs != nil && time.Since(caBundleCache.timestamp) < time.Hour {
		certs := make([]*x509.Certificate, len(caBundleCache.certs))
		copy(certs, caBundleCache.certs)
		a.logger.Debug("Using cached CA bundle (double-check)", "count", len(certs))
		return certs, nil
	}

	// Update cache
	path, err := a.ensureCABundle(ctx)
	caBundleCache.timestamp = time.Now()
	if err != nil {
		caBundleCache.err = err
		caBundleCache.certs = nil
		return nil, err
	}

	certs, err := loadTrustedCABundle(path)
	if err != nil {
		caBundleCache.err = err
		caBundleCache.certs = nil
		return nil, err
	}

	// Update cache with successful result
	caBundleCache.path = path
	caBundleCache.certs = make([]*x509.Certificate, len(certs))
	copy(caBundleCache.certs, certs)
	caBundleCache.err = nil

	a.logger.Debug("Updated CA bundle cache", "count", len(certs))
	return certs, nil
}

func (a *App) ensureCABundle(ctx context.Context) (string, error) {
	// If a local bundle path is supplied, use it verbatim.
	if a.cfg.TrustedCABundle != "" {
		a.logger.Debug("Using provided CA bundle path", "path", a.cfg.TrustedCABundle)
		return a.cfg.TrustedCABundle, nil
	}

	// Resolve cache directory, using injected override if present.
	dir, err := a.cacheDir()
	if err != nil {
		return "", fmt.Errorf("failed to determine cache directory: %w", err)
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create cache directory: %w", err)
	}

	dest := filepath.Join(dir, "cacert.pem")
	etagPath := filepath.Join(dir, "cacert.etag")
	lockPath := filepath.Join(dir, "cacert.lock")

	// Use file-based locking to prevent concurrent downloads
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Another process is downloading, wait and use existing file
			a.logger.Debug("Another process is downloading CA bundle, waiting...")
			return a.waitForCABundle(dest, 30*time.Second)
		}
		return "", fmt.Errorf("failed to create lock file: %w", err)
	}
	defer func() {
		_ = lockFile.Close()
		_ = os.Remove(lockPath)
	}()

	// Check if existing bundle is recent enough
	if stat, err := os.Stat(dest); err == nil {
		if time.Since(stat.ModTime()) < 24*time.Hour {
			a.logger.Debug("Using existing recent CA bundle", "path", dest, "age", time.Since(stat.ModTime()))
			return dest, nil
		}
	}

	// Read existing ETag if any.
	var etag string
	data, readErr := os.ReadFile(etagPath)
	if readErr == nil {
		etag = string(data)
		a.logger.Debug("Found existing ETag for CA bundle", "etag", etag)
	}

	// Choose URL: injected override or the default curl CA bundle.
	url := caBundleURL
	if a.cfg.CABundleURL != "" {
		url = a.cfg.CABundleURL
	}
	a.logger.Debug("Fetching CA bundle", "url", url)

	// Build request with conditional header and timeout
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request for CA bundle: %w", err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	req.Header.Set("User-Agent", "sniffl-certificate-tool/1.0")

	// Use injected client for testability with timeout
	client := a.cfg.HTTPClient
	if client.Timeout == 0 {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch CA bundle from %s: %w", url, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			a.logger.Debug("Warning: failed to close response body", "error", err)
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		a.logger.Debug("Downloading new CA bundle", "destination", dest)

		// Write to temporary file first
		tempDest := dest + ".tmp"
		f, err := a.cfg.FileCreator(tempDest)
		if err != nil {
			return "", fmt.Errorf("failed to create temporary CA bundle file %s: %w", tempDest, err)
		}

		// Copy with size limit to prevent DoS
		written, err := io.CopyN(f, resp.Body, 10*1024*1024) // 10MB limit
		closeErr := f.Close()

		if err != nil && err != io.EOF {
			_ = os.Remove(tempDest)
			return "", fmt.Errorf("failed to download CA bundle to %s: %w", tempDest, err)
		}
		if closeErr != nil {
			_ = os.Remove(tempDest)
			return "", fmt.Errorf("failed to close CA bundle file: %w", closeErr)
		}

		// Validate the downloaded bundle
		if err := a.validateCABundle(tempDest); err != nil {
			_ = os.Remove(tempDest)
			return "", fmt.Errorf("downloaded CA bundle validation failed: %w", err)
		}

		// Atomically move to final location
		if err := os.Rename(tempDest, dest); err != nil {
			_ = os.Remove(tempDest)
			return "", fmt.Errorf("failed to move CA bundle to final location: %w", err)
		}

		a.logger.Debug("Successfully downloaded CA bundle", "size", written, "destination", dest)

		// Save ETag for future requests
		if newEtag := resp.Header.Get("ETag"); newEtag != "" {
			if err := os.WriteFile(etagPath, []byte(newEtag), 0o600); err != nil {
				a.logger.Debug("Warning: failed to save ETag", "path", etagPath, "error", err)
			}
		}

	case http.StatusNotModified:
		a.logger.Debug("CA bundle is up to date (304 Not Modified)")
		// Update modification time to reset cache timer
		now := time.Now()
		if err := os.Chtimes(dest, now, now); err != nil {
			a.logger.Debug("Warning: failed to update CA bundle timestamp", "error", err)
		}

	default:
		return "", fmt.Errorf("unexpected HTTP status when fetching CA bundle: %s", resp.Status)
	}

	return dest, nil
}

// waitForCABundle waits for another process to finish downloading the CA bundle
func (a *App) waitForCABundle(dest string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if stat, err := os.Stat(dest); err == nil && stat.Size() > 0 {
			// Validate the bundle before returning
			if err := a.validateCABundle(dest); err == nil {
				a.logger.Debug("Using CA bundle downloaded by another process", "path", dest)
				return dest, nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("timeout waiting for CA bundle download")
}

// validateCABundle performs basic validation on a CA bundle file
func (a *App) validateCABundle(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read CA bundle: %w", err)
	}

	if len(data) < 1000 {
		return fmt.Errorf("CA bundle too small, likely corrupted")
	}

	// Count certificates
	certCount := 0
	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type == "CERTIFICATE" {
			certCount++
		}
	}

	if certCount < 1 {
		return fmt.Errorf("CA bundle contains no certificates, likely corrupted")
	}

	a.logger.Debug("CA bundle validation passed", "certificates", certCount, "size", len(data))
	return nil
}

func loadTrustedCABundle(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle file %q: %w", path, err)
	}

	var certs []*x509.Certificate
	remaining := data

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Log but continue with other certificates
			continue
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in CA bundle %q", path)
	}

	return certs, nil
}

func (a *App) cacheDir() (string, error) {
	if a.cfg.CacheDir != nil {
		return a.cfg.CacheDir()
	}

	// Use OS-specific cache directory conventions
	switch runtime.GOOS {
	case "windows":
		// Windows: %LOCALAPPDATA%\sniffl
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			return filepath.Join(localAppData, "sniffl"), nil
		}
		// Fallback to user profile if LOCALAPPDATA not set
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(homeDir, "AppData", "Local", "sniffl"), nil

	case "darwin":
		// macOS: ~/Library/Caches/sniffl
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(homeDir, "Library", "Caches", "sniffl"), nil

	default:
		// Linux/Unix: Follow XDG Base Directory specification
		// XDG_CACHE_HOME or ~/.cache/sniffl
		if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
			return filepath.Join(xdgCache, "sniffl"), nil
		}
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		return filepath.Join(homeDir, ".cache", "sniffl"), nil
	}
}

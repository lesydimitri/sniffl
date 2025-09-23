// sniffl/ca_bundle.go
package sniffl

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
)

const caBundleURL = "https://curl.se/ca/cacert.pem"

func (a *App) fetchAndAppendCABundle(ctx context.Context, certs *[]*x509.Certificate) error {
	if isWindows() {
		if winRoots, err := a.getWindowsCertStoreRoots(); err == nil {
			*certs = append(*certs, winRoots...)
		} else {
			a.debugf("Failed to load Windows cert store: %v", err)
		}
	}
	if isDarwin() {
		if macRoots, err := a.getMacOSCertStoreRoots(); err == nil {
			*certs = append(*certs, macRoots...)
		} else {
			a.debugf("Failed to load macOS cert store: %v", err)
		}
	}
	path, err := a.ensureCABundle(ctx)
	if err != nil {
		return err
	}
	trust, err := loadTrustedCABundle(path)
	if err != nil {
		return err
	}
	*certs = append(*certs, trust...)
	return nil
}

func (a *App) ensureCABundle(ctx context.Context) (string, error) {
	// If a local bundle path is supplied, use it verbatim.
	if a.cfg.TrustedCABundle != "" {
		return a.cfg.TrustedCABundle, nil
	}

	// Resolve cache directory, using injected override if present.
	dir, err := a.cacheDir()
	if err != nil {
		return "", err
	}
	dest := filepath.Join(dir, "cacert.pem")
	etagPath := filepath.Join(dir, "cacert.etag")

	// Read existing ETag if any.
	var etag string
	data, readErr := os.ReadFile(etagPath)
	if readErr == nil {
		etag = string(data)
	}

	// Choose URL: injected override or the default curl CA bundle.
	url := caBundleURL
	if a.cfg.CABundleURL != "" {
		url = a.cfg.CABundleURL
	}

	// Build request with conditional header.
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	// Use injected client for testability.
	resp, err := a.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("CA bundle fetch error: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Write new bundle via injected file creator.
		f, err := a.cfg.FileCreator(dest)
		if err != nil {
			return "", err
		}
		defer f.Close()
		if _, err := io.Copy(f, resp.Body); err != nil {
			return "", err
		}
		if newEtag := resp.Header.Get("ETag"); newEtag != "" {
			_ = os.WriteFile(etagPath, []byte(newEtag), 0o644)
		}
	case http.StatusNotModified:
		// Keep existing file; nothing to do.
	default:
		return "", fmt.Errorf("unexpected CA bundle status: %s", resp.Status)
	}
	return dest, nil
}

func loadTrustedCABundle(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle file %q: %w", path, err)
	}
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			certs = append(certs, &x509.Certificate{Raw: block.Bytes})
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (a *App) cacheDir() (string, error) {
	if a.cfg.CacheDir != nil {
		return a.cfg.CacheDir()
	}
	// default per-OS path creation (unchanged)
	var dir string
	switch runtime.GOOS {
	case "windows":
		if s := os.Getenv("LOCALAPPDATA"); s != "" {
			dir = filepath.Join(s, "sniffl")
		} else {
			dir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "sniffl")
		}
	case "darwin":
		dir = filepath.Join(os.Getenv("HOME"), "Library", "Caches", "sniffl")
	default:
		if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
			dir = filepath.Join(xdg, "sniffl")
		} else {
			dir = filepath.Join(os.Getenv("HOME"), ".cache", "sniffl")
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func isWindows() bool { return runtime.GOOS == "windows" }
func isDarwin() bool  { return runtime.GOOS == "darwin" }

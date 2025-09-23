package sniffl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Verifies: (1) first call downloads and writes bundle, (2) ETag persisted,
// (3) second call sends If-None-Match and receives 304, (4) no second write.
func TestEnsureCABundle_DownloadAndCache(t *testing.T) {
	t.Parallel()

	var lastIfNoneMatch string
	var reqCount int

	const body = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		lastIfNoneMatch = r.Header.Get("If-None-Match")
		if lastIfNoneMatch == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, body)
	}))
	defer ts.Close()

	tmp := t.TempDir()

	writes := 0
	app := New(Config{
		Out:         bytes.NewBuffer(nil),
		Err:         bytes.NewBuffer(nil),
		CABundleURL: ts.URL,      // point at test server
		HTTPClient:  ts.Client(), // reuse server client to avoid TLS issues
		CacheDir:    func() (string, error) { return tmp, nil },
		FileCreator: func(name string) (io.WriteCloser, error) {
			if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				return nil, err
			}
			writes++
			return os.Create(name)
		},
	})

	// First fetch should download and write bundle and ETag.
	p1, err := app.ensureCABundle(context.Background())
	if err != nil {
		t.Fatalf("ensureCABundle first: %v", err)
	}
	if _, err := os.Stat(p1); err != nil {
		t.Fatalf("missing bundle after first fetch: %v", err)
	}
	gotBody, err := os.ReadFile(p1)
	if err != nil || string(gotBody) != body {
		t.Fatalf("unexpected bundle content: %q, err=%v", string(gotBody), err)
	}
	if reqCount != 1 || lastIfNoneMatch != "" {
		t.Fatalf("first request: count=%d If-None-Match=%q; want 1 and empty", reqCount, lastIfNoneMatch)
	}

	// ETag file should be persisted for conditional GETs.
	etagPath := filepath.Join(tmp, "cacert.etag")
	etag, err := os.ReadFile(etagPath)
	if err != nil || string(etag) != `"v1"` {
		t.Fatalf("etag persistence failed: %q, err=%v", string(etag), err)
	}

	// Second fetch should send If-None-Match and get 304, without rewriting file.
	p2, err := app.ensureCABundle(context.Background())
	if err != nil {
		t.Fatalf("ensureCABundle second: %v", err)
	}
	if p1 != p2 {
		t.Fatalf("bundle path changed between calls: %s vs %s", p1, p2)
	}
	if reqCount != 2 || lastIfNoneMatch != `"v1"` {
		t.Fatalf("second request: count=%d If-None-Match=%q; want 2 and \"v1\"", reqCount, lastIfNoneMatch)
	}
	if writes != 1 {
		t.Fatalf("bundle file should not be rewritten on 304; writes=%d", writes)
	}
}

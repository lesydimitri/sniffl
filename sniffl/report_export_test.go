package sniffl

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

func makeCert(sn int64, dns ...string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(sn),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		Raw:          []byte{0x30, 0x3}, // minimal non-empty to PEM-encode in tests that don’t parse
	}
}

func TestSerialToHex(t *testing.T) {
	cases := []struct {
		in   *big.Int
		want string
	}{
		{big.NewInt(1), "01"},
		{big.NewInt(0x80), "00:80"},
		{big.NewInt(-255), "-00:FF"},
	}
	for _, c := range cases {
		if got := serialToHex(c.in); got != c.want {
			t.Errorf("serialToHex(%v)=%q; want %q", c.in, got, c.want)
		}
	}
}

func TestCertificateSummary(t *testing.T) {
	c := makeCert(1, "a", "b")
	s := certificateSummary(c)
	for _, f := range []string{"Subject:", "Issuer:", "Serial:", "Not Before:", "Not After:"} {
		if !strings.Contains(s, f) {
			t.Fatalf("summary missing %q in\n%s", f, s)
		}
	}
}

func TestDedupeCerts(t *testing.T) {
	c1, c2 := makeCert(1), makeCert(2)
	dups := []*x509.Certificate{c1, c2, c1}
	out := dedupeCerts(dups)
	if len(out) != 2 {
		t.Fatalf("dedupe expected 2, got %d", len(out))
	}
}

func TestExportCertsSingle_WritesFiles(t *testing.T) {
	var files = map[string]*bytes.Buffer{}
	app := New(Config{
		Out: bytes.NewBuffer(nil),
		Err: bytes.NewBuffer(nil),
		FileCreator: func(name string) (io.WriteCloser, error) {
			b := &bytes.Buffer{}
			files[name] = b
			return nopWriteCloser{b}, nil
		},
	})
	certs := []*x509.Certificate{makeCert(1), makeCert(2)}
	if err := app.exportCertsSingle(certs, "host"); err != nil {
		t.Fatalf("exportCertsSingle error: %v", err)
	}
	if _, ok := files["host_cert_1.pem"]; !ok {
		t.Fatalf("expected host_cert_1.pem")
	}
	if _, ok := files["host_cert_2.pem"]; !ok {
		t.Fatalf("expected host_cert_2.pem")
	}
}

type nopWriteCloser struct{ *bytes.Buffer }

func (n nopWriteCloser) Close() error { return nil }

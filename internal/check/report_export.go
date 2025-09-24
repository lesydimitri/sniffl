package check

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
)

func (a *App) displayCertReport(hostPort string, certs []*x509.Certificate) {
	if _, err := fmt.Fprintf(a.cfg.Out, "[*] Report for %s\n\n", hostPort); err != nil {
		a.logger.Warn("Failed to write output", "error", err)
	}
	for i, cert := range certs {
		if _, err := fmt.Fprintf(a.cfg.Out, "[-] Certificate %d:\n", i+1); err != nil {
			a.logger.Warn("Failed to write output", "error", err)
		}
		if _, err := fmt.Fprintln(a.cfg.Out, "    "+strings.ReplaceAll(certificateSummary(cert), "\n", "\n    ")); err != nil {
			a.logger.Failure("Failed to write certificate summary", "error", err)
		}
		if _, err := fmt.Fprintln(a.cfg.Out); err != nil {
			a.logger.Failure("Failed to write newline", "error", err)
		}
	}
}

func (a *App) recordDNSNames(certs []*x509.Certificate) {
	for _, c := range certs {
		for _, d := range c.DNSNames {
			a.dnsNames[d] = struct{}{}
		}
	}
}

func (a *App) exportCertsSingle(certs []*x509.Certificate, base string) error {
	for i, c := range certs {
		name := fmt.Sprintf("%s_cert_%d.pem", base, i+1)
		w, err := a.cfg.FileCreator(name)
		if err != nil {
			return fmt.Errorf("failed to create certificate file %s: %w", name, err)
		}
		if err := writeBundle(w, []*x509.Certificate{c}); err != nil {
			if closeErr := w.Close(); closeErr != nil {
				a.logger.Failure("Failed to close file after write error", "file", name, "error", closeErr)
			}
			return fmt.Errorf("failed to write certificate data to file %s: %w", name, err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("failed to close certificate file %s: %w", name, err)
		}
		if _, err := fmt.Fprintf(a.cfg.Out, "[+] Exported: %s\n", name); err != nil {
			a.logger.Warn("Failed to write output", "error", err)
		}
	}
	return nil
}

func writeBundle(out io.Writer, certs []*x509.Certificate) error {
	for i, cert := range certs {
		comment := fmt.Sprintf("# Certificate %d\n%s\n", i+1, certificateSummary(cert))
		if _, err := io.WriteString(out, comment); err != nil {
			return fmt.Errorf("failed to write certificate %d comment: %w", i+1, err)
		}
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return fmt.Errorf("failed to PEM encode certificate %d: %w", i+1, err)
		}
	}
	return nil
}

func (a *App) finalizeExport(ctx context.Context) error {
	if a.cfg.ExportMode == "bundle" || a.cfg.ExportMode == "full_bundle" {
		if err := a.handleFinalExport(ctx, a.cfg.ExportMode, a.allCerts); err != nil {
			return fmt.Errorf("failed to export certificate bundle: %w", err)
		}
	}
	// Check if DNS export is enabled
	if a.cfg.DNSExport != nil && a.cfg.DNSExport != (*os.File)(nil) {
		names := make([]string, 0, len(a.dnsNames))
		for d := range a.dnsNames {
			names = append(names, d)
		}
		sort.Strings(names)
		for _, d := range names {
			if _, err := fmt.Fprintln(a.cfg.DNSExport, d); err != nil {
				return fmt.Errorf("failed to write DNS name %s to export file: %w", d, err)
			}
		}
	}
	return nil
}

func (a *App) handleFinalExport(ctx context.Context, mode string, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		a.logger.Debug("No certificates to export", "mode", mode)
		return nil
	}
	if mode == "full_bundle" {
		if err := a.fetchAndAppendCABundle(ctx, &certs); err != nil {
			return fmt.Errorf("failed to fetch and append CA bundle for full_bundle export: %w", err)
		}
	}
	certs = dedupeCerts(certs)
	name := "combined_" + mode + ".pem"
	w, err := a.cfg.FileCreator(name)
	if err != nil {
		return fmt.Errorf("failed to create combined certificate file %s: %w", name, err)
	}
	defer func() {
		if closeErr := w.Close(); closeErr != nil {
			a.logger.Debug("Warning: failed to close file", "file", name, "error", closeErr)
		}
	}()
	if err := writeBundle(w, certs); err != nil {
		return fmt.Errorf("failed to write certificate bundle to file %s: %w", name, err)
	}
	if _, err := fmt.Fprintf(a.cfg.Out, "[+] Exported: %s\n", name); err != nil {
		a.logger.Warn("Failed to write output", "error", err)
	}
	return nil
}

func certificateSummary(cert *x509.Certificate) string {
	lines := []string{
		fmt.Sprintf("Subject: %s", cert.Subject),
		fmt.Sprintf("Issuer: %s", cert.Issuer),
		fmt.Sprintf("Serial: %s", serialToHex(cert.SerialNumber)),
		fmt.Sprintf("Not Before: %s", cert.NotBefore.Format("2006-01-02 15:04")),
		fmt.Sprintf("Not After: %s", cert.NotAfter.Format("2006-01-02 15:04")),
	}
	if len(cert.DNSNames) > 0 {
		lines = append(lines, fmt.Sprintf("DNS Names: %v", cert.DNSNames))
	}
	for i := range lines {
		lines[i] = "# " + lines[i]
	}
	return strings.Join(lines, "\n")
}

func serialToHex(serial *big.Int) string {
	sign := ""
	if serial.Sign() < 0 {
		sign = "-"
		serial = new(big.Int).Abs(serial)
	}
	hexStr := serial.Text(16)
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	if b, _ := strconv.ParseUint(hexStr[:2], 16, 8); b >= 0x80 {
		hexStr = "00" + hexStr
	}
	var pairs []string
	for i := 0; i < len(hexStr); i += 2 {
		pairs = append(pairs, strings.ToUpper(hexStr[i:i+2]))
	}
	return sign + strings.Join(pairs, ":")
}

func dedupeCerts(certs []*x509.Certificate) []*x509.Certificate {
	seen := make(map[string]bool)
	var unique []*x509.Certificate
	for _, cert := range certs {
		// More robust than serial alone: issuer+serial
		key := cert.Issuer.String() + "|" + cert.SerialNumber.String()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, cert)
		}
	}
	return unique
}

// sniffl/report_export.go
package sniffl

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

func (a *App) displayCertReport(hostPort string, certs []*x509.Certificate) {
	fmt.Fprintf(a.cfg.Out, "[*] Report for %s\n\n", hostPort)
	for i, cert := range certs {
		fmt.Fprintf(a.cfg.Out, "[-] Certificate %d:\n", i+1)
		fmt.Fprintln(a.cfg.Out, "    "+strings.ReplaceAll(certificateSummary(cert), "\n", "\n    "))
		fmt.Fprintln(a.cfg.Out)
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
			fmt.Fprintf(a.cfg.Out, "[-] Export failed for %s: %v\n", base, err)
			return err
		}
		if err := writeBundle(w, []*x509.Certificate{c}); err != nil {
			fmt.Fprintf(a.cfg.Out, "[-] Export failed for %s: %v\n", base, err)
			w.Close()
			return err
		}
		w.Close()
		fmt.Fprintf(a.cfg.Out, "[+] Exported: %s\n", name)
	}
	return nil
}

func writeBundle(out io.Writer, certs []*x509.Certificate) error {
	for i, cert := range certs {
		comment := fmt.Sprintf("# Certificate %d\n%s\n", i+1, certificateSummary(cert))
		if _, err := io.WriteString(out, comment); err != nil {
			return err
		}
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) finalizeExport(ctx context.Context) error {
	if a.cfg.ExportMode == "bundle" || a.cfg.ExportMode == "full_bundle" {
		if err := a.handleFinalExport(ctx, a.cfg.ExportMode, a.allCerts); err != nil {
			return err
		}
	}
	if a.cfg.DNSExport != nil {
		names := make([]string, 0, len(a.dnsNames))
		for d := range a.dnsNames {
			names = append(names, d)
		}
		sort.Strings(names)
		for _, d := range names {
			fmt.Fprintln(a.cfg.DNSExport, d)
		}
	}
	return nil
}

func (a *App) handleFinalExport(ctx context.Context, mode string, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return nil
	}
	if mode == "full_bundle" {
		if err := a.fetchAndAppendCABundle(ctx, &certs); err != nil {
			return fmt.Errorf("failed to append CA bundle: %w", err)
		}
	}
	certs = dedupeCerts(certs)
	name := "combined_" + mode + ".pem"
	w, err := a.cfg.FileCreator(name)
	if err != nil {
		return err
	}
	defer w.Close()
	if err := writeBundle(w, certs); err != nil {
		return err
	}
	fmt.Fprintf(a.cfg.Out, "[+] Exported: %s\n", name)
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

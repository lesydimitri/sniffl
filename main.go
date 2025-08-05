// sniffl.go
//
//go:debug x509negativeserial=1
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
)

const (
	toolName    = "sniffl"
	caBundleURL = "https://curl.se/ca/cacert.pem"
)

var (
	exportMode string
	hostPort   string
	filePath   string
)

type Target struct {
	HostPort string
	Protocol string
}

var supportedProtocols = map[string]bool{
	"smtp": true,
	"imap": true,
	"pop3": true,
	"none": true,
}

var asciiBanner = `
 ▗▄▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▄▖▗▖   
▐▌   ▐▛▚▖▐▌  █  ▐▌   ▐▌   ▐▌   
 ▝▀▚▖▐▌ ▝▜▌  █  ▐▛▀▀▘▐▛▀▀▘▐▌   
▗▄▄▞▘▐▌  ▐▌▗▄█▄▖▐▌   ▐▌   ▐▙▄▄▖

Certificate Sniffing & Export Tool
`

func init() {
	flag.StringVar(&exportMode, "export", "", "Export mode: 'single', 'bundle', or 'full_bundle'")
	flag.StringVar(&hostPort, "H", "", "Target hostname and port (e.g. smtp.example.com:587)")
	flag.StringVar(&filePath, "F", "", "File with list of targets (host:port [protocol] per line)")
	flag.Usage = func() { usage("") }
	log.SetFlags(0)
}

func usage(reason string) {
	if reason != "" {
		fmt.Fprintf(os.Stderr, "%s: %s\n", toolName, reason)
	}
	fmt.Fprintln(os.Stderr, asciiBanner)
	fmt.Fprintf(os.Stderr, `
Usage: %s [--export=single|bundle|full_bundle] (-H host:port | -F filename) [protocol]

  --export     Export certificates:
                 'single'      - separate PEM files
                 'bundle'      - single PEM file
                 'full_bundle' - with trusted root CAs appended

  -H           Target hostname and port (e.g. smtp.example.com:587)
  -F           File containing targets (host:port [protocol] per line)
  protocol     STARTTLS protocol to use (smtp, imap, pop3, none). Only valid with -H

Notes:
  - Exactly one of -H or -F must be provided.
  - If -F is used, protocol specified on the command line is ignored; protocol must be provided per line in the file if needed.
  - If no protocol is specified, the tool will guess based on the port.
`, toolName)
	os.Exit(3)
}

func fatalf(format string, a ...interface{}) {
	log.Fatalf("%s: %s", toolName, fmt.Sprintf(format, a...))
}

func main() {
	flag.Parse()

	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" {
			flag.Usage()
			return
		}
	}

	if (hostPort == "" && filePath == "") || (hostPort != "" && filePath != "") {
		usage("Exactly one of -H or -F must be specified")
	}

	manualProtocol := ""
	if args := flag.Args(); len(args) > 0 {
		manualProtocol = strings.ToLower(args[0])
		if !supportedProtocols[manualProtocol] {
			usage("Unsupported protocol: " + manualProtocol)
		}
	}

	targets, err := parseTargets(filePath, hostPort, manualProtocol)
	if err != nil {
		fatalf("Failed to parse targets: %v", err)
	}

	var allCerts []*x509.Certificate

	for _, t := range targets {
		host, port, err := net.SplitHostPort(t.HostPort)
		if err != nil {
			log.Printf("[-] Invalid host:port format: %s", t.HostPort)
			continue
		}

		protocol := t.Protocol
		if protocol == "" {
			protocol = guessProtocol(port)
			if protocol != "none" {
				log.Printf("[!] Protocol guessed for %s: %s", t.HostPort, protocol)
			}
		}

		var certs []*x509.Certificate
		switch protocol {
		case "none":
			certs, err = fetchTLS(host, port)
		case "smtp":
			certs, err = fetchTLSOverSMTP(host, port)
		case "imap":
			certs, err = fetchTLSOverIMAP(host, port)
		case "pop3":
			certs, err = fetchTLSOverPOP3(host, port)
		default:
			log.Printf("[-] Unsupported protocol: %s", protocol)
			continue
		}

		if err != nil {
			log.Printf("[-] Failed to fetch certs from %s: %v", t.HostPort, err)
			continue
		}

		fmt.Printf("[*] Report for %s\n\n", t.HostPort)
		for i, cert := range certs {
			displayCertInfo(cert, i)
		}

		switch exportMode {
		case "single":
			if err := exportCertsSingle(certs, host); err != nil {
				log.Printf("[-] Export failed for %s: %v", host, err)
			}
		case "bundle", "full_bundle":
			allCerts = append(allCerts, certs...)
		}
	}

	if exportMode == "bundle" || exportMode == "full_bundle" {
		handleFinalExport(exportMode, allCerts)
	}

	fmt.Println("[*] Done.")
}

func parseTargets(filePath, hostPort, protocol string) ([]Target, error) {
	var targets []Target
	if filePath != "" {
		file, err := os.Open(filePath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for lineNum := 1; scanner.Scan(); lineNum++ {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 1 {
				continue
			}
			target := Target{HostPort: fields[0]}
			if len(fields) > 1 {
				proto := strings.ToLower(fields[1])
				if !supportedProtocols[proto] {
					log.Printf("[!] Skipping line %d (invalid protocol): %s", lineNum, line)
					continue
				}
				target.Protocol = proto
			}
			targets = append(targets, target)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	} else {
		targets = append(targets, Target{HostPort: hostPort, Protocol: protocol})
	}
	return targets, nil
}

func guessProtocol(port string) string {
	switch port {
	case "25", "587":
		return "smtp"
	case "143":
		return "imap"
	case "110":
		return "pop3"
	default:
		return "none"
	}
}

func fetchTLS(host, port string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

func fetchTLSOverProtocol(host, port string, initFunc func(*bufio.Writer, *bufio.Reader) error) ([]*x509.Certificate, error) {
	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return fetchTLSWithStartTLS(conn, initFunc, host)
}

func fetchTLSWithStartTLS(conn net.Conn, initFunc func(*bufio.Writer, *bufio.Reader) error, host string) ([]*x509.Certificate, error) {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	if err := initFunc(writer, reader); err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	defer tlsConn.Close()
	return tlsConn.ConnectionState().PeerCertificates, nil
}

func fetchTLSOverSMTP(host, port string) ([]*x509.Certificate, error) {
	return fetchTLSOverProtocol(host, port, func(w *bufio.Writer, r *bufio.Reader) error {
		r.ReadString('\n')
		fmt.Fprintf(w, "EHLO %s\r\n", getLocalHostname())
		w.Flush()

		starttls := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			if strings.Contains(line, "STARTTLS") {
				starttls = true
			}
			if strings.HasPrefix(line, "250 ") {
				break
			}
		}
		if !starttls {
			return fmt.Errorf("STARTTLS not supported")
		}
		fmt.Fprint(w, "STARTTLS\r\n")
		w.Flush()
		resp, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(resp, "220") {
			return fmt.Errorf("STARTTLS failed: %s", resp)
		}
		return nil
	})
}

func fetchTLSOverIMAP(host, port string) ([]*x509.Certificate, error) {
	return fetchTLSOverProtocol(host, port, func(w *bufio.Writer, r *bufio.Reader) error {
		r.ReadString('\n')
		fmt.Fprint(w, "A001 STARTTLS\r\n")
		w.Flush()
		for {
			line, _ := r.ReadString('\n')
			if strings.HasPrefix(strings.ToUpper(line), "A001 ") {
				if strings.Contains(strings.ToUpper(line), "OK") {
					return nil
				}
				return fmt.Errorf("STARTTLS rejected: %s", line)
			}
		}
	})
}

func fetchTLSOverPOP3(host, port string) ([]*x509.Certificate, error) {
	return fetchTLSOverProtocol(host, port, func(w *bufio.Writer, r *bufio.Reader) error {
		r.ReadString('\n')
		fmt.Fprint(w, "STLS\r\n")
		w.Flush()
		resp, _ := r.ReadString('\n')
		if !strings.HasPrefix(resp, "+OK") {
			return fmt.Errorf("STLS failed: %s", resp)
		}
		return nil
	})
}

func displayCertInfo(cert *x509.Certificate, idx int) {
	fmt.Printf("[-] Certificate %d:\n", idx+1)
	fmt.Println("    " + strings.ReplaceAll(certificateSummary(cert), "\n", "\n    "))
	fmt.Println()
}

func certificateSummary(cert *x509.Certificate) string {
	lines := []string{
		fmt.Sprintf("Subject: %s", cert.Subject),
		fmt.Sprintf("Issuer: %s", cert.Issuer),
		fmt.Sprintf("Serial: %s", cert.SerialNumber),
		fmt.Sprintf("Not Before: %s", cert.NotBefore.Format("2006-01-02 15:04")),
		fmt.Sprintf("Not After: %s", cert.NotAfter.Format("2006-01-02 15:04")),
	}
	if len(cert.DNSNames) > 0 {
		lines = append(lines, fmt.Sprintf("DNS Names: %v", cert.DNSNames))
	}
	for i, line := range lines {
		lines[i] = "# " + line
	}
	return strings.Join(lines, "\n")
}

func exportCertsSingle(certs []*x509.Certificate, base string) error {
	for i, c := range certs {
		name := fmt.Sprintf("%s_cert_%d.pem", base, i+1)
		if err := exportCertBundleToFile([]*x509.Certificate{c}, name); err != nil {
			return err
		}
		fmt.Printf("[+] Exported: %s\n", name)
	}
	return nil
}

func exportCertBundleToFile(certs []*x509.Certificate, filename string) error {
	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()
	for i, cert := range certs {
		comment := fmt.Sprintf("# Certificate %d\n%s\n", i+1, certificateSummary(cert))
		if _, err := out.WriteString(comment); err != nil {
			return err
		}
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}
	return nil
}

func fetchCABundle(url, outPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func loadTrustedCABundle(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
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
		if err == nil {
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func dedupeCerts(certs []*x509.Certificate) []*x509.Certificate {
	seen := make(map[string]bool)
	var unique []*x509.Certificate
	for _, cert := range certs {
		fp := fmt.Sprintf("%x", cert.Signature)
		if !seen[fp] {
			seen[fp] = true
			unique = append(unique, cert)
		}
	}
	return unique
}

func handleFinalExport(exportMode string, certs []*x509.Certificate) {
	if len(certs) == 0 {
		return
	}
	if exportMode == "full_bundle" {
		if err := fetchAndAppendCABundle(&certs); err != nil {
			fatalf("Failed to append CA bundle: %v", err)
		}
	}
	certs = dedupeCerts(certs)
	name := "combined_" + exportMode + ".pem"
	if err := exportCertBundleToFile(certs, name); err != nil {
		fatalf("Failed to write bundle: %v", err)
	}
	fmt.Printf("[+] Exported: %s\n", name)
}

func fetchAndAppendCABundle(certs *[]*x509.Certificate) error {
	// On Windows, include Windows root cert store certificates.
	if isWindows() {
		winRoots, err := getWindowsCertStoreRoots()
		if err != nil {
			log.Printf("[!] Warning: Failed to load Windows cert store: %v", err)
		} else {
			*certs = append(*certs, winRoots...)
		}
	}

	// Always append the Mozilla/curl PEM bundle
	if err := fetchCABundle(caBundleURL, "cacert.pem"); err != nil {
		return err
	}
	caCerts, err := loadTrustedCABundle("cacert.pem")
	if err != nil {
		return err
	}
	*certs = append(*certs, caCerts...)
	return nil
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func getLocalHostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "localhost"
	}
	return h
}

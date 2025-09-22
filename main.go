//go:debug x509negativeserial=1
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	toolName    = "sniffl"
	caBundleURL = "https://curl.se/ca/cacert.pem"
)

var (
	exportMode        string
	hostPort          string
	filePath          string
	dnsExportFilePath string
	httpsProxy        string
	toolVersion       = "dev"
	verbose           bool
)

type Target struct {
	HostPort string
	Protocol string
}

var supportedProtocols = map[string]bool{
	"smtp": true,
	"imap": true,
	"pop3": true,
	"http": true,
	"none": true,
}

func init() {
	flag.StringVar(&exportMode, "export", "", "Export mode: 'single', 'bundle', or 'full_bundle'")
	flag.StringVar(&hostPort, "H", "", "Target hostname and port (e.g. smtp.example.com:587)")
	flag.StringVar(&filePath, "F", "", "File with list of targets (host:port [protocol] per line)")
	flag.StringVar(&dnsExportFilePath, "exportdns", "", "Export all DNS names found to specified file")
	flag.BoolVar(&verbose, "v", false, "Enable verbose debug logging")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose debug logging (long form)")
	flag.StringVar(&httpsProxy, "https_proxy", "", "HTTP proxy URL (e.g. http://user:pass@127.0.0.1:8080)")
	flag.Usage = func() { usage("") }
	log.SetFlags(0)
}

func main() {
	flag.Parse()
	handleHelpFlag()

	if err := validateInput(); err != nil {
		fatalf("%s", err.Error())
	}

	manualProtocol := extractManualProtocol()
	targets, err := parseTargets(filePath, hostPort, manualProtocol)
	if err != nil {
		fatalf("Failed to parse targets: %v", err)
	}

	processTargets(targets)
	finalizeExport()
	fmt.Println("[*] Done.")
}

func handleHelpFlag() {
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" {
			flag.Usage()
			os.Exit(0)
		}
	}
}

func validateInput() error {
	if (hostPort == "" && filePath == "") || (hostPort != "" && filePath != "") {
		return fmt.Errorf("specify a target host with -H or a file containing one target per line using -F")
	}
	if hostPort != "" {
		if !isValidHostPort(hostPort) {
			return fmt.Errorf("invalid host:port format: %s", hostPort)
		}
	}
	if filePath != "" {
		if _, err := os.Stat(filePath); err != nil {
			return fmt.Errorf("specified file does not exist or cannot be accessed: %s", filePath)
		}
	}
	return nil
}

// Added input validation for host:port format
func isValidHostPort(hp string) bool {
	host, port, err := net.SplitHostPort(hp)
	if err != nil || host == "" || port == "" {
		return false
	}
	return true
}

func extractManualProtocol() string {
	if args := flag.Args(); len(args) > 0 {
		manualProtocol := strings.ToLower(args[0])
		if !supportedProtocols[manualProtocol] {
			usage("Unsupported protocol: " + manualProtocol)
		}
		return manualProtocol
	}
	return ""
}

var allCerts []*x509.Certificate
var dnsNamesSet = make(map[string]struct{})

func processTargets(targets []Target) {
	for _, t := range targets {
		if !isValidHostPort(t.HostPort) {
			log.Printf("[-] Invalid host:port format: %s (skipped)", t.HostPort)
			continue
		}
		host, port, err := net.SplitHostPort(t.HostPort)
		if err != nil {
			log.Printf("[-] Invalid host:port format (runtime): %s", t.HostPort)
			continue
		}

		protocol := resolveProtocol(t.Protocol, port, t.HostPort)
		certs, err := fetchCertsByProtocol(protocol, host, port, t.HostPort)
		if err != nil {
			log.Printf("[-] Failed to fetch certs from %s (protocol %s): %v", t.HostPort, protocol, err)
			continue
		}

		displayCertReport(t.HostPort, certs)
		recordDNSNames(certs)
		exportCertsIfNeeded(certs, host)
		if exportMode == "bundle" || exportMode == "full_bundle" {
			allCerts = append(allCerts, certs...)
		}
	}
}

func finalizeExport() {
	if exportMode == "bundle" || exportMode == "full_bundle" {
		handleFinalExport(exportMode, allCerts)
	}

	if dnsExportFilePath != "" {
		if err := writeDNSNamesToFile(dnsExportFilePath); err != nil {
			log.Printf("[-] Failed to write DNS names: %v", err)
		}
	}
}

func resolveProtocol(proto, port, hostPort string) string {
	if proto != "" {
		if !supportedProtocols[proto] {
			log.Printf("[!] Unsupported protocol %q for host %s (skipped)", proto, hostPort)
			return "none"
		}
		return proto
	}
	p := guessProtocol(port)
	if p != "none" {
		log.Printf("[!] Protocol guessed for %s: %s", hostPort, p)
	}
	return p
}

func fetchCertsByProtocol(protocol, host, port, hostPort string) ([]*x509.Certificate, error) {
	switch protocol {
	case "none":
		return fetchTLS(host, port)
	case "smtp":
		return fetchTLSOverSMTP(host, port)
	case "imap":
		return fetchTLSOverIMAP(host, port)
	case "pop3":
		return fetchTLSOverPOP3(host, port)
	case "http":
		return fetchTLSOverHTTP(host, port)
	default:
		log.Printf("[-] Unsupported protocol: %s for host: %s", protocol, hostPort)
		return nil, fmt.Errorf("unsupported protocol %q for host %s", protocol, hostPort)
	}
}

func displayCertReport(hostPort string, certs []*x509.Certificate) {
	fmt.Printf("[*] Report for %s\n\n", hostPort)
	for i, cert := range certs {
		displayCertInfo(cert, i)
	}
}

func recordDNSNames(certs []*x509.Certificate) {
	for _, cert := range certs {
		for _, dns := range cert.DNSNames {
			dnsNamesSet[dns] = struct{}{}
		}
	}
}

func exportCertsIfNeeded(certs []*x509.Certificate, host string) {
	if exportMode == "single" {
		if err := exportCertsSingle(certs, host); err != nil {
			log.Printf("[-] Export failed for %s: %v", host, err)
		}
	}
}

func writeDNSNamesToFile(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create DNS export file %q: %w", path, err)
	}
	defer file.Close()

	for dns := range dnsNamesSet {
		if _, err := file.WriteString(dns + "\n"); err != nil {
			return fmt.Errorf("failed to write DNS name %q: %w", dns, err)
		}
	}
	fmt.Printf("[+] Exported DNS names to %s\n", path)
	return nil
}

func usage(reason string) {
	if reason != "" {
		fmt.Fprintf(os.Stderr, "%s: %s\n", toolName, reason)
	}
	fmt.Fprintln(os.Stderr, asciiBanner)
	fmt.Fprintln(os.Stderr, toolVersion)
	fmt.Fprintln(os.Stderr, usageText)
	os.Exit(2)
}

func debugf(format string, args ...interface{}) {
	if verbose {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func fatalf(format string, a ...interface{}) {
	log.Fatalf("%s: %s\nPass -h or --help for usage instructions.", toolName, fmt.Sprintf(format, a...))
}

func parseTargets(filePath, hostPort, protocol string) ([]Target, error) {
	var targets []Target
	if filePath != "" {
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %q: %w", filePath, err)
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
			if !isValidHostPort(target.HostPort) {
				log.Printf("[!] Skipping line %d (invalid host:port): %s", lineNum, line)
				continue
			}
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
			return nil, fmt.Errorf("failed reading file %q: %w", filePath, err)
		}
	} else {
		targets = append(targets, Target{HostPort: hostPort, Protocol: protocol})
	}
	return targets, nil
}

func guessProtocol(port string) string {
	if port == "" {
		return "none"
	}
	switch port {
	case "25", "587":
		return "smtp"
	case "143":
		return "imap"
	case "110":
		return "pop3"
	case "443":
		return "http"
	default:
		return "none"
	}
}

// SECURITY NOTE: InsecureSkipVerify is used intentionally for certificate analysis.
// This tool examines certificates without validating trust chains.
func fetchTLS(host, port string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", net.JoinHostPort(host, port), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS dial error for %s:%s: %w", host, port, err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

func fetchTLSOverProtocol(host, port string, initFunc func(*bufio.Writer, *bufio.Reader) error) ([]*x509.Certificate, error) {
	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("TCP dial error for %s:%s: %w", host, port, err)
	}
	return fetchTLSWithStartTLS(conn, initFunc, host)
}

func fetchTLSWithStartTLS(conn net.Conn, initFunc func(*bufio.Writer, *bufio.Reader) error, host string) ([]*x509.Certificate, error) {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	if err := initFunc(writer, reader); err != nil {
		conn.Close()
		return nil, fmt.Errorf("STARTTLS/initFunc error: %w", err)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake error: %w", err)
	}
	defer tlsConn.Close()
	return tlsConn.ConnectionState().PeerCertificates, nil
}

func fetchTLSOverHTTP(host, port string) ([]*x509.Certificate, error) {
	addr := net.JoinHostPort(host, port)
	var conn net.Conn
	var err error

	if httpsProxy != "" {
		proxyURL, err := url.Parse(httpsProxy)
		if err != nil {
			return nil, fmt.Errorf("invalid https_proxy: %v", err)
		}

		proxyConn, err := net.Dial("tcp", proxyURL.Host)
		if err != nil {
			return nil, fmt.Errorf("cannot connect to proxy: %v", err)
		}

		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)

		// Add basic auth header if credentials are supplied
		if proxyURL.User != nil {
			username := proxyURL.User.Username()
			password, _ := proxyURL.User.Password()
			auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
		}

		connectReq += "\r\n"
		if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("proxy write failed: %v", err)
		}

		reader := bufio.NewReader(proxyConn)
		statusLine, err := reader.ReadString('\n')
		if err != nil || !strings.Contains(statusLine, "200") {
			proxyConn.Close()
			return nil, fmt.Errorf("proxy connect failed: %s", strings.TrimSpace(statusLine))
		}

		// Consume headers
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				proxyConn.Close()
				return nil, fmt.Errorf("proxy header read error: %v", err)
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}

		conn = proxyConn
	} else {
		conn, err = net.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("cannot connect directly to %s: %v", addr, err)
		}
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})

	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake error: %v", err)
	}
	defer tlsConn.Close()

	return tlsConn.ConnectionState().PeerCertificates, nil
}

func fetchTLSOverSMTP(host, port string) ([]*x509.Certificate, error) {
	return fetchTLSOverProtocol(host, port, func(w *bufio.Writer, r *bufio.Reader) error {
		if _, err := r.ReadString('\n'); err != nil {
			return fmt.Errorf("error reading SMTP greeting: %w", err)
		}
		fmt.Fprintf(w, "EHLO %s\r\n", getLocalHostname())
		w.Flush()

		starttls := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return fmt.Errorf("error reading SMTP EHLO response: %w", err)
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
		if _, err := r.ReadString('\n'); err != nil {
			return fmt.Errorf("error reading IMAP greeting: %w", err)
		}
		fmt.Fprint(w, "A001 STARTTLS\r\n")
		w.Flush()
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return fmt.Errorf("error reading IMAP STARTTLS response: %w", err)
			}
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
		if _, err := r.ReadString('\n'); err != nil {
			return fmt.Errorf("error reading POP3 greeting: %w", err)
		}
		fmt.Fprint(w, "STLS\r\n")
		w.Flush()
		resp, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading POP3 STLS response: %w", err)
		}
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
			return fmt.Errorf("failed to export cert %d for %s: %w", i+1, base, err)
		}
		fmt.Printf("[+] Exported: %s\n", name)
	}
	return nil
}

func exportCertBundleToFile(certs []*x509.Certificate, filename string) error {
	out, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %q: %w", filename, err)
	}
	defer out.Close()
	for i, cert := range certs {
		comment := fmt.Sprintf("# Certificate %d\n%s\n", i+1, certificateSummary(cert))
		if _, err := out.WriteString(comment); err != nil {
			return fmt.Errorf("failed to write cert %d comment in %q: %w", i+1, filename, err)
		}
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return fmt.Errorf("failed to encode cert %d in %q: %w", i+1, filename, err)
		}
	}
	return nil
}

func cacheDir() string {
	var cache string
	switch runtime.GOOS {
	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData != "" {
			cache = filepath.Join(localAppData, "sniffl")
		} else {
			home := os.Getenv("USERPROFILE")
			cache = filepath.Join(home, "AppData", "Local", "sniffl")
		}
	case "darwin":
		cache = filepath.Join(os.Getenv("HOME"), "Library", "Caches", "sniffl")
	default:
		xdg := os.Getenv("XDG_CACHE_HOME")
		if xdg != "" {
			cache = filepath.Join(xdg, "sniffl")
		} else {
			cache = filepath.Join(os.Getenv("HOME"), ".cache", "sniffl")
		}
	}
	os.MkdirAll(cache, 0o755)
	return cache
}

func fetchCABundle(url string) (string, error) {
	dir := cacheDir()
	caBundlePath := filepath.Join(dir, "cacert.pem")
	etagPath := filepath.Join(dir, "cacert.etag")

	var etag string
	if data, err := os.ReadFile(etagPath); err == nil {
		etag = string(data)
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request for CA bundle: %w", err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("CA bundle fetch error: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		out, err := os.Create(caBundlePath)
		if err != nil {
			return "", fmt.Errorf("failed to create CA bundle file: %w", err)
		}
		defer out.Close()
		if _, err = io.Copy(out, resp.Body); err != nil {
			return "", fmt.Errorf("failed to write CA bundle  %w", err)
		}
		newEtag := resp.Header.Get("ETag")
		if newEtag != "" {
			os.WriteFile(etagPath, []byte(newEtag), 0o644)
		}
		fmt.Printf("[+] Downloaded new cacert.pem (%s)\n", caBundlePath)
	case http.StatusNotModified:
		fmt.Printf("[*] CA bundle up to date (using cached %s)\n", caBundlePath)
	default:
		return "", fmt.Errorf("unexpected CA bundle fetch status: %s", resp.Status)
	}

	return caBundlePath, nil
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
	if isWindows() {
		if winRoots, err := getWindowsCertStoreRoots(); err != nil {
			log.Printf("[!] Warning: Failed to load Windows cert store: %v", err)
		} else {
			*certs = append(*certs, winRoots...)
		}
	}
	if isDarwin() {
		if macRoots, err := getMacOSCertStoreRoots(); err != nil {
			log.Printf("[!] Warning: Failed to load macOS cert store: %v", err)
		} else {
			*certs = append(*certs, macRoots...)
		}
	}
	bundlePath, err := fetchCABundle(caBundleURL)
	if err != nil {
		return fmt.Errorf("failed to fetch CA bundle: %w", err)
	}
	caCerts, err := loadTrustedCABundle(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to load trusted CA bundle: %w", err)
	}
	*certs = append(*certs, caCerts...)
	return nil
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func isDarwin() bool {
	return runtime.GOOS == "darwin"
}

func getLocalHostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "localhost"
	}
	return h
}

// cmd/sniffl/main.go
//
//go:debug x509negativeserial=1
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/lesydimitri/sniffl/sniffl"
)

var (
	exportMode  string
	hostPort    string
	filePath    string
	dnsOut      string
	httpsProxy  string
	verbose     bool
	toolVersion = "dev"
)

func main() {
	flag.StringVar(&exportMode, "export", "", "single|bundle|full_bundle")
	flag.StringVar(&hostPort, "H", "", "host:port")
	flag.StringVar(&filePath, "F", "", "file with targets (host:port [protocol])")
	flag.StringVar(&dnsOut, "exportdns", "", "file to write DNS names")
	flag.StringVar(&httpsProxy, "https_proxy", "", "HTTP proxy URL")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.BoolVar(&verbose, "verbose", false, "verbose")

	// Custom flag parsing to handle flags that appear after positional arguments
	parseFlags()

	if (hostPort == "" && filePath == "") || (hostPort != "" && filePath != "") {
		fatalUsage("specify exactly one of -H or -F")
	}

	var proxyURL *url.URL
	if httpsProxy != "" {
		u, err := url.Parse(httpsProxy)
		if err != nil {
			fatal(fmt.Errorf("invalid https_proxy: %w", err))
		}
		proxyURL = u
	}

	var dnsFile *os.File
	if dnsOut != "" {
		f, err := os.Create(dnsOut)
		if err != nil {
			fatal(fmt.Errorf("cannot create DNS export file: %w", err))
		}
		defer f.Close()
		dnsFile = f
	}

	cfg := sniffl.Config{
		ExportMode: exportMode,
		DNSExport:  dnsFile,
		HTTPSProxy: proxyURL,
		Verbose:    verbose,
		TimeNow:    nil,
		Out:        os.Stdout,
		Err:        os.Stderr,
		HTTPClient: nil,
		FileOpener: func(name string) (io.ReadCloser, error) { return os.Open(name) },
		FileCreator: func(name string) (io.WriteCloser, error) {
			// ensure parent dirs
			if i := strings.LastIndex(name, "/"); i > 0 {
				_ = os.MkdirAll(name[:i], 0o755)
			}
			return os.Create(name)
		},
	}

	app := sniffl.New(cfg)
	var targets []sniffl.Target
	var err error
	if filePath != "" {
		f, e := os.Open(filePath)
		if e != nil {
			fatal(fmt.Errorf("cannot open file: %w", e))
		}
		defer f.Close()
		targets, err = sniffl.ParseTargets(f, "")
	} else {
		proto := ""
		if args := flag.Args(); len(args) > 0 {
			proto = strings.ToLower(args[0])
		}
		targets = []sniffl.Target{{HostPort: hostPort, Protocol: proto}}
	}
	if err != nil {
		fatal(err)
	}

	if err := app.Run(context.Background(), targets); err != nil {
		fatal(err)
	}
	fmt.Println("[*] Done.")
}

func fatal(err error) { log.Fatalf("sniffl: %v", err) }
func fatalUsage(msg string) {
	log.Fatalf("sniffl: %s\nPass -h or --help for usage instructions.", msg)
}

// parseFlags parses command line flags regardless of their position
func parseFlags() {
	// First, collect all flags and their values
	args := os.Args[1:]
	flagArgs := []string{}
	nonFlagArgs := []string{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			// If this flag takes a value and it's not the last argument
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagArgs = append(flagArgs, args[i+1])
				i++ // Skip the next argument as it's a flag value
			}
		} else {
			nonFlagArgs = append(nonFlagArgs, arg)
		}
	}

	// Create a new argument list with flags first, then non-flag arguments
	newArgs := append(flagArgs, nonFlagArgs...)
	os.Args = append([]string{os.Args[0]}, newArgs...)

	// Now parse flags normally
	flag.Parse()
}

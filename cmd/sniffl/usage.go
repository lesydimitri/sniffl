// cmd/sniffl/usage.go
package main

import (
	"flag"
	"fmt"
	"os"
)

const asciiBanner = `
 ▗▄▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▄▖▗▖   
▐▌   ▐▛▚▖▐▌  █  ▐▌   ▐▌   ▐▌   
 ▝▀▚▖▐▌ ▝▜▌  █  ▐▛▀▀▘▐▛▀▀▘▐▌   
▗▄▄▞▘▐▌  ▐▌▗▄█▄▖▐▌   ▐▌   ▐▙▄▄▖

Certificate Sniffing & Export Tool`

// init wires a custom usage printer for -h/--help and any flag parse errors.
func init() {
	// Optional: route usage to stderr explicitly (default is already stderr).
	flag.CommandLine.SetOutput(os.Stderr)

	flag.Usage = func() {
		w := flag.CommandLine.Output()
		fmt.Fprintln(w, asciiBanner)
		fmt.Fprintf(w, "sniffl %s\n\n", toolVersion)

		fmt.Fprintln(w, "Usage: sniffl [-export single|bundle|full_bundle] (-H host:port | -F filename) [protocol] [-exportdnsfilename] [-https_proxy=proxyurl] [-verbose]")
		fmt.Fprintln(w, "Options:")
		flag.PrintDefaults()

		fmt.Fprintln(w, "\nNotes:")
		fmt.Fprintln(w, "  - Exactly one of -H or -F must be provided.")
		fmt.Fprintln(w, "  - If -F is used, the command line protocol is ignored; define it per-line instead.")
		fmt.Fprintln(w, "  - Protocol guessing based on port: 443=http, 25/587=smtp, 143=imap, 110=pop3.")

		fmt.Fprintln(w, "\nExamples:")
		fmt.Fprintln(w, "  sniffl -H smtp.example.com:587 smtp")
		fmt.Fprintln(w, "  sniffl -H www.example.com:443 http -export bundle")
		fmt.Fprintln(w, "  sniffl -F targets.txt -export full_bundle -exportdns all_dns.txt")

		// Trailing newline for a clean prompt return.
		fmt.Fprintln(w)
	}
}

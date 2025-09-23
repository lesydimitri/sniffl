# sniffl 🐽

[![Go Reference](https://pkg.go.dev/badge/github.com/lesydimitri/sniffl.svg)](https://pkg.go.dev/github.com/lesydimitri/sniffl)
[![Build Status](https://github.com/lesydimitri/sniffl/actions/workflows/release.yml/badge.svg)](https://github.com/lesydimitri/sniffl/actions)
[![Release](https://img.shields.io/github/v/release/lesydimitri/sniffl)](https://github.com/lesydimitri/sniffl/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/lesydimitri/sniffl)](https://goreportcard.com/report/github.com/lesydimitri/sniffl)

**sniffl** is a **Certificate Sniffing & Export Tool** designed to fetch, inspect, and export TLS certificates from remote servers using multiple protocols including SMTP, IMAP, POP3, or plain TLS connection.

## Features

- Supports multiple protocols with STARTTLS: SMTP, IMAP, POP3, and plain TLS
- Fetches full certificate chains from remote servers
- Export the DNS names found in certificates to a file
- Exports certificates as individual PEM files, standalone bundles, or full bundles including trusted root CAs (System + Mozilla)
- Exports system-trusted certificate authorities from both macOS and Windows stores for root CA inclusion
- Protocol guessing based on common ports if not explicitly specified

## Installation

### Option 1: Download a Precompiled Binary

Go to the [releases page](https://github.com/lesydimitri/sniffl/releases) and download a precompiled binary for your operating system and architecture.

### Option 2: Build from Source

Clone the repository and build the binary with Go:

```bash
git clone https://github.com/lesydimitri/sniffl.git
cd sniffl
go build ./cmd/sniffl
```

*Note:* For Windows cross-compilation on other platforms, use:

```bash
GOOS=windows GOARCH=amd64 go build ./cmd/sniffl
```

## Usage

```bash
sniffl [-export single|bundle|full_bundle] (-H host:port | -F filename) [protocol] [-exportdns FILE] [-verbose]
```

## Options

- `-export <single|bundle|full_bundle>`  
  Export certificates:  
  - `single`      Export each certificate as a separate PEM file  
  - `bundle`      Export all certificates into a single PEM file  
  - `full_bundle` Export all certificates into a single PEM file with system/Mozilla root CAs appended  

- `-exportdns FILE`  
  Write all unique DNS names found in the scanned certificates to the specified file

- `-verbose`, `-v`  
  Enable verbose debug logging

- `-H host:port`  
  Scan a single host and port (e.g. `smtp.example.com:587`)  

- `-F FILE`  
  Scan multiple targets from a file. Each line must be formatted as:  
  ```
  host:port [protocol]
  ```

- `protocol` (optional with `-H`, ignored with `-F`)  
  Protocol for STARTTLS negotiation (`smtp`, `imap`, `pop3`, `none`)  
  If omitted, the tool will try to guess based on the port (e.g., port 587 → SMTP)

## Examples

Scan a single SMTP server and export each certificate separately:

```bash
sniffl -H smtp.gmail.com:587 smtp -export single
```

Scan using an IMAP connection and output the full bundle with roots:

```bash
sniffl -H imap.mail.yahoo.com:143 imap -export full_bundle
```

Scan a list of targets from a file (with optional per-line protocols):

```bash
sniffl -F targets.txt
```

Export all DNS names found to a separate file:

```bash
sniffl -H example.com:443 -exportdns dnsnames.txt
```

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/lesydimitri/sniffl/issues) or open a pull request.

## Credits

- Brank, for [split-certs-online](https://codeberg.org/brank/split-certs-online)
- AI chatbots, for quick prototyping and taking the blame for any shitty code

## Support

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/codingkoala)

![Change Please](https://media1.tenor.com/m/wUEW1CEbQHkAAAAd/change-please.gif)
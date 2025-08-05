# sniffl 🐽

[![Go Reference](https://pkg.go.dev/badge/github.com/lesydimitri/sniffl.svg)](https://pkg.go.dev/github.com/lesydimitri/sniffl)
[![Build Status](https://github.com/lesydimitri/sniffl/actions/workflows/release.yml/badge.svg)](https://github.com/lesydimitri/sniffl/actions)
[![GitHub release](https://img.shields.io/github/v/release/lesydimitri/sniffl)](https://github.com/<USER>/<REPO>/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/lesydimitri/sniffl)](https://goreportcard.com/report/github.com/lesydimitri/sniffl)


**sniffl** is a **Certificate Sniffing & Export Tool** designed to fetch, inspect, and export TLS certificates from remote servers using multiple protocols including SMTP, IMAP, POP3, or plain TLS connection.

## Features

- Supports multiple protocols with STARTTLS: SMTP, IMAP, POP3, and plain TLS
- Fetches full certificate chains from remote servers
- Export the DNS names found in certificates to a file
- Exports certificates as individual PEM files, standalone bundles, or full bundles including trusted root CAs
- Automatically fetches and includes Mozilla's CA bundle for comprehensive trust verification
- Windows support: integration with the Windows system certificate store to include trusted roots
- Protocol guessing based on common ports if not explicitly specified
- Minimal external dependencies — built with Go for cross-platform usage

## Installation

```
go install github.com/lesydimitri/sniffl@latest
```

*Note:* To build or install on non-Windows platforms, use `go build` or `go install` inside the repository directory. For Windows cross-compilation on other platforms, use:

```
GOOS=windows GOARCH=amd64 go build
```

## Usage

```
sniffl [--export=single|bundle|full_bundle] (-H host:port | -F filename) [protocol]
```

### Options:

- `--export`  
  Export mode:  
  - `single`      Export each certificate as a separate PEM file  
  - `bundle`      Export all certificates into a single PEM file  
  - `full_bundle` Export with trusted root CAs appended  

- `-H`  
  Target hostname and port (e.g., `smtp.example.com:587`)  

- `-F`  
  File with list of targets, one per line:  
  ```
  host:port [protocol]
  ```
  Protocols are optional per line when using `-F`

- `protocol` (optional)  
  STARTTLS protocol to use (smtp, imap, pop3, none). Only valid with `-H`

## Examples

Fetch and display certificates from an SMTP server and export each cert as separate files:

```
sniffl --export=single -H smtp.gmail.com:587 smtp
```

Fetch certificates from multiple servers listed in a file:

```
sniffl -F targets.txt
```

Fetch certificates with full CA bundle appended:

```
sniffl --export=full_bundle -H imap.mail.yahoo.com:143 imap
```

## Notes

- Exactly one of `-H` or `-F` must be specified.
- If no protocol is specified, the tool guesses based on the port number.
- The built-in CA bundle is fetched from [curl.se](https://curl.se/ca/cacert.pem) each time unless manually cached.

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/lesydimitri/sniffl/issues) or open a pull request.

## Credits

- Brank, for [the script that kickstarted this little project](https://codeberg.org/brank/split-certs-online)
- AI chatbots, for quick prototyping and taking the blame for any shitty code

## Support

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/codingkoala)

![alt text](https://media1.tenor.com/m/wUEW1CEbQHkAAAAd/change-please.gif)
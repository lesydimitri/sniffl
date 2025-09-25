# sniffl 🐽

[![Go Reference](https://pkg.go.dev/badge/github.com/lesydimitri/sniffl.svg)](https://pkg.go.dev/github.com/lesydimitri/sniffl)
[![Build Status](https://github.com/lesydimitri/sniffl/actions/workflows/release.yml/badge.svg)](https://github.com/lesydimitri/sniffl/actions)
[![Release](https://img.shields.io/github/v/release/lesydimitri/sniffl)](https://github.com/lesydimitri/sniffl/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/lesydimitri/sniffl)](https://goreportcard.com/report/github.com/lesydimitri/sniffl)

**sniffl** is a **Certificate Sniffing & Export Tool** designed to fetch, inspect, and export TLS certificates from remote servers using multiple protocols including SMTP, IMAP, POP3, or plain TLS connection. It also supports querying Certificate Transparency logs to discover all issued certificates for a domain.

## Features

### 🔍 **Certificate Analysis**
- Supports multiple protocols: SMTP, IMAP, POP3 (with STARTTLS), HTTP, and plain TLS
- Fetches full certificate chains from remote servers
- **Certificate Transparency queries**: Discover all issued certificates for a domain and subdomains
- **Certificate validity checking**: Shows which certificates are currently valid or expired
- Export the DNS names found in certificates to a file
- Exports certificates as individual PEM files, standalone bundles, or full bundles including trusted root CAs (System + Mozilla)
- Exports system-trusted certificate authorities from both macOS and Windows stores for root CA inclusion
- Protocol guessing based on common ports if not explicitly specified

### 📸 **Screenshot Capture**
- **Visual reconnaissance**: Capture screenshots of HTTP/HTTPS services
- **Multiple input methods**: Single URLs, host:port, file lists, or CIDR ranges
- **SSL handling**: Ignores certificate errors by default for reconnaissance

## Installation

### Option 1: Download a Precompiled Binary

Go to the [releases page](https://github.com/lesydimitri/sniffl/releases) and download a precompiled binary for your operating system and architecture.

### Option 2: Build from Source

Clone the repository and build the binary with Go:

```bash
git clone https://github.com/lesydimitri/sniffl.git
cd sniffl
go build -o dist/sniffl ./cmd/sniffl
```

> [!NOTE]
> To cross-compile sniffl for Windows from other platforms, use:
> ```bash
> GOOS=windows GOARCH=amd64 go build -o dist/sniffl.exe ./cmd/sniffl
> ```

## Commands

sniffl uses a subcommand-based interface. Use `--help` with any command for details.

### `sniffl check` - Certificate Checking

Check certificates from live servers using various protocols.

**Options:**

- `-f, --file <file>`         File with targets (host:port [protocol])
- `-p, --protocol <proto>`    Connection protocol (smtp|imap|pop3|http|none, auto-detected if omitted)
- `-e, --export <mode>`       Export certificates (single|bundle|full_bundle)
- `--export-dns <file>`       File to write DNS names
- `--https-proxy <url>`       HTTP proxy URL
- `--dry-run`                 Show what would be done without executing

**Global Options:**
- `--config <file>`       Config file (default: $HOME/.sniffl.yaml)
- `-v, --verbose`         Enable verbose/debug logging

**Supported Protocols:**
- `smtp, imap, pop3` - Use STARTTLS to upgrade to TLS connection  
- `http` - Direct TLS connection (HTTPS)
- `none` - Direct TLS connection without protocol negotiation

**Protocol Auto-Detection:**
- `25/587` → smtp (STARTTLS), `143` → imap (STARTTLS), `110` → pop3 (STARTTLS)  
- `465/993/995` → none (direct TLS), `443/8080/8443` → http (HTTPS)

### `sniffl ct` - Certificate Transparency

Query Certificate Transparency logs to discover all issued certificates for a domain.

**Options:**

- `--show-expired`      Show expired certificates in CT results
- `--export-dns <file>` File to write discovered DNS names
- `--dry-run`           Show what would be done without executing
- `--verbose`           Verbose output

### `sniffl config` - Configuration Management

Manage sniffl configuration files.

**Subcommands:**
- `config init [path]`    Initialize a new configuration file
- `config show`           Show current configuration values
- `config example`        Display example configuration with all options

### `sniffl man` - Documentation Generation

Generate Unix man pages and documentation.

**Options:**
- `--generate`                Generate documentation files instead of showing man page
- `--format <format>`         Output format when generating: man, markdown, rest (default: man)
- `--output <directory>`      Output directory for generated files (default: ./man)

### `sniffl completion` - Shell Completion

Generate shell completion scripts for various shells.

**Subcommands:**
- `completion bash`           Generate bash completion script
- `completion zsh`            Generate zsh completion script  
- `completion fish`           Generate fish completion script
- `completion powershell`     Generate PowerShell completion script

**Completion Examples:**
```bash
# Install bash completion
sniffl completion bash > /etc/bash_completion.d/sniffl

# Install zsh completion (for oh-my-zsh)
sniffl completion zsh > ~/.oh-my-zsh/completions/_sniffl
```

**Examples:**
```bash
sniffl man                              # Show main manual page
sniffl man check                        # Show check command manual
sniffl man --generate                   # Generate man pages in ./man/
sniffl man --generate --format markdown # Generate markdown documentation
sniffl man --generate --output /usr/local/share/man  # Generate in custom location
```

**Notes:**
- CT queries show valid certificates by default
- Use `--show-expired` to include expired certificates in results
- Discovered domains are automatically filtered to include only relevant subdomains

### `sniffl screenshot` - Web Screenshot Capture

Capture screenshots of HTTP/HTTPS services for visual reconnaissance.

**Options:**

- `-f, --file <file>`         File with targets (URLs or host:port)
- `--cidr <range>`           CIDR range to scan (e.g., 192.168.1.0/24)
- `-o, --output-dir <dir>`   Output directory for screenshots (default: screenshots)
- `-p, --ports <ports>`      Comma-separated ports for CIDR scan (default: 80,443,8080,8443)
- `-c, --concurrency <n>`    Concurrent operations (default: 5)
- `--timeout <duration>`     Screenshot timeout (default: 30s)
- `--ignore-ssl-errors`      Ignore SSL certificate errors (default: true)
- `--skip-port-check`        Skip initial port connectivity check
- `--chrome-path <path>`     Path to Chrome/Chromium executable
- `--auto-download`          Auto-download Chromium if not found (default: true)
- `--dry-run`                Show what would be done without executing

**Requirements:**
- Chrome or Chromium (auto-downloaded if not found)

**Input Methods:**
- Single URL: `https://example.com`
- Host:port: `example.com:8080` (auto-detects HTTP/HTTPS)
- File: List of URLs or host:port entries
- CIDR: Network range scanning

## Examples

### Certificate Checking

Scan a single SMTP server and export each certificate separately:

```bash
sniffl check smtp.gmail.com:587 --protocol smtp --export single
```

Scan using an IMAP connection and output the full bundle with roots:

```bash
sniffl check imap.mail.yahoo.com:143 --protocol imap --export full_bundle
```

Scan multiple targets from a file:

```bash
sniffl check --file targets.txt --export bundle --export-dns all_domains.txt
```

Use an HTTP proxy:

```bash
sniffl check example.com:443 --https-proxy http://proxy.example.com:8080
```

Preview operations with dry-run mode:

```bash
sniffl check example.com:443 --export bundle --dry-run
```

Use verbose logging for debugging:

```bash
sniffl check example.com:443 --verbose
```

### Certificate Transparency

Query CT logs for a domain:

```bash
sniffl ct example.com
```

Query CT logs with expired certificates and export domains:

```bash
sniffl ct github.com --show-expired --export-dns domains.txt
```

Preview CT query with dry-run:

```bash
sniffl ct example.com --dry-run
```

### Screenshot Capture

Capture screenshot of a single website:

```bash
sniffl screenshot https://example.com
```

Scan a network range for web services:

```bash
sniffl screenshot --cidr 192.168.1.0/24
```

Capture screenshots from a file list:

```bash
sniffl screenshot --file targets.txt --output-dir ./screenshots
```

High-speed scanning with custom settings:

```bash
sniffl screenshot --cidr 10.0.0.0/24 --concurrency 10 --timeout 15s
```

### Configuration Management

Create a configuration file with defaults:

```bash
sniffl config init
```

Create config at specific location:

```bash
sniffl config init ~/.config/sniffl/config.yaml
```

View current configuration:

```bash
sniffl config show
```

See example configuration:

```bash
sniffl config example
```

## Configuration

sniffl supports YAML configuration files for default settings. Configuration files are loaded from:

1. `--config` flag value
2. `~/.sniffl.yaml`
3. `~/.config/sniffl/config.yaml`

**Example configuration:**

```yaml
# sniffl configuration file
# This file contains default settings for the sniffl certificate tool
# Place this file at ~/.sniffl.yaml or ~/.config/sniffl/config.yaml

verbose: true
timeout: 30s
concurrency: 5
https_proxy: ""
export_mode: bundle
export_dir: .
retry_attempts: 5
retry_delay: 1s
ct_show_expired: false

# Screenshot settings
screenshot_output_dir: "screenshots"
screenshot_timeout: "30s"
screenshot_concurrency: 5
screenshot_ignore_ssl_errors: true
screenshot_auto_download: true

log_level: info
log_format: text
```

## File Formats

### Certificate Checking

When using `sniffl check --file <targets.txt>`, each line should contain:

```
host:port [protocol]
```

**Examples:**
```
smtp.gmail.com:587 smtp
imap.gmail.com:993 imap
example.com:443
pop.gmail.com:995 pop3
```

### Screenshot Capture

When using `sniffl screenshot --file <targets.txt>`, each line should contain:

```
URL or host:port
```

**Examples:**
```
https://example.com
http://internal.company.com:8080
example.com:443
192.168.1.100:80
```

## Logging

sniffl provides structured logging with configurable levels and formats:

- **Log Levels**: debug, info, warn, error
- **Log Formats**: text (human-readable), json (structured)
- **Context**: Automatic context like target host, protocol, operation type

**Examples:**
```bash
# Debug logging with text format
sniffl check example.com:443 --verbose

# JSON logging (configure in ~/.sniffl.yaml)
log_format: json
log_level: debug
```

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/lesydimitri/sniffl/issues) or open a pull request.

## Credits

- Brank, for [split-certs-online](https://codeberg.org/brank/split-certs-online)
- AI chatbots, for quick prototyping and taking the blame for any shitty code

## Support

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/codingkoala)

![Change Please](https://media1.tenor.com/m/wUEW1CEbQHkAAAAd/change-please.gif)
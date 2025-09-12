package main

var asciiBanner = `
 ▗▄▄▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▄▖▗▖   
▐▌   ▐▛▚▖▐▌  █  ▐▌   ▐▌   ▐▌   
 ▝▀▚▖▐▌ ▝▜▌  █  ▐▛▀▀▘▐▛▀▀▘▐▌   
▗▄▄▞▘▐▌  ▐▌▗▄█▄▖▐▌   ▐▌   ▐▙▄▄▖

Certificate Sniffing & Export Tool
`

var usageText = `
Usage: sniffl [--export=single|bundle|full_bundle] (-H host:port | -F filename) [protocol] [--exportdns=filename] [--https_proxy=proxyurl] [--verbose]

--export        Export certificates:
                    'single'      - separate PEM files
                    'bundle'      - single PEM file
                    'full_bundle' - with trusted root CAs appended

--exportdns     Export all unique DNS names to the specified file

--https_proxy   Use a proxy for HTTP CONNECT method. Example:
                    --https_proxy="http://user:pass@proxyhost:port"

--verbose / -v  Enable verbose logging

-H              Target hostname and port (e.g. smtp.example.com:587)
-F              File with targets (host:port [protocol] per line)

Notes:

- Exactly one of -H or -F must be provided.
- If -F is used, the command line protocol is ignored; define it per-line instead.
- Protocol guessing based on port: 443=http, 25=smtp, etc.
`

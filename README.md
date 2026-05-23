# pia-wireguard-cfg

A lightweight command-line tool written in Go that generates a ready-to-use WireGuard configuration file for the Private Internet Access (PIA) VPN service. It authenticates with PIA's official provisioning API, selects the lowest-latency server in your chosen region, generates a fresh WireGuard keypair, and writes a complete `.conf` file directly to your Windows desktop.

## Why use this?

Manually creating a PIA WireGuard configuration requires authenticating against multiple APIs, parsing server lists, performing key exchange, and assembling the config by hand. **pia-wireguard-cfg** automates the entire process end-to-end in a single command.

- **No manual API calls:** the full PIA WireGuard provisioning flow is handled automatically
- **Fresh keypair every run:** a new WireGuard keypair is cryptographically generated each time
- **Lowest-latency server selection:** TCP latency is measured against all available servers in the region before connecting
- **Router-compatible output:** config files are written with Unix line endings as required by most WireGuard router implementations
- **No credentials stored:** your PIA password is entered interactively and never written to disk

## Features

- **Automatic server selection:** measures TCP latency to all WireGuard servers in the chosen region and selects the fastest one
- **Full region support:** works with any PIA region, not just a hardcoded location -- use `-list-regions` to browse all options
- **Interactive or flag-driven:** supply username and region via command-line flags or be prompted interactively for each
- **Configurable DNS:** use any DNS servers you choose, with Quad9 as the default
- **Verbose diagnostic mode:** optionally prints server IP, CN, measured latency, and raw PIA registration response for troubleshooting
- **Safe overwrite handling:** prompts before overwriting an existing config file
- **Single binary:** compiles to a single `.exe` with no runtime dependencies

## Requirements

- Go 1.21 or later
- Windows 11 (output path uses `%USERPROFILE%\Desktop`)
- A valid Private Internet Access account with an active subscription

## Installation

```
git clone https://github.com/ExponentiallyDigital/pia-wireguard-cfg.git
cd pia-wireguard-cfg
go mod tidy
go build -o pia-wireguard-cfg.exe
```

The compiled `pia-wireguard-cfg.exe` can be placed anywhere on your system. No installer is required.

## Usage

```
pia-wireguard-cfg.exe [-username PIA_username] [-region region_id] [-list-regions]
                  [-dns "dns_servers"] [-verbose] [-help] [-?]
```

With no arguments, you will be prompted interactively for the region, username, and password.

## Command-line options

| Option                          | Description                                                                                                                                              |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-username`                     | Your PIA account username (e.g. `p1234567`). If omitted you will be prompted interactively.                                                              |
| `-region`                       | PIA region ID to connect through (e.g. `aus_melbourne`). If omitted you will be prompted interactively. Run `-list-regions` to see all valid region IDs. |
| `-list-regions`                 | Prints all available PIA regions and their WireGuard server counts, sorted alphabetically, then exits. Does not require credentials.                     |
| `-dns`                          | DNS servers to write into the config file, comma-separated. Default: `9.9.9.9, 149.112.112.112` (Quad9).                                                 |
| `-verbose`                      | Prints diagnostic output to stderr: resolved server IP and CN, measured latency, and raw PIA registration response.                                      |
| `-help` / `-?` / `/help` / `/?` | Shows the help message and exits.                                                                                                                        |

## Examples

Generate a config for Melbourne, Australia, prompting for all credentials:

```
pia-wireguard-cfg.exe -region aus_melbourne
```

Supply username on the command line (password is always prompted):

```
pia-wireguard-cfg.exe -username p1234567 -region aus_melbourne
```

Use a different region:

```
pia-wireguard-cfg.exe -username p1234567 -region us_new_york_city
```

Use Cloudflare DNS instead of the default Quad9:

```
pia-wireguard-cfg.exe -username p1234567 -region aus_melbourne -dns "1.1.1.1, 1.0.0.1"
```

Use Google DNS with verbose output for troubleshooting:

```
pia-wireguard-cfg.exe -username p1234567 -region aus_melbourne -dns "8.8.8.8, 8.8.4.4" -verbose
```

Browse all available PIA regions before choosing one:

```
pia-wireguard-cfg.exe -list-regions
```

## DNS options

The default DNS servers are Quad9, a privacy-focused, malware-blocking resolver:

| Server          | Address           |
| --------------- | ----------------- |
| Quad9 primary   | `9.9.9.9`         |
| Quad9 secondary | `149.112.112.112` |

Common alternatives:

| Provider   | Primary   | Secondary |
| ---------- | --------- | --------- |
| Cloudflare | `1.1.1.1` | `1.0.0.1` |
| Google     | `8.8.8.8` | `8.8.4.4` |

Pass multiple servers as a quoted comma-separated string: `-dns "1.1.1.1, 1.0.0.1"`

## Output

The generated config file is written to:

```
%USERPROFILE%\Desktop\pia-<region_name>.conf
```

For example, selecting region `aus_melbourne` produces `pia-aus_melbourne.conf` on your desktop. If a file with that name already exists, you will be prompted before it is overwritten.

The config file follows this structure, with all dynamic fields populated from the PIA registration response:

```ini
[Interface]
PrivateKey = <freshly generated private key>
Address    = <client IP assigned by PIA>
DNS        = <from -dns flag or default>
MTU        = 1420

[Peer]
PublicKey           = <server public key from PIA>
Endpoint            = <server IP:port from PIA>
PersistentKeepalive = 25
AllowedIPs          = 0.0.0.0/0
```

## Authentication

- Your PIA password is **always** entered interactively at runtime and is **never** stored, logged, or written to disk
- Credentials are used solely to obtain a short-lived PIA authentication token for the WireGuard key registration step
- The WireGuard private key is written only to the output `.conf` file on your desktop -- treat this file as a secret

## How it works

1. Fetches the PIA server list from `serverlist.piaservers.net/vpninfo/servers/v6`
2. Filters servers to the chosen region and measures TCP latency to port 1337 on each candidate
3. Authenticates against the PIA token API using your credentials to obtain a short-lived token
4. Generates a fresh WireGuard keypair using `golang.org/x/crypto/curve25519` with correct RFC 7748 scalar clamping
5. Registers the generated public key with the lowest-latency server via its local HTTPS API (port 1337), using PIA's own CA certificate for TLS verification
6. Assembles the complete WireGuard config from the registration response and writes it to your desktop

This follows the same provisioning flow as PIA's official open-source manual connection scripts at [github.com/pia-foss/manual-connections](https://github.com/pia-foss/manual-connections).

## Technical details

- **Key generation:** uses `golang.org/x/crypto/curve25519` directly; no dependency on the `wg` binary or kernel WireGuard modules
- **TLS:** the port 1337 registration API uses HTTPS with PIA's own CA certificate, fetched from the PIA manual-connections repository and used to build a custom TLS root pool at runtime
- **Server name verification:** `tls.Config.ServerName` is set to the server's `cn` field from the PIA server list, as the certificate is issued to the hostname rather than the IP address
- **Line endings:** the output config file always uses Unix line endings (`\n`) regardless of the host OS, as required by WireGuard router implementations
- **Timeouts:** 10-second timeout on all HTTP clients; 2-second timeout on TCP latency probes

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure the code passes `go vet` cleanly
5. Submit a pull request with a clear description of the change

## Bugs and feature requests

Found a bug or want to request a feature?
[Open an issue here](https://github.com/ExponentiallyDigital/pia-wireguard-cfg/issues)

## Support

This tool is unsupported and may cause objects in mirrors to be closer than they appear. Batteries not included.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

Copyright (C) 2026 Andrew Newbury

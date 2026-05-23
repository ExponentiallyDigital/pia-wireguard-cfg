Build a command-line Go app (Go 1.21 or later) as a single `main.go` with module name `pia-wireguard-cfg` that generates a WireGuard config file for PIA VPN using their official provisioning API flow (reference: github.com/pia-foss/manual-connections).

Include a comment block at the top of `main.go` with the exact commands to initialise the module, run `go mod tidy`, and build the app. Also output the complete `go.mod` with `go 1.21` and all required dependencies so the project builds with a single `go mod tidy`.

---

## Command-line flags

The app must accept the following flags:

- `--username` — PIA account username. If omitted, prompt interactively.
- `--region` — PIA region ID to use (e.g. `aus_melbourne`). If omitted, prompt interactively. There is no default; it must always be explicitly supplied or entered.
- `--dns` — DNS servers to write into the config file, comma-separated. Default: `"9.9.9.9, 149.112.112.112"`.
- `--verbose` — write diagnostic output (resolved server IP and CN, measured latency, raw registration response) to `os.Stderr`.
- `--list-regions` — print all available PIA regions with their WireGuard server counts sorted alphabetically, then exit. Does not require credentials.
- `--help`, `-?`, `/help`, `/?` — print the help block described below and exit. These must be detected manually before `flag.Parse()` is called, by iterating `os.Args[1:]`, so that `-?` and `/?` do not cause a flag parse error.

---

## Input handling

- Declare a single `reader := bufio.NewReader(os.Stdin)` at the top of `main()` and reuse it for all interactive prompts.
- Read all interactive input using `reader.ReadString('\n')` with `strings.TrimSpace()` to correctly handle spaces and special characters.
- The password is **always** prompted interactively as plain visible text on stdin, never supplied via a flag.
- Prompt order when flags are missing:
  1. If `--list-regions` was passed, fetch and print the server list (see below) then exit — do not prompt for anything.
  2. If `--region` was not supplied, prompt: `Enter PIA region ID (or run -list-regions to see options): `
  3. If `--username` was not supplied, prompt: `Enter PIA username: `
  4. Always prompt: `Enter PIA password: `
- Abort with a clear error if region, username, or password are empty after prompting.

---

## Server list

- Fetch from `https://serverlist.piaservers.net/vpninfo/servers/v6` using an HTTP client with the system CA pool.
- The response is JSON followed by a newline and a cryptographic signature. Split on the first `\n` and parse only the JSON portion before it.
- The relevant JSON structure is:

```json
{
  "regions": [
    {
      "id": "aus_melbourne",
      "servers": {
        "wg": [{ "ip": "x.x.x.x", "cn": "melbourne401.privacy.network" }]
      }
    }
  ]
}
```

- For `--list-regions`: sort regions alphabetically by ID and print each as `%-30s %d WireGuard server(s)` then exit. This must run before any credential prompts.
- For normal operation: filter to the region matching `--region`. Abort with a clear error (suggesting `--list-regions`) if the region is not found or has no WireGuard servers.

---

## Latency selection

- Measure TCP connect latency to port 1337 on each server in the selected region using a 2-second timeout per probe.
- Select the server with the lowest latency.
- Abort with a clear error if no server responds within the probe timeout.
- If `--verbose`, write each probe result (IP, CN, latency or error) to `os.Stderr`.

---

## Authentication

- POST to `https://www.privateinternetaccess.com/gtoken/generateToken` with HTTP Basic Auth (username and password), an **empty POST body**, and an HTTP client using the system CA pool.
- Check the HTTP response status code and abort with a clear error on non-200.
- The response body is `{"token": "..."}`. Extract the `token` field and abort with a clear error if it is empty.

---

## WireGuard keypair generation

- Use `golang.org/x/crypto/curve25519` directly. Do not use `wgctrl` or shell out to the `wg` binary.
- Generate 32 random bytes using `crypto/rand`.
- Apply correct RFC 7748 scalar clamping: `k[0] &= 248`, `k[31] &= 127`, `k[31] |= 64`.
- Base64-encode the clamped private key bytes using `base64.StdEncoding` for the `PrivateKey` config field.
- Derive the public key using `curve25519.X25519(privateKey, curve25519.Basepoint)` (not the deprecated `ScalarBaseMult`) and base64-encode the result.

---

## Server registration

- GET `https://{server_ip}:1337/addKey?pt={token}&pubkey={url-encoded-public-key}`.
- Use `url.QueryEscape` on the public key value (base64 contains `+` and `/` which must be escaped).
- This call must use a **dedicated HTTP client** configured with:
  - A custom TLS root pool built from PIA's CA certificate, hardcoded as a `const` string directly in `main.go`. Fetch the certificate from `https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt` and paste it verbatim as the const value. Do **not** fetch it at runtime.
  - `tls.Config.ServerName` set to the `cn` field from the server list entry for the selected server, because the certificate is issued to the hostname, not the IP address.
- Check the HTTP response status code and abort with a clear error on non-200.
- Parse the registration JSON response:
  - Check that `status` equals `"OK"` and abort with a clear error if not.
  - Extract `server_key` (string), `peer_ip` (string), and `server_port` (JSON **integer** — unmarshal as `int`, convert with `strconv.Itoa` for the Endpoint field).
  - Strip any existing CIDR suffix from `peer_ip` before appending `/32` to form the WireGuard `Address` value.

---

## HTTP client rules

Three separate HTTP clients are required — do not share them:

1. **Server list + token API** — system CA pool, 10-second timeout.
2. **Registration API (port 1337)** — custom PIA CA pool, `ServerName` set to server CN, 10-second timeout.

TCP latency probes use `net.DialTimeout` with a 2-second timeout, not an HTTP client.

---

## Output file

- Resolve the output path as `filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "pia-"+regionFlag+".conf")`.
  - For example, region `aus_melbourne` produces `pia-aus_melbourne.conf`.
- Abort with a clear error if `USERPROFILE` is not set.
- If the file already exists, prompt `Overwrite existing file? [y/N]: ` defaulting to no, and only proceed on explicit `y` or `Y`.
- Strip all `\r` characters from the config string before writing (use `strings.ReplaceAll(config, "\r", "")`) to guarantee Unix line endings regardless of any `\r` in API responses.
- Write using `os.WriteFile` with permission mode `0600`.
- The config string must use a regular double-quoted string (not a raw backtick literal) so that `\n` escape sequences are interpreted as real newlines.
- The output config must follow this exact structure:

```
[Interface]
PrivateKey = <base64 clamped private key>
Address = <peer_ip>/32
DNS = <from --dns flag>
MTU = 1420

[Peer]
PublicKey = <base64 server_key>
Endpoint = <server_ip>:<server_port>
PersistentKeepalive = 25
AllowedIPs = 0.0.0.0/0
```

---

## Help text

Implement a `printHelp()` function that writes a detailed help block to stdout using `os.Stdout.WriteString(...)` (not `fmt.Print` or `fmt.Fprint` — these trigger a go vet warning on the `%USERPROFILE%` path string). The help block must include:

- A version line (`pia-wireguard-cfg v1.0.0`) and one-line description.
- Full usage line showing all flags.
- A parameters table describing every flag including defaults and examples.
- At least three usage examples showing different flag combinations.
- An output section describing the desktop file path and naming convention.
- An authentication section noting the password is never stored.
- A DNS defaults section listing Quad9, Cloudflare, and Google options.
- A config file format section showing the output structure.

---

## Code quality

- Use `fmt.Errorf` with `%w` for all error wrapping throughout.
- No `panic` for any recoverable error condition.
- Ensure the code passes `go vet` cleanly.
- Emit clear human-readable error messages for every failure mode: auth failure, empty token, non-200 HTTP responses, network errors, server list parse failure, region not found, empty server list for region, all latency probes failing, TLS configuration failure (invalid CA cert), registration failure, non-OK registration status, missing `USERPROFILE` environment variable, empty region/username/password after prompting.

---

_This prompt was developed iteratively by Claude Sonnet 4.6 in collaboration with the author._

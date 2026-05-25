// *************************************************************************************************
// pia-wireguard-cfg
//
//  Purpose: Generates a WireGuard configuration file for Private Internet Access (PIA) VPN.
//           Authenticates with PIA, selects the lowest-latency server in the specified region,
//           generates a WireGuard keypair, and writes a ready-to-use .conf file to your desktop.
//
// To initialize and tidy dependencies (run once):
//
//    go mod init pia-wireguard-cfg
//    go mod tidy
//
// To build both Windows and Linux (ARM64) binaries, run build.bat:
//
//    build.bat
//
// This produces:
//    pia-wireguard-cfg.exe   -- Windows binary
//    pia-wireguard-cfg       -- Linux/Android binary
//
// To run on Android via Termux, transfer pia-wireguard-cfg-linux-arm64 to the device,
// then in Termux run:
//    chmod +x pia-wireguard-cfg
// Run the binary from within the Termux home directory (~/) to ensure the output
// .conf file is written to an accessible location.
// On Android Termux, you make need to install the CA certificates package bundle with
//    pkg install ca-certificates
//
// *************************************************************************************************
// Copyright (C) 2025 Andrew Newbury
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
// the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.
// *************************************************************************************************
//go:generate goversioninfo
// *************************************************************************************************

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const programVersion = "1.0.9"

type wgServer struct {
    IP string `json:"ip"`
    CN string `json:"cn"`
}

type region struct {
    ID      string `json:"id"`
    Servers struct {
        WG []wgServer `json:"wg"`
    } `json:"servers"`
}

type serverList struct {
    Regions []region `json:"regions"`
}

func main() {
    var usernameFlag string
    var verbose bool
	var regionFlag string
	var listRegions bool
	var dnsFlag string

	// Handle help flags before standard flag parsing so -? and /? don't cause errors
	for _, arg := range os.Args[1:] {
		if arg == "-help" || arg == "-?" || arg == "/help" || arg == "/?" {
			printHelp()
			os.Exit(0)
		}
	}
	reader := bufio.NewReader(os.Stdin)
	flag.StringVar(&usernameFlag, "username", "", "PIA username")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.StringVar(&regionFlag, "region", "", "PIA region ID to use")
	flag.StringVar(&dnsFlag, "dns", "9.9.9.9, 149.112.112.112", "DNS servers to use in the config file")
	flag.BoolVar(&listRegions, "list-regions", false, "Print all available regions and exit")
	flag.Parse()

    // Fetch server list
    serverListURL := "https://serverlist.piaservers.net/vpninfo/servers/v6"
    httpClient := &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            DialContext: newDialer().DialContext,
            TLSClientConfig: &tls.Config{
                RootCAs: buildSystemCertPool(),
            },
        },
    }
    resp, err := httpClient.Get(serverListURL)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to fetch server list: %v\n", err)
        os.Exit(1)
    }
    defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read server list: %v\n", err)
        os.Exit(1)
    }
    jsonEnd := strings.IndexByte(string(body), '\n')
    if jsonEnd == -1 {
        fmt.Fprintln(os.Stderr, "Server list format error: missing newline after JSON")
        os.Exit(1)
    }
    var sl serverList
    if err := json.Unmarshal(body[:jsonEnd], &sl); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to parse server list JSON: %v\n", err)
        os.Exit(1)
    }

	if listRegions {
		sort.Slice(sl.Regions, func(i, j int) bool {
			return sl.Regions[i].ID < sl.Regions[j].ID
		})
		for _, r := range sl.Regions {
			fmt.Printf("%-30s %d WireGuard server(s)\n", r.ID, len(r.Servers.WG))
		}
		os.Exit(0)
	}

	if regionFlag == "" {
		fmt.Print("Enter PIA region ID (or run -list-regions to see options): ")
		r, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read region: %v\n", err)
			os.Exit(1)
		}
		regionFlag = strings.TrimSpace(r)
	}
	if regionFlag == "" {
		fmt.Fprintln(os.Stderr, "Region cannot be empty -- run with -list-regions to see available regions")
		os.Exit(1)
	}

	username := strings.TrimSpace(usernameFlag)
    if username == "" {
        fmt.Print("Enter PIA username: ")
        u, err := reader.ReadString('\n')
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to read username: %v\n", err)
            os.Exit(1)
        }
        username = strings.TrimSpace(u)
    }
    if username == "" {
        fmt.Fprintln(os.Stderr, "Username cannot be empty")
        os.Exit(1)
    }

    fmt.Print("Enter PIA password: ")
    pass, err := reader.ReadString('\n')
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
        os.Exit(1)
    }
    password := strings.TrimSpace(pass)
    if password == "" {
        fmt.Fprintln(os.Stderr, "Password cannot be empty")
        os.Exit(1)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

	var melRegion *region
	for i, r := range sl.Regions {
		if r.ID == regionFlag {
			melRegion = &sl.Regions[i]
			break
		}
	}

	if melRegion == nil {
    fmt.Fprintf(os.Stderr, "Region %q not found in server list, run with -list-regions to see available regions\n", regionFlag)
    os.Exit(1)
	}
	if len(melRegion.Servers.WG) == 0 {
		fmt.Fprintf(os.Stderr, "No WireGuard servers found for region %q\n", regionFlag)
		os.Exit(1)
	}

    // Probe latency
    type probeResult struct {
        server  wgServer
        latency time.Duration
        failed  bool
    }
    var probeResults []probeResult
    minLatency := time.Duration(1<<63 - 1)
    var bestServer *wgServer
    for i, s := range melRegion.Servers.WG {
        start := time.Now()
        conn, err := newDialer().DialContext(context.Background(), "tcp", net.JoinHostPort(s.IP, "1337"))
        latency := time.Since(start)
        if err == nil {
            conn.Close()
            if latency < minLatency {
                minLatency = latency
                bestServer = &melRegion.Servers.WG[i]
            }
            probeResults = append(probeResults, probeResult{server: s, latency: latency, failed: false})
        } else {
            probeResults = append(probeResults, probeResult{server: s, latency: 0, failed: true})
        }
    }
    if bestServer == nil {
        fmt.Fprintf(os.Stderr, "All latency probes failed for region %q WireGuard servers\n", regionFlag)
        os.Exit(1)
    }

    if verbose {
        sort.Slice(probeResults, func(i, j int) bool {
            if probeResults[i].failed {
                return false
            }
            if probeResults[j].failed {
                return true
            }
            return probeResults[i].latency < probeResults[j].latency
        })
        fmt.Fprintf(os.Stderr, "\n%-20s  %-45s  %s\n", "IP", "CN", "Latency")
        fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 75))
        for _, r := range probeResults {
            if r.failed {
                fmt.Fprintf(os.Stderr, "%-20s  %-45s  %s\n", r.server.IP, r.server.CN, "probe failed")
            } else {
                marker := ""
                if r.server.IP == bestServer.IP {
                    marker = " <-- selected"
                }
                fmt.Fprintf(os.Stderr, "%-20s  %-45s  %v%s\n", r.server.IP, r.server.CN, r.latency, marker)
            }
        }
        fmt.Fprintf(os.Stderr, "\n")
    }
    
    // Authenticate to get token
    token, err := getPIAToken(ctx, username, password)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Authentication failed: %v\n", err)
        os.Exit(1)
    }
    if token == "" {
        fmt.Fprintln(os.Stderr, "Received empty token from PIA")
        os.Exit(1)
    }

    // Generate WireGuard keypair
    priv, pub, err := generateWGKeypair()
    if err != nil {
        fmt.Fprintf(os.Stderr, "WireGuard key generation failed: %v\n", err)
        os.Exit(1)
    }

    // Register public key
    regResp, rawReg, err := registerWGKey(ctx, bestServer, token, pub)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Registration failed: %v\n", err)
        os.Exit(1)
    }
    if verbose {
        fmt.Fprintf(os.Stderr, "Registration response: %s\n", rawReg)
    }
    if regResp.Status != "OK" {
        fmt.Fprintf(os.Stderr, "Registration status not OK: %s\n", regResp.Status)
        os.Exit(1)
    }

    peerIP := regResp.PeerIP
    if idx := strings.Index(peerIP, "/"); idx != -1 {
        peerIP = peerIP[:idx]
    }
    peerIP += "/32"

    confPath, err := resolveOutputPath(regionFlag)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to resolve output path: %v\n", err)
        os.Exit(1)
    }
    if _, err := os.Stat(confPath); err == nil {
        fmt.Printf("Overwrite existing file? [y/N]: ")
        ans, _ := reader.ReadString('\n')
        ans = strings.TrimSpace(ans)
        if ans != "y" && ans != "Y" {
            fmt.Fprintln(os.Stderr, "Aborted by user; file not overwritten.")
            os.Exit(1)
        }
    }

    config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = 1420\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nPersistentKeepalive = 25\nAllowedIPs = 0.0.0.0/0\n", priv, peerIP, dnsFlag, regResp.ServerKey, bestServer.IP, regResp.ServerPort)
	config = strings.ReplaceAll(config, "\r", "")
	if err := os.WriteFile(confPath, []byte(config), 0600); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to write config file: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("WireGuard config written to %s\n", confPath)
}

func buildSystemCertPool() *x509.CertPool {
    pool, err := x509.SystemCertPool()
    if err != nil || pool == nil {
        pool = x509.NewCertPool()
    }
    if runtime.GOOS == "linux" {
        // Standard Linux CA bundle locations plus hardcoded Termux path --
        // do not rely on $PREFIX env var as it is not reliably inherited by child processes
        bundleFiles := []string{
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/ssl/certs/ca-bundle.crt",
            "/data/data/com.termux/files/usr/etc/tls/cert.pem",
        }
        // Also try PREFIX if it happens to be set
        if prefix := os.Getenv("PREFIX"); prefix != "" {
            bundleFiles = append(bundleFiles,
                filepath.Join(prefix, "etc/tls/cert.pem"),
                filepath.Join(prefix, "etc/ca-certificates/ca-certificates.crt"),
            )
        }
        for _, f := range bundleFiles {
            if certBytes, err := os.ReadFile(f); err == nil {
                pool.AppendCertsFromPEM(certBytes)
            }
        }
        // Android system CA directory (individual cert files)
        androidCADir := "/system/etc/security/cacerts"
        if entries, err := os.ReadDir(androidCADir); err == nil {
            for _, entry := range entries {
                if entry.IsDir() {
                    continue
                }
                if certBytes, err := os.ReadFile(filepath.Join(androidCADir, entry.Name())); err == nil {
                    pool.AppendCertsFromPEM(certBytes)
                }
            }
        }
    }
    return pool
}

func newDialer() *net.Dialer {
    return &net.Dialer{
        Timeout: 10 * time.Second,
        Resolver: &net.Resolver{
            PreferGo: true,
            Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
                d := net.Dialer{Timeout: 5 * time.Second}
                return d.DialContext(ctx, "udp", "8.8.8.8:53")
            },
        },
    }
}

func resolveOutputPath(regionFlag string) (string, error) {
    filename := "pia-" + regionFlag + ".conf"
    switch runtime.GOOS {
    case "windows":
        userProfile := os.Getenv("USERPROFILE")
        if userProfile == "" {
            return "", errors.New("USERPROFILE environment variable is not set")
        }
        return filepath.Join(userProfile, "Desktop", filename), nil
    default:
        cwd, err := os.Getwd()
        if err != nil {
            return "", fmt.Errorf("failed to determine current working directory: %w", err)
        }
        return filepath.Join(cwd, filename), nil
    }
}

func getPIAToken(ctx context.Context, username, password string) (string, error) {
    req, err := http.NewRequestWithContext(ctx, "POST", "https://www.privateinternetaccess.com/gtoken/generateToken", nil)
    if err != nil {
        return "", fmt.Errorf("creating request: %w", err)
    }
    req.SetBasicAuth(username, password)
    httpClient := &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            DialContext: newDialer().DialContext,
            TLSClientConfig: &tls.Config{
                RootCAs: buildSystemCertPool(),
            },
        },
    }
    resp, err := httpClient.Do(req)
    if err != nil {
        return "", fmt.Errorf("token request failed: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return "", fmt.Errorf("token request returned status %d", resp.StatusCode)
    }
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("reading token response: %w", err)
    }
    var tok struct {
        Token string `json:"token"`
    }
    if err := json.Unmarshal(body, &tok); err != nil {
        return "", fmt.Errorf("parsing token response: %w", err)
    }
    if tok.Token == "" {
        return "", errors.New("empty token in response")
    }
    return tok.Token, nil
}

func generateWGKeypair() (privB64, pubB64 string, err error) {
    priv := make([]byte, 32)
    if _, err = rand.Read(priv); err != nil {
        return "", "", fmt.Errorf("random read: %w", err)
    }
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    pub, err := curve25519.X25519(priv, curve25519.Basepoint)
    if err != nil {
        return "", "", fmt.Errorf("curve25519.X25519: %w", err)
    }
    privB64 = base64.StdEncoding.EncodeToString(priv)
    pubB64 = base64.StdEncoding.EncodeToString(pub)
    return privB64, pubB64, nil
}

type regResponse struct {
    Status    string `json:"status"`
    ServerKey string `json:"server_key"`
    PeerIP    string `json:"peer_ip"`
    ServerPort int   `json:"server_port"`
}

func registerWGKey(ctx context.Context, server *wgServer, token, pubkey string) (regResponse, string, error) {
    caCertClient := &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            DialContext: newDialer().DialContext,
            TLSClientConfig: &tls.Config{
                RootCAs: buildSystemCertPool(),
            },
        },
    }
    caCertResp, err := caCertClient.Get("https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt")
	if err != nil {
		return regResponse{}, "", fmt.Errorf("failed to fetch PIA CA certificate: %w", err)
	}
	defer caCertResp.Body.Close()
	caCertBytes, err := io.ReadAll(caCertResp.Body)
	if err != nil {
		return regResponse{}, "", fmt.Errorf("failed to read PIA CA certificate: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertBytes) {
		return regResponse{}, "", errors.New("failed to parse PIA CA certificate")
	}
    tlsConfig := &tls.Config{
        RootCAs:    caPool,
        ServerName: server.CN,
    }
    httpClient := &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
            DialContext:     newDialer().DialContext,
        },
    }
    urlStr := fmt.Sprintf("https://%s:1337/addKey?pt=%s&pubkey=%s", server.IP, url.QueryEscape(token), url.QueryEscape(pubkey))
    req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
    if err != nil {
        return regResponse{}, "", fmt.Errorf("creating registration request: %w", err)
    }
    resp, err := httpClient.Do(req)
    if err != nil {
        return regResponse{}, "", fmt.Errorf("registration request failed: %w", err)
    }
    defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return regResponse{}, "", fmt.Errorf("reading registration response: %w", err)
    }
    if resp.StatusCode != 200 {
        return regResponse{}, string(body), fmt.Errorf("registration returned status %d", resp.StatusCode)
    }
    var reg regResponse
    if err := json.Unmarshal(body, &reg); err != nil {
        return regResponse{}, string(body), fmt.Errorf("parsing registration response: %w", err)
    }
    return reg, string(body), nil
}

func printHelp() {
    os.Stdout.WriteString("\npia-wireguard-cfg v" + programVersion + `
Generates a WireGuard configuration file for Private Internet Access (PIA) VPN.
Authenticates with PIA, selects the lowest-latency server in the specified region,
generates a WireGuard keypair, and writes a ready-to-use .conf file to your desktop.

Usage:

  pia-wireguard-cfg.exe [-username PIA_username] [-region region_id] [-list-regions]
                        [-dns "dns_servers"] [-verbose] [-help] [-?]

Parameters:
  -username      PIA account username (e.g., p1234567). If omitted you will be prompted interactively.
  -region        PIA region ID to connect through. If omitted you will be prompted interactively.
                  Run -list-regions to see all available region IDs.
  -list-regions  Print all available PIA regions with their WireGuard server counts, does not require credentials.
  -dns           DNS servers to write into the config file, comma-separated (default: "9.9.9.9, 149.112.112.112").
  -verbose       Print diagnostic output to stderr: resolved server IP and CN, measured
                  latency, and raw PIA registration response.
  -help, -?      Show this help message.
  /help, /?      Show this help message.

Examples:
  pia-wireguard-cfg.exe -username p1234567
  pia-wireguard-cfg.exe -username p1234567 -region aus_melbourne
  pia-wireguard-cfg.exe -username p1234567 -region us_new_york_city -dns "1.1.1.1, 1.0.0.1"
  pia-wireguard-cfg.exe -username p1234567 -dns "8.8.8.8, 8.8.4.4" -verbose
  pia-wireguard-cfg.exe -list-regions
  pia-wireguard-cfg.exe -help

Output:
  Windows:       %USERPROFILE%\Desktop\pia-<region>.conf
  Linux/Android: <current working directory>/pia-<region>.conf

  Where <region> is the name of the chosen region (e.g. pia-aus_melbourne.conf).
  If the file already exists you will be prompted before it is overwritten.

Android/Termux:
  After transferring the Linux binary to your device, run:
    chmod +x pia-wireguard-cfg-linux-arm64
  before executing it. Run from within the Termux home directory (~/) to ensure
  the output .conf file is written to an accessible location.

Authentication:
  You will always be prompted interactively for your PIA password.
  Your password is never stored or written to disk.
  PIA credentials are used only to obtain a short-lived token for server registration.

DNS defaults:
  9.9.9.9          Quad9 primary
  149.112.112.112  Quad9 secondary

  Alternative well-known DNS servers:
    Cloudflare:  1.1.1.1, 1.0.0.1
    Google:      8.8.8.8, 8.8.4.4
`)
}
Modify the existing `pia-wireguard-cfg` Go app to also build as a Linux binary suitable for running on Android (via Termux) on ARM64 devices such as the Google Pixel 7 Pro and Samsung Galaxy Tab S10 FE. All compilation is done on Windows only.

**Program version constant**

Add a `programVersion` constant near the top of `main.go`, immediately after the import block and before the type declarations:

```go
const programVersion = "1.0.2"
```

Update `printHelp()` to use this constant instead of a hardcoded version string. Replace the hardcoded version line at the start of the help output with a concatenation that injects the constant, then immediately resume the raw string literal for the rest of the help text:

```go
os.Stdout.WriteString("pia-wireguard-cfg v" + programVersion + `
Generates a WireGuard configuration file...
```

This constant is also used by the build script to extract the version and update `versioninfo.json` before building.

**Output path changes**

Replace the current hardcoded Windows-only output path logic with a platform-aware helper function using `runtime.GOOS`:

- On `"windows"`: retain the existing behaviour -- resolve the output path as `filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "pia-"+regionFlag+".conf")` and abort with a clear error if `USERPROFILE` is not set.
- On all other platforms: resolve the output path using `os.Getwd()` and produce `"pia-"+regionFlag+".conf"` in the current working directory. If `os.Getwd()` returns an error, abort with a clear error.

Implement this as `func resolveOutputPath(regionFlag string) (string, error)` switching on `runtime.GOOS`.

**Build script**

Create a `build.bat` Windows batch file in the project root. This script must:

1. Extract the version string from the `programVersion` constant in `main.go`
2. Update `versioninfo.json` with the extracted version (major, minor, patch components) using PowerShell
3. Run `go generate` to embed version resources into the Windows binary via `goversioninfo`
4. Build the Windows AMD64 binary as `pia-wireguard-cfg.exe`
5. Build the Linux ARM64 binary as `pia-wireguard-cfg`
6. Restore all environment variables on exit

```bat
@echo off
REM Build script for pia-wireguard-cfg
REM Extracts version from Go source, updates versioninfo.json, then builds both binaries

setlocal enabledelayedexpansion

if "%1"=="--help" goto :help
if "%1"=="-help" goto :help
if "%1"=="-?" goto :help
if "%1"=="/?" goto :help

REM Check we are in the right directory
if not exist "main.go" (
    echo Error: Must be run from the project root directory
    exit /b 1
)

REM Extract version from Go source
echo Extracting version from main.go...
for /f "tokens=2 delims==" %%a in ('findstr "programVersion.*=" main.go') do (
    set version_line=%%a
)

REM Clean up the version string (remove quotes and spaces)
set version_line=!version_line: =!
set version_line=!version_line:"=!
set current_version=!version_line!

if "!current_version!"=="" (
    echo Error: Could not extract version from main.go
    exit /b 1
)

echo Detected version: !current_version!

REM Parse version components
for /f "tokens=1,2,3 delims=." %%a in ("!current_version!") do (
    set major=%%a
    set minor=%%b
    set patch=%%c
)

REM Update versioninfo.json
echo Updating versioninfo.json to version !current_version!...
powershell -Command "& { $v = Get-Content 'versioninfo.json' | ConvertFrom-Json; $v.FixedFileInfo.FileVersion.Major = !major!; $v.FixedFileInfo.FileVersion.Minor = !minor!; $v.FixedFileInfo.FileVersion.Patch = !patch!; $v.FixedFileInfo.ProductVersion.Major = !major!; $v.FixedFileInfo.ProductVersion.Minor = !minor!; $v.FixedFileInfo.ProductVersion.Patch = !patch!; $v.StringFileInfo.FileVersion = '!current_version!.0'; $v.StringFileInfo.ProductVersion = '!current_version!.0'; $v | ConvertTo-Json -Depth 10 | Out-File 'versioninfo.json' -Encoding ASCII }"
if errorlevel 1 (
    echo Error: Failed to update versioninfo.json
    exit /b 1
)
echo Updated versioninfo.json with version !current_version!

REM Run go generate to embed version info into Windows binary via goversioninfo
echo Running go generate...
go generate
if errorlevel 1 (
    echo Error: go generate failed
    exit /b 1
)
echo go generate completed successfully

REM Build Windows AMD64
echo Building Windows AMD64...
SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=amd64
go build -o pia-wireguard-cfg.exe
if errorlevel 1 (
    echo Error: Windows build failed
    goto :cleanup
)
echo Done: pia-wireguard-cfg.exe

REM Build Linux ARM64
echo Building Linux ARM64...
SET GOOS=linux
SET GOARCH=arm64
go build -o pia-wireguard-cfg
if errorlevel 1 (
    echo Error: Linux build failed
    goto :cleanup
)
echo Done: pia-wireguard-cfg

echo.
echo Both binaries built successfully.
goto :cleanup

:help
echo.
echo Build script for pia-wireguard-cfg
echo.
echo Usage: build.bat [options]
echo.
echo Options:
echo   --help, -help, -?  Show this help message
echo.
echo This script will:
echo   1. Extract the version from the programVersion constant in main.go
echo   2. Update versioninfo.json with the extracted version
echo   3. Run go generate to embed version resources into the Windows binary
echo   4. Build the Windows AMD64 binary: pia-wireguard-cfg.exe
echo   5. Build the Linux ARM64 binary:   pia-wireguard-cfg
echo.

:cleanup
SET GOOS=
SET GOARCH=
SET CGO_ENABLED=
endlocal
```

`CGO_ENABLED=0` is required because `golang.org/x/crypto/curve25519` must build without CGo for cross-compilation to work.

**Android DNS fix**

Android does not run a local DNS resolver, so Go's default DNS lookup fails on Termux. All HTTP clients and the TCP latency prober must use a custom dialer that bypasses the system resolver and dials Google DNS directly. Implement this as a helper function:

```go
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
```

Use `newDialer().DialContext` as the `DialContext` in every `http.Transport` in the app. Use `newDialer().DialContext` for the TCP latency probes instead of `net.DialTimeout`.

**Android TLS fix**

Android does not store CA certificates in any of the standard Linux locations Go looks for, so `x509.SystemCertPool()` returns an empty pool on Android. Implement a helper function that loads CA certificates from all known locations including the Termux-specific path. The Termux path must be hardcoded as `/data/data/com.termux/files/usr/etc/tls/cert.pem` because the `$PREFIX` environment variable is not reliably inherited by child processes on Android:

```go
func buildSystemCertPool() *x509.CertPool {
    pool, err := x509.SystemCertPool()
    if err != nil || pool == nil {
        pool = x509.NewCertPool()
    }
    if runtime.GOOS == "linux" {
        bundleFiles := []string{
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/ssl/certs/ca-bundle.crt",
            // Hardcoded Termux path -- PREFIX env var is not reliably inherited by child processes
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
```

Apply `buildSystemCertPool()` as the `RootCAs` in the `tls.Config` of every HTTP client that uses the system CA pool (server list fetch, token API, and PIA CA cert fetch). The registration API client uses PIA's own CA cert pool and is not affected.

**PIA CA certificate fetch**

The `registerWGKey` function fetches PIA's CA certificate from GitHub at runtime. This fetch must also use the custom dialer and system cert pool -- do NOT use the default `http.Get()` for this call. The CA certificate must always be fetched dynamically so it stays current if PIA rotate it; it must never be hardcoded as a constant. Implement it as a dedicated HTTP client:

```go
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
```

**Four distinct HTTP clients required**

There must be exactly four HTTP client instances in the app, each configured correctly:

1. **Server list fetch** -- `newDialer().DialContext`, `buildSystemCertPool()` TLS root pool.
2. **Token API** -- `newDialer().DialContext`, `buildSystemCertPool()` TLS root pool.
3. **PIA CA cert fetch** (inside `registerWGKey`) -- `newDialer().DialContext`, `buildSystemCertPool()` TLS root pool.
4. **Registration API** (inside `registerWGKey`) -- `newDialer().DialContext`, PIA CA cert pool, `ServerName` set to server CN.

No HTTP client anywhere in the app may use the default Go transport or a transport without `newDialer().DialContext`.

**Update the comment block at the top of `main.go`** to replace the single build command with a reference to `build.bat` as the recommended way to produce both binaries, document both output binary names, and include the following note:

  To run on Android via Termux, transfer `pia-wireguard-cfg` to the device,
  then in Termux run:
    chmod +x pia-wireguard-cfg
  Run the binary from within the Termux home directory (~/) to ensure the output
  .conf file is written to an accessible location.
  You may need to install the CA certificates package: pkg install ca-certificates

**Update `printHelp()`** to document the platform-specific output path behaviour:

- Windows: `%USERPROFILE%\Desktop\pia-<region>.conf`
- Linux/Android: `<current working directory>/pia-<region>.conf`

Also include the following note in the Linux/Android section of the help output:

  On Android via Termux: after transferring the binary to your device, run
    chmod +x pia-wireguard-cfg
  before executing it. Run from within the Termux home directory (~/) to ensure
  the output .conf file is written to an accessible location.
  If you see TLS errors, run: pkg install ca-certificates

**stdin handling**

Ensure the overwrite confirmation prompt uses the same shared `reader` instance declared at the top of `main()` and that no new `bufio.Reader` is declared anywhere else in the function. Multiple readers on the same stdin stream can cause missed input on non-Windows platforms including Android/Termux.

**Verification step**

After making all changes, explicitly verify that:

1. The old inline output path logic in `main()` (the direct `filepath.Join(os.Getenv("USERPROFILE"), ...)` call) has been fully removed and replaced with a call to `resolveOutputPath(regionFlag)`. There must be no remaining reference to `USERPROFILE` outside of `resolveOutputPath` itself.
2. The `resolveOutputPath` function is the sole place in the codebase that determines the output file path.
3. `main()` handles the error return from `resolveOutputPath` and aborts with a clear error message if it fails.
4. Every HTTP client in the app uses `newDialer().DialContext` -- there must be no remaining calls to `http.Get()` or any `http.Transport` without a custom `DialContext`.
5. The server list fetch, token API, and PIA CA cert fetch clients all use `buildSystemCertPool()` as the TLS root pool.
6. The `programVersion` constant is declared at the top of `main.go` and `printHelp()` uses it rather than a hardcoded version string.

If any of these conditions are not met, fix them before finishing.

**No other behaviour should change.** All flag handling, server selection, keypair generation, registration, DNS options, overwrite prompting, and config file format remain identical on both platforms.

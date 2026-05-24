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
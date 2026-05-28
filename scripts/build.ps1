# Cross-compile static binaries for common Keenetic/Entware architectures (Windows dev).
# Usage: powershell -File scripts/build.ps1 [-Version v1.0.0]
param([string]$Version = "dev")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
New-Item -ItemType Directory -Force -Path dist | Out-Null
$ld = "-s -w -X main.version=$Version"
$pkg = "./cmd/nfqws2-strategy"

function Build($goarch, $goarm, $gomips, $name) {
  $env:GOOS = "linux"; $env:GOARCH = $goarch; $env:CGO_ENABLED = "0"
  if ($goarm) { $env:GOARM = $goarm } else { Remove-Item Env:GOARM -ErrorAction SilentlyContinue }
  if ($gomips) { $env:GOMIPS = $gomips } else { Remove-Item Env:GOMIPS -ErrorAction SilentlyContinue }
  go build -trimpath -ldflags $ld -o "dist/nfqws2-strategy-linux-$name" $pkg
  if ($LASTEXITCODE -ne 0) { throw "build $name failed" }
  Write-Output ("built {0} ({1} bytes)" -f $name, (Get-Item "dist/nfqws2-strategy-linux-$name").Length)
}

Write-Output "building version=$Version"
Build "arm64"  $null  $null        "arm64"
Build "arm"    "7"    $null        "arm"
Build "mipsle" $null  "softfloat"  "mipsle"
Build "mips"   $null  "softfloat"  "mips"
Remove-Item Env:GOOS,Env:GOARCH,Env:CGO_ENABLED,Env:GOARM,Env:GOMIPS -ErrorAction SilentlyContinue

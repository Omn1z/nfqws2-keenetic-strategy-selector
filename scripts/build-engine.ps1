# Pinned AmneziaWG 3.1 source with our security dependency lock. Requires Go 1.26.8+.
# Set GOVULNCHECK to check an audit build per target, kept outside release assets.
param([string]$Go = "go", [string]$Ref = "v3.1.20260828")
$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$engineWork = Join-Path $projectRoot '.engine-build'
$engineSource = Join-Path $engineWork 'amneziawg-go'
$outputDir = Join-Path $projectRoot 'dist'
$moduleFile = Join-Path $projectRoot 'internal/services/awg/engine-deps.mod'
New-Item -ItemType Directory -Force -Path $engineWork,$outputDir | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $engineSource '.git'))) {
    git clone --no-checkout --depth 1 https://github.com/amnezia-vpn/amneziawg-go $engineSource
    if ($LASTEXITCODE) { throw 'engine clone failed' }
}
git -C $engineSource fetch --depth 1 origin "refs/tags/${Ref}:refs/tags/${Ref}"
if ($LASTEXITCODE) { throw 'engine fetch failed' }
git -C $engineSource checkout --detach $Ref
if ($LASTEXITCODE) { throw 'engine checkout failed' }
# The dependency lock must be reviewed together with any source-pin update.
if ((git -C $engineSource rev-parse HEAD) -ne 'b5928efb6ca19f0153958460c3d141f04abc5c2e') { throw 'unexpected upstream revision for dependency lock' }

$savedEnv = @{}
foreach ($key in @('GOOS','GOARCH','CGO_ENABLED','GOARM','GOMIPS')) { $savedEnv[$key] = [Environment]::GetEnvironmentVariable($key,'Process') }
Push-Location $engineSource
try {
    $env:GOOS = 'linux'; $env:CGO_ENABLED = '0'
    foreach ($arch in @('arm64','arm','mipsle','mips')) {
        $env:GOARCH = $arch
        [Environment]::SetEnvironmentVariable('GOARM',$(if ($arch -eq 'arm') { '7' } else { $null }),'Process')
        [Environment]::SetEnvironmentVariable('GOMIPS',$(if ($arch -like 'mips*') { 'softfloat' } else { $null }),'Process')
        $stage = Join-Path $engineWork "stage-$arch"
        New-Item -ItemType Directory -Force -Path $stage | Out-Null
        # Keep upstream files untouched and forbid implicit dependency changes.
        & $Go build "-modfile=$moduleFile" '-mod=readonly' -trimpath -ldflags '-s -w' -o (Join-Path $stage 'amneziawg-go') .
        if ($LASTEXITCODE) { throw "engine build $arch failed" }
        if ($env:GOVULNCHECK) {
            $auditDir = Join-Path $engineWork "audit-$arch"
            New-Item -ItemType Directory -Force -Path $auditDir | Out-Null
            $auditBinary = Join-Path $auditDir 'amneziawg-go'
            # Stripped binaries make govulncheck assume every package in each
            # linked module is present. Keep symbols for accurate scanning.
            & $Go build "-modfile=$moduleFile" '-mod=readonly' -trimpath -ldflags '-w' -o $auditBinary .
            if ($LASTEXITCODE) { throw "engine audit build $arch failed" }
            & $env:GOVULNCHECK '-mode=binary' $auditBinary
            if ($LASTEXITCODE) { throw "engine vulnerability scan $arch failed" }
        }
        $asset = "awg-engine-linux-$arch.tar.gz"
        $archive = Join-Path $outputDir $asset
        tar -czf $archive -C $stage amneziawg-go
        if ($LASTEXITCODE) { throw "engine archive $arch failed" }
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText("$archive.sha256", "$hash  $asset`n", [Text.UTF8Encoding]::new($false))
        Write-Output "packaged $asset ($Ref)"
    }
} finally {
    Pop-Location
    foreach ($key in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($key,$savedEnv[$key],'Process') }
}

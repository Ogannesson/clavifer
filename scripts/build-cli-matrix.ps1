param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) {
  $OutputDirectory = Join-Path $repo ('work\cli-build-matrix\' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new output directory; existing build artifacts are preserved.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$previousGoOS, $previousGoArch, $previousCGO = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
$targets = @('windows/amd64','windows/arm64','linux/amd64','linux/arm64','darwin/amd64','darwin/arm64')
$artifacts = @()
Push-Location $repo
try {
  foreach ($target in $targets) {
    $env:GOOS, $env:GOARCH = $target.Split('/')
    $env:CGO_ENABLED = '0'
    $fileName = 'clavifer-' + $env:GOOS + '-' + $env:GOARCH
    if ($env:GOOS -eq 'windows') { $fileName += '.exe' }
    $output = Join-Path $OutputDirectory $fileName
    Write-Output "Compiling $target; retaining Go work files."
    & go build -work -trimpath -o $output ./cmd/clavifer
    if ($LASTEXITCODE -ne 0) { throw "CLI build failed for $target." }
    $artifacts += [ordered]@{ target=$target; file=$fileName; bytes=(Get-Item -LiteralPath $output).Length; sha256=(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant(); verification='cross-compiled; platform credential store requires native acceptance' }
  }
  $manifest = [ordered]@{ createdAt=[DateTime]::UtcNow.ToString('o'); version=(Get-Content -LiteralPath package.json -Raw | ConvertFrom-Json).version; artifacts=$artifacts }
  $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8
  Write-Output "CLI matrix and checksum manifest retained at $OutputDirectory"
} finally {
  $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $previousGoOS, $previousGoArch, $previousCGO
  Pop-Location
}

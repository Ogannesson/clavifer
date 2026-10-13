param(
  [Parameter(Mandatory=$true)][string]$Target,
  [ValidateSet('user','project')][string]$Scope='user',
  [switch]$Force
)
$ErrorActionPreference = 'Stop'
$source = (Resolve-Path (Join-Path $PSScriptRoot '..\skills\clavifer')).Path
$destination = if ($Scope -eq 'project') { Join-Path (Get-Location) $Target } else { Join-Path $env:USERPROFILE $Target }
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$manifestPath = Join-Path $destination '.clavifer-install.json'
$previous = if (Test-Path -LiteralPath $manifestPath) { Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable } else { @{} }
$files = @(Get-ChildItem -LiteralPath $source -Recurse -File)
foreach ($file in $files) {
  $relative = [IO.Path]::GetRelativePath($source, $file.FullName)
  $out = Join-Path $destination $relative
  if ((Test-Path -LiteralPath $out) -and -not $Force) {
    $current = (Get-FileHash -LiteralPath $out).Hash
    $incoming = (Get-FileHash -LiteralPath $file.FullName).Hash
    if ($current -ne $incoming -and $previous[$relative] -ne $current) { throw "Local changes preserved: $out. Review them before using -Force." }
  }
}
$next = @{}
$files | ForEach-Object {
  $relative = $_.FullName.Substring($source.Length).TrimStart('\')
  $out = Join-Path $destination $relative
  New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
  Copy-Item -LiteralPath $_.FullName -Destination $out -Force
  $next[$relative] = (Get-FileHash -LiteralPath $out).Hash
}
$next | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output "Installed clavifer Skill at $destination"

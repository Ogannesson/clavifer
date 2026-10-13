$ErrorActionPreference = 'Stop'
# The executable is the repository's build output (dist\) or, when the integrations
# folder was copied elsewhere together with a built executable, the one beside that folder.
$source = @('..\..\dist\clavifer.exe','..\..\clavifer.exe') |
  ForEach-Object { Join-Path $PSScriptRoot $_ } |
  Where-Object { Test-Path -LiteralPath $_ } |
  Select-Object -First 1
if (-not $source) { throw 'clavifer.exe not found. Build it with npm run build:cli, or put a built clavifer.exe beside the integrations folder.' }
$directory = Join-Path $env:LOCALAPPDATA 'clavifer\bin'
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$target = Join-Path $directory 'clavifer.exe'
try { Copy-Item -LiteralPath $source -Destination $target -Force }
catch { throw "Cannot replace $target. Close the hosts still running it, then retry." }
Write-Output "Installed $((Resolve-Path -LiteralPath $source).Path) to $target"
Write-Output "Point each host's MCP command at this absolute path: $target"

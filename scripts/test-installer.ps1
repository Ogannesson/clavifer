$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$sandbox = Join-Path $repo ('work\installer-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $sandbox | Out-Null
$installer = Join-Path $repo 'integrations\adapters\install-skill.ps1'
Push-Location $sandbox
try {
  & $installer -Target '.agents\skills\clavifer' -Scope project
  & $installer -Target '.agents\skills\clavifer' -Scope project
  $file = Join-Path $sandbox '.agents\skills\clavifer\SKILL.md'
  Add-Content -LiteralPath $file -Value "`nLocal user customization preserved by test."
  $before = (Get-FileHash -LiteralPath $file).Hash
  $refused = $false
  try { & $installer -Target '.agents\skills\clavifer' -Scope project }
  catch { if ($_.Exception.Message -notlike 'Local changes preserved:*') { throw }; $refused = $true }
  if (-not $refused -or (Get-FileHash -LiteralPath $file).Hash -ne $before) { throw 'Installer overwrote or accepted local changes.' }
  Write-Output 'Installer passed: repeat installation, modified-file refusal, and preservation of user edits.'
} finally { Pop-Location }

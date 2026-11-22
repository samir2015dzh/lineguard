# Runs inside a real logon session of a throwaway CI user (started by ci-windows-smoke.ps1).
# Console mode deliberately requires a non-SYSTEM token with a logon-session SID.
param([Parameter(Mandatory = $true)][string]$Dir)
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$svc = Join-Path $Dir 'lineguard-service.exe'
$ctl = Join-Path $Dir 'lineguardctl.exe'
$log = Join-Path $Dir 'console-result.txt'
function Say($t) { Add-Content -Path $log -Value $t -Encoding utf8 }
function Run([string[]]$argv) {
  $out = & $ctl @argv 2>&1 | Out-String
  Say $out.TrimEnd(); Say "[exit $LASTEXITCODE]"
  return [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
}
function Expect($c, $m) { if ($c) { Say "PASS: $m" } else { Say "FAIL: $m" } }
Say ("logon SID groups: " + ((& whoami.exe /groups /fo csv | Select-String 'S-1-5-5-' | Measure-Object).Count))
Say ("LOCALAPPDATA exists: " + (Test-Path $env:LOCALAPPDATA))
try { $t = Join-Path $env:LOCALAPPDATA 'lg-write-test'; Set-Content $t 'x'; Remove-Item $t; Say 'LOCALAPPDATA writable: True' } catch { Say "LOCALAPPDATA writable: False ($($_.Exception.Message))" }
$p = Start-Process -FilePath $svc -ArgumentList '--console' -PassThru -NoNewWindow `
  -RedirectStandardError (Join-Path $Dir 'service-stderr.txt')
Start-Sleep -Seconds 3
try {
  $r = Run @('--console', 'status'); Expect ($r.Code -eq 0) 'ctl --console status over named pipe'
  $r = Run @('--console', 'import', (Join-Path $Dir 'offline.example.json'))
  Expect ($r.Code -eq 0) 'offline import is validated and saved'
  $r = Run @('--console', 'status')
  Expect ($r.Code -eq 0 -and $r.Out -match '"generation":\s*1') 'generation advanced after import'
  $r = Run @('--console', 'diagnostics')
  Expect ($r.Code -eq 0 -and $r.Out -notmatch 'example-not-a-real-credential') 'diagnostics succeed and do not leak the password'
  $r = Run @('--console', 'connect'); Expect ($r.Code -ne 0) 'connect stays unsupported'
} finally {
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  if (Test-Path (Join-Path $Dir 'service-stderr.txt')) { Say (Get-Content (Join-Path $Dir 'service-stderr.txt') -Raw) }
  Say 'DONE'
}

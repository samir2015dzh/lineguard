# Windows runtime smoke test. ONLY for a disposable CI VM (GitHub-hosted runner):
# it installs the experimental block-all-IP WFP rules, checks they really cut IP traffic,
# then removes them with the independent rescue. Never run this on a real computer.
param([Parameter(Mandatory = $true)][string]$Bin)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'refusing: only runs on a disposable GitHub Actions VM' }

$Bin = (Resolve-Path $Bin).Path
$ctl = Join-Path $Bin 'lineguardctl.exe'
$svc = Join-Path $Bin 'lineguard-service.exe'
$rescue = Join-Path $Bin 'lineguard-rescue.exe'
$failures = [System.Collections.Generic.List[string]]::new()

function Step($name) { Write-Host "`n=== $name ===" }
function Run($exe, [string[]]$argv) {
  $out = & $exe @argv 2>&1 | Out-String
  $code = $LASTEXITCODE
  Write-Host $out.TrimEnd()
  Write-Host "[exit $code]"
  return [pscustomobject]@{ Code = $code; Out = $out }
}
function Expect($cond, $msg) {
  if ($cond) { Write-Host "PASS: $msg" } else { Write-Host "FAIL: $msg"; $failures.Add($msg) }
}
function Json($text) {
  $start = $text.IndexOf('{'); $end = $text.LastIndexOf('}')
  if ($start -lt 0 -or $end -le $start) { return $null }
  try { return $text.Substring($start, $end - $start + 1) | ConvertFrom-Json } catch { return $null }
}
function CanConnect($ip, $port) {
  $c = [Net.Sockets.TcpClient]::new()
  try { return $c.ConnectAsync($ip, $port).Wait(3000) -and $c.Connected } catch { return $false } finally { $c.Dispose() }
}

Step 'versions and read-only rescue inspect'
$r = Run $rescue @('--version'); Expect ($r.Code -eq 0 -and $r.Out -match 'PermitRevoke\.v3') 'rescue --version carries v3 marker'
$r = Run $rescue @('inspect'); Expect ($r.Code -eq 0) 'rescue inspect (read-only) succeeds'

Step 'console IPC in a real logon session of a throwaway user'
# The runner token has no logon-session SID, which console mode requires by design, so start a
# genuine logon session for a temporary local user instead.
$work = 'C:\lgsmoke'
New-Item -ItemType Directory -Force -Path $work | Out-Null
Copy-Item (Join-Path $Bin '*.exe') $work
Copy-Item 'examples/offline.example.json' $work
Copy-Item 'scripts/ci-windows-console.ps1' $work
# net user prompts (and fails non-interactively) for passwords longer than 14 characters.
$pw = 'L!' + [guid]::NewGuid().ToString('N').Substring(0, 10) + 'a'
& net.exe user lgsmoke $pw /add | Out-Host
Expect ($LASTEXITCODE -eq 0) 'temporary console-test user created'
& icacls.exe $work /grant 'lgsmoke:(OI)(CI)M' | Out-Null
# Start-Process -Credential did not load the profile (no LocalAppData). A scheduled task does a
# full batch logon with profile; Administrators membership grants the batch-logon right, and
# RunLevel Limited keeps the console process unelevated.
& net.exe localgroup Administrators lgsmoke /add | Out-Null
$pwsh = (Get-Command pwsh).Source
$action = New-ScheduledTaskAction -Execute $pwsh -WorkingDirectory $work `
  -Argument "-NoProfile -NonInteractive -File `"$work\ci-windows-console.ps1`" -Dir `"$work`""
Register-ScheduledTask -TaskName 'LineGuardConsoleSmoke' -Action $action -User 'lgsmoke' -Password $pw `
  -RunLevel Limited -Force | Out-Null
Start-ScheduledTask -TaskName 'LineGuardConsoleSmoke'
$deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
  $f = Join-Path $work 'console-result.txt'
  if ((Test-Path $f) -and ((Get-Content $f -Raw -Encoding utf8) -match 'DONE')) { break }
  Start-Sleep -Seconds 2
}
Get-ScheduledTaskInfo -TaskName 'LineGuardConsoleSmoke' | Format-List LastRunTime, LastTaskResult | Out-Host
Unregister-ScheduledTask -TaskName 'LineGuardConsoleSmoke' -Confirm:$false
$result = Join-Path $work 'console-result.txt'
if (Test-Path $result) {
  $text = Get-Content $result -Raw -Encoding utf8
  Write-Host $text
  Expect ($text -match 'DONE') 'console test ran to completion'
  foreach ($line in ($text -split "`r?`n")) {
    if ($line -like 'FAIL: *') { $failures.Add('console: ' + $line.Substring(6)) }
  }
} else { Expect $false 'console test produced a result file' }
& net.exe user lgsmoke /delete | Out-Null

Step 'preconfigure LineGuardPreview service (not started)'
& sc.exe create LineGuardPreview binPath= "`"$svc`"" start= auto obj= LocalSystem | Out-Host
& sc.exe sidtype LineGuardPreview unrestricted | Out-Host

Step 'baseline'
$r = Run $ctl @('guard', 'inspect'); $j = Json $r.Out
Expect ($r.Code -eq 0 -and $j.evidence.state -eq 'absent') 'no product rules before install'
$r = Run $ctl @('guard', 'permit', 'inspect'); $j = Json $r.Out
Expect ($r.Code -eq 0 -and $j.state -eq 'absent') 'no v3 objects before install'
Expect (CanConnect '1.1.1.1' 443) 'direct TCP works before install'

# From here the VM loses IP connectivity; everything below is local until rescue succeeds.
$installed = $false
try {
  Step 'M2 install (BLOCK-ALL-IP) and readback'
  $r = Run $ctl @('guard', 'install', '--experimental-vm-only', '--confirm', 'BLOCK-ALL-IP')
  $installed = $true
  $j = Json $r.Out
  Expect ($r.Code -eq 0 -and $j.state -eq 'configured') 'install commits and reads back 6 persistent + 6 boot'
  $r = Run $ctl @('guard', 'inspect')
  $j = Json $r.Out
  Expect ($j.evidence.state -eq 'configured' -and $j.evidence.persistent_rules -eq 6 -and $j.evidence.boot_rules -eq 6) 'fresh readback is exact'
  $r = Run $ctl @('guard', 'permit', 'inspect'); $j = Json $r.Out
  Expect ($j.state -eq 'absent') 'M2 alone has no v3 objects'
  Expect (-not (CanConnect '1.1.1.1' 443)) 'ENFORCEMENT: outbound TCP is actually blocked'
  $r = Run $ctl @('guard', 'install', '--experimental-vm-only', '--confirm', 'BLOCK-ALL-IP')
  Expect ($r.Code -eq 0) 'second install is an idempotent no-op'
} finally {
  if ($installed) {
    Step 'independent rescue remove (always attempted)'
    $r = Run $rescue @('remove', '--confirm', 'ALLOW-DIRECT')
    Expect ($r.Code -eq 0) 'rescue remove: barrier, revoke, M2 + emergency removal'
  }
}

Step 'after rescue'
$r = Run $ctl @('guard', 'inspect'); $j = Json $r.Out
Expect ($j.evidence.state -eq 'absent') 'no product rules remain'
$ok = $false
for ($i = 0; $i -lt 5 -and -not $ok; $i++) { $ok = CanConnect '1.1.1.1' 443; if (-not $ok) { Start-Sleep 2 } }
Expect $ok 'direct TCP works again after rescue'

Write-Host "`n$($failures.Count) failure(s)"
$failures | ForEach-Object { Write-Host " - $_" }
if ($failures.Count -gt 0) { exit 1 }

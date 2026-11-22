# CI-only: launch the GUI on a disposable Windows VM and capture its window, so UI changes can
# be reviewed without a Windows desktop. Uses Mesa's software OpenGL (the runner has no GPU).
param([Parameter(Mandatory = $true)][string]$Bin, [string]$Out = 'ui-screenshot.png')
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'CI only' }
$Bin = (Resolve-Path $Bin).Path

$headers = @{ Authorization = "Bearer $env:GITHUB_TOKEN"; 'User-Agent' = 'lineguard-ci' }
$rel = Invoke-RestMethod -Headers $headers 'https://api.github.com/repos/pal1000/mesa-dist-win/releases/latest'
$asset = $rel.assets | Where-Object { $_.name -match '^mesa3d-.*-release-msvc\.7z$' } | Select-Object -First 1
Write-Host "Mesa: $($asset.name)"
Invoke-WebRequest -Headers $headers $asset.browser_download_url -OutFile mesa.7z
& 7z x mesa.7z -omesa x64 -y | Out-Null
Copy-Item mesa\x64\*.dll $Bin
$env:GALLIUM_DRIVER = 'llvmpipe'

$p = Start-Process -FilePath (Join-Path $Bin 'lineguard.exe') -PassThru
for ($i = 0; $i -lt 30 -and $p.MainWindowHandle -eq 0; $i++) { Start-Sleep -Milliseconds 500; $p.Refresh() }
Start-Sleep -Seconds 4
if ($p.HasExited) { throw "GUI exited with $($p.ExitCode)" }

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class W {
  [StructLayout(LayoutKind.Sequential)] public struct R { public int L, T, Rt, B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
'@
[W]::SetProcessDPIAware() | Out-Null
$p.Refresh(); [W]::SetForegroundWindow($p.MainWindowHandle) | Out-Null; Start-Sleep -Seconds 1
$r = New-Object W+R; [W]::GetWindowRect($p.MainWindowHandle, [ref]$r) | Out-Null
$w = $r.Rt - $r.L; $h = $r.B - $r.T
Write-Host "window ${w}x${h}"
$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
Stop-Process -Id $p.Id -Force
Write-Host "saved $Out ($((Get-Item $Out).Length) bytes)"
# Also print to the log so it can be retrieved without artifact access.
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Out))
Write-Host 'BEGIN-UI-SCREENSHOT'
for ($i = 0; $i -lt $b64.Length; $i += 4000) { Write-Host $b64.Substring($i, [Math]::Min(4000, $b64.Length - $i)) }
Write-Host 'END-UI-SCREENSHOT'

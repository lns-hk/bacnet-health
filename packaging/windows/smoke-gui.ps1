<#
.SYNOPSIS
  GUI smoke test of the built bacnet-health.exe (sends nothing on the network).
.DESCRIPTION
  Launches the exe (optionally with QT_SCALE_FACTOR), checks that no console window/conhost is attached, measures
  launch-to-window time, then drives "Analyse a capture file" > "Try a sample capture" with Windows UI Automation
  and waits for the Done screen (the "Findings" tree). Saves window screenshots (PrintWindow) as
  <ShotDir>\gui-{home,analyse,done}-<Tag>.png and prints a JSON summary. Needs an interactive desktop session.
  Windows PowerShell 5.1 compatible.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File packaging\windows\smoke-gui.ps1 -Exe dist\bacnet-health\bacnet-health.exe -Scale 1.5 -Tag 150
#>
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [string]$ShotDir,
  [double]$Scale = 1.0,
  [string]$Tag = "100",
  [int]$Width = 1120,
  [int]$Height = 800
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing
Add-Type @"
using System; using System.Runtime.InteropServices;
public static class BhWin {
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int w, int hh, uint f);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
}
"@
$Exe = (Resolve-Path $Exe).Path
if (-not $ShotDir) { $ShotDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "screenshots" }
New-Item -ItemType Directory -Force $ShotDir | Out-Null
$AE = [Windows.Automation.AutomationElement]
$TS = [Windows.Automation.TreeScope]

function Shot([IntPtr]$h, [string]$name) {
  Start-Sleep -Milliseconds 600
  $r = New-Object BhWin+RECT
  [void][BhWin]::GetWindowRect($h, [ref]$r)
  $bmp = New-Object Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T)
  $g = [Drawing.Graphics]::FromImage($bmp)
  $dc = $g.GetHdc()
  [void][BhWin]::PrintWindow($h, $dc, 2)   # PW_RENDERFULLCONTENT
  $g.ReleaseHdc($dc); $g.Dispose()
  $path = Join-Path $ShotDir "gui-$name-$Tag.png"
  $bmp.Save($path, [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
  return $path
}
function Find([object]$root, [string]$name, [int]$timeoutMs = 15000) {
  $cond = New-Object Windows.Automation.PropertyCondition($AE::NameProperty, $name)
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
    $e = $root.FindFirst($TS::Descendants, $cond)
    if ($e) { return $e }
    Start-Sleep -Milliseconds 100
  }
  throw "UI element '$name' not found within $timeoutMs ms"
}
function Click([object]$e) {
  $p = $null
  if ($e.TryGetCurrentPattern([Windows.Automation.InvokePattern]::Pattern, [ref]$p)) { $p.Invoke() }
  else { throw "Element '$($e.Current.Name)' is not invokable" }
}

if ($Scale -ne 1.0) { $env:QT_SCALE_FACTOR = "$Scale" } else { Remove-Item Env:QT_SCALE_FACTOR -ErrorAction SilentlyContinue }
$sw = [Diagnostics.Stopwatch]::StartNew()
$proc = Start-Process $Exe -PassThru
$h = [IntPtr]::Zero
while ($sw.Elapsed.TotalSeconds -lt 60) {
  $proc.Refresh()
  if ($proc.MainWindowHandle -ne [IntPtr]::Zero -and $proc.MainWindowTitle) { $h = $proc.MainWindowHandle; break }
  Start-Sleep -Milliseconds 20
}
if ($h -eq [IntPtr]::Zero) { throw "No main window within 60 s" }
$launchSec = [math]::Round($sw.Elapsed.TotalSeconds, 2)
$win = $AE::FromHandle($h)
[void](Find $win "Analyse a capture file")    # home screen is populated
$readySec = [math]::Round($sw.Elapsed.TotalSeconds, 2)

$children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($proc.Id)" | Select-Object -ExpandProperty Name)
$exeBytes = [IO.File]::ReadAllBytes($Exe)
$pe = [BitConverter]::ToInt32($exeBytes, 0x3C)
$subsystem = [BitConverter]::ToUInt16($exeBytes, $pe + 24 + 68)

[void][BhWin]::SetWindowPos($h, [IntPtr]::Zero, 40, 40, [int]($Width * $Scale), [int]($Height * $Scale), 0x0040)
[void][BhWin]::SetForegroundWindow($h)
$shots = @()
$shots += Shot $h "home"
Click (Find $win "Analyse a capture file")
$sample = Find $win "No capture file yet? Try a sample capture"
$shots += Shot $h "analyse"
$t = [Diagnostics.Stopwatch]::StartNew()
Click $sample
[void](Find $win "Findings" 60000)               # the Done screen's findings tree
$analyseSec = [math]::Round($t.Elapsed.TotalSeconds, 2)
$shots += Shot $h "done"

$winPat = $null
if ($win.TryGetCurrentPattern([Windows.Automation.WindowPattern]::Pattern, [ref]$winPat)) { $winPat.Close() }
if (-not $proc.WaitForExit(10000)) { $proc.Kill(); $exitInfo = "killed after 10 s" } else { $exitInfo = "exit $($proc.ExitCode)" }

[ordered]@{
  exe = $Exe
  scale = $Scale
  pe_subsystem = $subsystem
  child_processes = $children
  console_attached = [bool]($children -contains "conhost.exe")
  launch_to_window_s = $launchSec
  launch_to_home_ready_s = $readySec
  sample_analysis_to_done_s = $analyseSec
  window_title = $proc.MainWindowTitle
  close = $exitInfo
  screenshots = $shots
} | ConvertTo-Json -Depth 3

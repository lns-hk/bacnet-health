<#
.SYNOPSIS
  Packaging spike: build the bacnet-health --onedir test bundle (GUI exe + CLI exe) and print metrics.
.DESCRIPTION
  All build output (venv, PyInstaller work dir, dist, zip) goes to -OutDir, which must be OUTSIDE
  the Synology-synced source tree. Nothing is signed or published. Windows PowerShell 5.1 compatible.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -OutDir C:\AI\Project\bh-build
  powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -OutDir C:\AI\Project\bh-build -WebEngine
#>
param(
  [Parameter(Mandatory = $true)][string]$OutDir,
  [string]$Python = "python",
  [switch]$WebEngine,
  [switch]$SkipInstall
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here "..\..")).Path
$OutDir = [IO.Path]::GetFullPath($OutDir)
if ($OutDir.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase) -or $OutDir -match "SynologyDrive") {
  throw "OutDir must be outside the synced source tree: $OutDir"
}
New-Item -ItemType Directory -Force $OutDir | Out-Null
if ($WebEngine) { $variant = "webengine" } else { $variant = "widgets" }
$venv = Join-Path $OutDir "venv"
$work = Join-Path $OutDir "work-$variant"
$dist = Join-Path $OutDir "dist-$variant"

if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) { & $Python -m venv $venv }
$py = Join-Path $venv "Scripts\python.exe"
if (-not $SkipInstall) {
  & $py -m pip install --quiet --upgrade pip
  & $py -m pip install --quiet PySide6 pyinstaller
}
if ($WebEngine) { $env:BH_TEST_WEBENGINE = "1" } else { $env:BH_TEST_WEBENGINE = "0" }
$env:PYTHONDONTWRITEBYTECODE = "1"   # keep __pycache__ out of the synced tree
$sw = [Diagnostics.Stopwatch]::StartNew()
& $py -m PyInstaller --noconfirm --clean --log-level WARN --workpath $work --distpath $dist (Join-Path $here "bacnet_health_test.spec")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed ($LASTEXITCODE)" }
$buildSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)

$app = Join-Path $dist "bacnet-health"
$zip = Join-Path $OutDir "bacnet-health-win-x64-$variant-test.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $app -DestinationPath $zip -CompressionLevel Optimal

$files = Get-ChildItem $app -Recurse -File
$folderMB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB, 1)
$zipMB = [math]::Round((Get-Item $zip).Length / 1MB, 1)
$cliOut = (& (Join-Path $app "bacnet-health-cli.exe")) -join " "

# Startup: wall time from launch until the window has been shown once and the app quit.
$probe = Join-Path $OutDir "startup-$variant.txt"
$wall = @(); $inApp = @()
foreach ($i in 1..3) {
  if (Test-Path $probe) { Remove-Item $probe }
  $t = [Diagnostics.Stopwatch]::StartNew()
  $p = Start-Process (Join-Path $app "bacnet-health.exe") -ArgumentList "--startup-probe=$probe" -PassThru
  $null = $p.WaitForExit(60000)
  $wall += [math]::Round($t.Elapsed.TotalSeconds, 2)
  if (Test-Path $probe) { $inApp += [double](Get-Content $probe) }
}
[ordered]@{
  variant = $variant
  build_seconds = $buildSec
  folder_mb = $folderMB
  file_count = $files.Count
  zip = $zip
  zip_mb = $zipMB
  zip_sha256 = (Get-FileHash $zip -Algorithm SHA256).Hash
  cli_output = $cliOut
  gui_launch_to_exit_seconds = $wall
  python_to_shown_seconds = $inApp
  qt_dlls = @($files | Where-Object Name -like "Qt6*.dll" | Select-Object -ExpandProperty Name)
} | ConvertTo-Json -Depth 3

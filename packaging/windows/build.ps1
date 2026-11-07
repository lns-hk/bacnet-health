<#
.SYNOPSIS
  Build the Windows release folder and zip of bacnet-health.
.DESCRIPTION
  Produces, under -OutDir (default: <repo>\dist):
    bacnet-health\                              onedir app: bacnet-health.exe (GUI), bacnet-health-cli.exe (console)
    bacnet-health-<version>-win-x64.zip         the folder, plus README-FIRST.txt, THIRD_PARTY_NOTICES.md, licenses\
    bacnet-health-<version>-win-x64.zip.sha256  "<hash> *<zip name>" (sha256sum format)
  The PyInstaller work dir goes to <OutDir>\..\build\pyinstaller (or -WorkDir). Nothing is signed or published.
  Uses the Python of the current environment unless -Python is given; with -Venv it creates a clean build venv
  in <OutDir>\..\build\venv and installs the project with the [gui] extra and PyInstaller.
  Paths inside a SynologyDrive folder are refused (synced trees must not receive build output).
  Windows PowerShell 5.1 compatible.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1
  powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -Venv -OutDir C:\bh-release
#>
param(
  [string]$OutDir,
  [string]$WorkDir,
  [string]$Python = "python",
  [switch]$Venv,
  [switch]$NoZip
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here "..\..")).Path
if (-not $OutDir) { $OutDir = Join-Path $repo "dist" }
$OutDir = [IO.Path]::GetFullPath($OutDir)
if (-not $WorkDir) { $WorkDir = Join-Path (Split-Path -Parent $OutDir) "build" }
$WorkDir = [IO.Path]::GetFullPath($WorkDir)
foreach ($p in @($OutDir, $WorkDir, $repo)) {
  if ($p -match "SynologyDrive") { throw "Refusing to build in a synced folder: $p" }
}
New-Item -ItemType Directory -Force $OutDir, $WorkDir | Out-Null

if ($Venv) {
  $venvDir = Join-Path $WorkDir "venv"
  if (-not (Test-Path (Join-Path $venvDir "Scripts\python.exe"))) { & $Python -m venv $venvDir }
  $Python = Join-Path $venvDir "Scripts\python.exe"
  & $Python -m pip install --quiet --upgrade pip
  & $Python -m pip install --quiet "$repo[gui]" pyinstaller
  if ($LASTEXITCODE -ne 0) { throw "pip install failed ($LASTEXITCODE)" }
}

$version = (& $Python -c "import sys; sys.path.insert(0, r'$repo\src'); import bacnet_health; print(bacnet_health.__version__)").Trim()
if (-not $version) { throw "Could not read bacnet_health.__version__" }
$name = "bacnet-health-$version-win-x64"
$app = Join-Path $OutDir "bacnet-health"
$zip = Join-Path $OutDir "$name.zip"

$env:PYTHONDONTWRITEBYTECODE = "1"
$sw = [Diagnostics.Stopwatch]::StartNew()
& $Python -m PyInstaller --noconfirm --clean --log-level WARN `
  --workpath (Join-Path $WorkDir "pyinstaller") --distpath $OutDir (Join-Path $here "bacnet-health.spec")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed ($LASTEXITCODE)" }
$buildSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)

# Release extras inside the app folder: notices, licence texts, first-run instructions.
$utf8 = New-Object Text.UTF8Encoding($false)
$readme = [IO.File]::ReadAllText((Join-Path $here "README-FIRST.txt"), $utf8).Replace("{VERSION}", $version)
[IO.File]::WriteAllText((Join-Path $app "README-FIRST.txt"), $readme.Replace("`r`n", "`n").Replace("`n", "`r`n"), $utf8)
Copy-Item (Join-Path $repo "THIRD_PARTY_NOTICES.md") $app -Force
$lic = Join-Path $app "licenses"
New-Item -ItemType Directory -Force $lic | Out-Null
Copy-Item (Join-Path $here "licenses\*.txt") $lic -Force
$pyLicense = (& $Python -c "import os, sys; print(os.path.join(sys.base_prefix, 'LICENSE.txt'))").Trim()
if (Test-Path $pyLicense) { Copy-Item $pyLicense (Join-Path $lic "Python-PSF-LICENSE.txt") -Force }
else { Write-Warning "Python LICENSE.txt not found at $pyLicense" }

# Sanity: the trimmed bundle must not contain what the spec drops.
$files = Get-ChildItem $app -Recurse -File
$forbidden = $files | Where-Object { $_.Name -match '^(opengl32sw\.dll|Qt6(WebEngine|Quick|Qml|Pdf|Network|Svg)\w*\.dll|QtWebEngineProcess\.exe)$' }
if ($forbidden) { throw "Trimmed build still contains: $($forbidden.Name -join ', ')" }

$result = [ordered]@{
  version = $version
  build_seconds = $buildSec
  app_dir = $app
  folder_mb = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB, 1)
  file_count = $files.Count
  qt_dlls = @($files | Where-Object Name -like "Qt6*.dll" | Select-Object -ExpandProperty Name)
}

if (-not $NoZip) {
  if (Test-Path $zip) { Remove-Item $zip -Force }
  # Zip root: README-FIRST.txt (visible as soon as the zip is opened) + the bacnet-health\ folder.
  $stage = Join-Path $WorkDir "zip-root"
  New-Item -ItemType Directory -Force $stage | Out-Null
  Copy-Item (Join-Path $app "README-FIRST.txt") $stage -Force
  & $Python -I (Join-Path $here "make_zip.py") $zip $app (Join-Path $stage "README-FIRST.txt")
  if ($LASTEXITCODE -ne 0) { throw "make_zip.py failed ($LASTEXITCODE)" }
  $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  [IO.File]::WriteAllText("$zip.sha256", "$hash *$name.zip`n", $utf8)
  $result.zip = $zip
  $result.zip_mb = [math]::Round((Get-Item $zip).Length / 1MB, 1)
  $result.zip_sha256 = $hash
}
$result | ConvertTo-Json -Depth 3

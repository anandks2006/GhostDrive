<#
.SYNOPSIS
    GhostDrive Windows release build: PyInstaller bundle + Inno Setup installer.

.DESCRIPTION
    Runs the full release pipeline:
      1. Sanity checks (deps, spec file, installer script)
      2. poetry run pyinstaller ghostdrive.spec --noconfirm   → dist\GhostDrive\
      3. iscc installer\GhostDrive.iss                        → installer\Output\*.exe  (if Inno Setup found)

    Skips steps whose tools are missing (prints what to install) rather than
    failing the whole build, so you can at least get the portable bundle.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
    powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1 -SkipInstaller
#>
[CmdletBinding()]
param(
    [switch]$SkipInstaller,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "  ! $msg" -ForegroundColor Yellow }
function Ok($msg)   { Write-Host "  + $msg" -ForegroundColor Green }

# ── 1. Sanity checks ────────────────────────────────────────────────────────
Step "Preflight"

if (-not (Test-Path "ghostdrive.spec")) { throw "ghostdrive.spec not found in $root" }
Ok "PyInstaller spec present"

if (-not (Test-Path "installer\GhostDrive.iss")) { throw "installer\GhostDrive.iss not found" }
Ok "Inno Setup script present"

$py = Get-Command py -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python -ErrorAction SilentlyContinue }
if (-not $py) { throw "No Python launcher found (py/python)." }
Ok "Python: $($py.Source)"

& $py.Source -c "import ghostdrive, fastapi, argon2, cryptography, mnemonic, blake3, zfec" 2>$null
if ($LASTEXITCODE -ne 0) { Warn "Some runtime deps missing — run: poetry install" } else { Ok "Runtime deps importable" }

$pyinstaller = & $py.Source -c "import PyInstaller; print(PyInstaller.__version__)" 2>$null
if (-not $pyinstaller) {
    Warn "PyInstaller not installed. Install with: poetry add --group dev pyinstaller (or pip install pyinstaller)"
    exit 1
}
Ok "PyInstaller $pyinstaller"

# ── 2. Clean (optional) ─────────────────────────────────────────────────────
if ($Clean) {
    Step "Clean"
    foreach ($d in @("build", "dist")) {
        if (Test-Path $d) { Remove-Item $d -Recurse -Force; Ok "removed $d" }
    }
}

# ── 3. PyInstaller ──────────────────────────────────────────────────────────
Step "PyInstaller bundle"
& $py.Source -m PyInstaller ghostdrive.spec --noconfirm --clean
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }
if (-not (Test-Path "dist\GhostDrive\GhostDrive.exe")) { throw "Expected dist\GhostDrive\GhostDrive.exe missing." }
Ok "dist\GhostDrive\GhostDrive.exe"

# Smoke test: the bundle must start and answer --version without a traceback.
Step "Bundle smoke test"
$out = & "dist\GhostDrive\GhostDrive.exe" --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Warn "Smoke test output: $out"
} else {
    Ok "$out"
}

# ── 4. Inno Setup installer (optional) ──────────────────────────────────────
if ($SkipInstaller) {
    Step "Installer skipped (-SkipInstaller)"
} else {
    Step "Inno Setup installer"
    $iscc = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $iscc) {
        Warn "Inno Setup 6 not found — installer skipped."
        Warn "Install from https://jrsoftware.org/isdl.php then re-run, or pass -SkipInstaller."
    } else {
        & $iscc "installer\GhostDrive.iss"
        if ($LASTEXITCODE -ne 0) { throw "ISCC failed." }
        Get-ChildItem "installer\Output\*.exe" | ForEach-Object { Ok $_.FullName }
    }
}

Step "Done"

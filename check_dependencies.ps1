# Check Dependencies Script
# This script checks pip and all installed packages in the virtual environment
# for available updates but does NOT perform any upgrades.

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Dependency Check Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Activate virtual environment
Write-Host "[1/3] Activating virtual environment..." -ForegroundColor Yellow
$venvPath = Join-Path $PSScriptRoot ".venv\Scripts\Activate.ps1"

if (-not (Test-Path $venvPath)) {
    Write-Host "Error: Virtual environment not found at $venvPath" -ForegroundColor Red
    exit 1
}

& $venvPath
Write-Host "Virtual environment activated successfully!" -ForegroundColor Green
Write-Host ""

# Step 2: Check pip version vs latest on PyPI
Write-Host "[2/3] Checking pip version..." -ForegroundColor Yellow
$pipOutput = python -m pip --version 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: Failed to probe pip version." -ForegroundColor Yellow
} else {
    $currentPipVersion = ($pipOutput -split ' ')[1]
    try {
        $pypi = Invoke-RestMethod -Uri "https://pypi.org/pypi/pip/json" -UseBasicParsing -ErrorAction Stop
        $latestPipVersion = $pypi.info.version
    } catch {
        Write-Host "Warning: Could not query PyPI for the latest pip version." -ForegroundColor Yellow
        $latestPipVersion = $null
    }

    if ($latestPipVersion) {
        if ($currentPipVersion -ne $latestPipVersion) {
            Write-Host "pip: $currentPipVersion -> $latestPipVersion" -ForegroundColor Cyan
            Write-Host "To upgrade pip, run: `python -m pip install --upgrade pip` (not performed by this script)" -ForegroundColor DarkYellow
        } else {
            Write-Host "pip is up to date ($currentPipVersion)" -ForegroundColor Green
        }
    } else {
        Write-Host "pip: current version $currentPipVersion (could not determine latest on PyPI)" -ForegroundColor Gray
    }
}

Write-Host ""

# Step 3: Report outdated packages (no upgrades performed)
Write-Host "[3/3] Checking installed packages for available updates..." -ForegroundColor Yellow
$outdatedJson = pip list --outdated --format=json 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to list packages. Make sure pip is available in the virtual environment." -ForegroundColor Red
    exit 1
}

$packages = $null
if ($outdatedJson -and $outdatedJson.Trim() -ne "") {
    try {
        $packages = $outdatedJson | ConvertFrom-Json
    } catch {
        Write-Host "Error: Unexpected output from pip list --outdated" -ForegroundColor Red
        exit 1
    }
} else {
    $packages = @()
}

if ($packages.Count -eq 0) {
    Write-Host "All packages are already up to date!" -ForegroundColor Green
} else {
    Write-Host "Found $($packages.Count) package(s) with updates available:" -ForegroundColor Cyan
    foreach ($package in $packages) {
        Write-Host "  - $($package.name): $($package.version) -> $($package.latest_version)" -ForegroundColor Gray
    }

    Write-Host "" -ForegroundColor Gray
    Write-Host "This script only checks for updates and does NOT perform upgrades." -ForegroundColor Yellow
    Write-Host "To upgrade packages run: `pip install --upgrade <package>` or update requirements manually." -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Check Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

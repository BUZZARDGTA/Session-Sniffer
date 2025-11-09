# Update Dependencies Script
# This script updates pip and all installed packages in the virtual environment

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Dependency Update Script" -ForegroundColor Cyan
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

# Step 2: Update pip
Write-Host "[2/3] Updating pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to update pip" -ForegroundColor Red
    exit 1
}
Write-Host "Pip updated successfully!" -ForegroundColor Green
Write-Host ""

# Step 3: Update all installed packages
Write-Host "[3/3] Updating all installed packages..." -ForegroundColor Yellow
$packages = pip list --outdated --format=json | ConvertFrom-Json

if ($packages.Count -eq 0) {
    Write-Host "All packages are already up to date!" -ForegroundColor Green
} else {
    Write-Host "Found $($packages.Count) package(s) to update:" -ForegroundColor Cyan
    foreach ($package in $packages) {
        Write-Host "  - $($package.name): $($package.version) -> $($package.latest_version)" -ForegroundColor Gray
    }
    Write-Host ""

    foreach ($package in $packages) {
        Write-Host "Updating $($package.name)..." -ForegroundColor Yellow
        pip install --upgrade $package.name
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] $($package.name) updated successfully!" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Failed to update $($package.name)" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Update Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

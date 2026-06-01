# Check Project Dependencies Script
# This script checks pip and all installed packages in the virtual environment
# for available updates but does NOT perform any upgrades.

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Project Dependency Check Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

function Get-LatestGitHubTag {
    param(
        [Parameter(Mandatory = $true)][string]$Owner,
        [Parameter(Mandatory = $true)][string]$Repo
    )

    $headers = @{
        'User-Agent' = 'Session-Sniffer-Dependency-Checker'
        'Accept' = 'application/vnd.github+json'
    }

    try {
        $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/releases/latest" -Headers $headers -ErrorAction Stop
        if ($latestRelease -and $latestRelease.tag_name) {
            return [string]$latestRelease.tag_name
        }
    } catch {
        # Some actions may not expose a latest release; fall back to tags.
    }

    try {
        $tags = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/tags?per_page=100" -Headers $headers -ErrorAction Stop
        if (-not $tags) {
            return $null
        }

        $semverTags = @()
        foreach ($tag in $tags) {
            if ($tag.name -match '^v(\d+)\.(\d+)\.(\d+)$') {
                $semverTags += [PSCustomObject]@{
                    Name = [string]$tag.name
                    Version = [Version]::new([int]$matches[1], [int]$matches[2], [int]$matches[3])
                }
            }
        }

        if ($semverTags.Count -gt 0) {
            return ($semverTags | Sort-Object Version | Select-Object -Last 1).Name
        }

        return [string]($tags[0].name)
    } catch {
        return $null
    }
}

function Get-NormalizedSemVer {
    param([Parameter(Mandatory = $true)][string]$Tag)

    if ($Tag -match '^v(\d+)$') {
        return [Version]::new([int]$matches[1], 0, 0)
    }

    if ($Tag -match '^v(\d+)\.(\d+)$') {
        return [Version]::new([int]$matches[1], [int]$matches[2], 0)
    }

    if ($Tag -match '^v(\d+)\.(\d+)\.(\d+)$') {
        return [Version]::new([int]$matches[1], [int]$matches[2], [int]$matches[3])
    }

    return $null
}

# Step 1: Activate virtual environment
Write-Host "[1/4] Activating virtual environment..." -ForegroundColor Yellow
$venvPath = Join-Path $PSScriptRoot ".venv\Scripts\Activate.ps1"

if (-not (Test-Path $venvPath)) {
    Write-Host "Error: Virtual environment not found at $venvPath" -ForegroundColor Red
    exit 1
}

& $venvPath
Write-Host "Virtual environment activated successfully!" -ForegroundColor Green
Write-Host ""

# Step 2: Check pip version vs latest on PyPI
Write-Host "[2/4] Checking pip version..." -ForegroundColor Yellow
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
Write-Host "[3/4] Checking installed packages for available updates..." -ForegroundColor Yellow
$outdatedJson = & {
        $ErrorActionPreference = 'SilentlyContinue'
        pip list --outdated --format=json 2>&1
    } | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }

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
    Write-Host "To upgrade packages run: `pip install --upgrade <package>` or update dependencies in pyproject.toml manually." -ForegroundColor DarkYellow
}

Write-Host ""

# Step 4: Check GitHub Actions versions in workflow files
Write-Host "[4/4] Checking GitHub Actions pins in workflow files..." -ForegroundColor Yellow
$workflowsPath = Join-Path $PSScriptRoot '.github\workflows'

if (-not (Test-Path $workflowsPath)) {
    Write-Host "Workflow directory not found at $workflowsPath" -ForegroundColor Gray
} else {
    $workflowFiles = Get-ChildItem -Path $workflowsPath -File | Where-Object { $_.Extension -in @('.yml', '.yaml') }

    if (-not $workflowFiles -or $workflowFiles.Count -eq 0) {
        Write-Host 'No workflow files found to scan.' -ForegroundColor Gray
    } else {
        $usesMatches = @()
        foreach ($file in $workflowFiles) {
            $lines = Get-Content -Path $file.FullName
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^\s*uses:\s*([^\s]+)\s*$') {
                    $usesMatches += [PSCustomObject]@{
                        File = $file.Name
                        Line = $i + 1
                        Uses = [string]$matches[1]
                    }
                }
            }
        }

        if ($usesMatches.Count -eq 0) {
            Write-Host 'No uses: entries found in workflow files.' -ForegroundColor Gray
        } else {
            $githubActionUsages = $usesMatches | Where-Object { $_.Uses -match '^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@(.+)$' }
            $cache = @{}
            $outdatedActions = @()

            foreach ($usage in $githubActionUsages) {
                $null = $usage.Uses -match '^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)@(.+)$'
                $owner = [string]$matches[1]
                $repo = [string]$matches[2]
                $currentRef = [string]$matches[3]
                $repoKey = "$owner/$repo"

                if (-not $cache.ContainsKey($repoKey)) {
                    $cache[$repoKey] = Get-LatestGitHubTag -Owner $owner -Repo $repo
                }

                $latestTag = [string]$cache[$repoKey]
                if ([string]::IsNullOrWhiteSpace($latestTag)) {
                    Write-Host "  - $repoKey@$currentRef -> unable to resolve latest tag (API/rate/network)." -ForegroundColor DarkYellow
                    continue
                }

                $currentSemVer = Get-NormalizedSemVer -Tag $currentRef
                $latestSemVer = Get-NormalizedSemVer -Tag $latestTag
                if ($null -eq $currentSemVer -or $null -eq $latestSemVer) {
                    Write-Host "  - $repoKey@$currentRef (latest: $latestTag) [non-semver compare skipped]" -ForegroundColor Gray
                    continue
                }

                if ($currentSemVer -lt $latestSemVer) {
                    $outdatedActions += [PSCustomObject]@{
                        Repo = $repoKey
                        Current = $currentRef
                        Latest = $latestTag
                        File = [string]$usage.File
                        Line = [int]$usage.Line
                    }
                }
            }

            if ($outdatedActions.Count -eq 0) {
                Write-Host 'All scanned GitHub Actions are up to date.' -ForegroundColor Green
            } else {
                Write-Host "Found $($outdatedActions.Count) outdated GitHub Action pin(s):" -ForegroundColor Cyan
                foreach ($item in $outdatedActions) {
                    Write-Host "  - $($item.Repo): $($item.Current) -> $($item.Latest) ($($item.File):$($item.Line))" -ForegroundColor Gray
                }
            }
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Check Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

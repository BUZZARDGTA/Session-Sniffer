#!/usr/bin/env pwsh

# Activate virtual environment
& "${PSScriptRoot}\.venv\Scripts\Activate.ps1"

# Function to check if a command exists and run it, or show skip message
function Invoke-QualityTool {
    param(
        [string]$ToolName,
        [string]$Command,
        [string]$InstallCommand,
        [string]$Description,
        [string]$Category,
        [int]$StepNumber,
        [int]$TotalSteps
    )

    Write-Host ""
    Write-Host "[$StepNumber/$TotalSteps] $Category - $ToolName ($Description)" -ForegroundColor Cyan
    Write-Host "-----------------------------------" -ForegroundColor DarkGray

    if (Get-Command $ToolName -ErrorAction SilentlyContinue) {
        $startTime = Get-Date
        Invoke-Expression $Command
        $endTime = Get-Date
        $elapsed = $endTime - $startTime
        $elapsedSeconds = [math]::Round($elapsed.TotalSeconds, 1)
        Write-Host "✓  $ToolName completed in $elapsedSeconds seconds" -ForegroundColor Green
    } else {
        Write-Host "⚠  $ToolName is not installed. Skipping $ToolName check." -ForegroundColor DarkYellow
        Write-Host "   To install: $InstallCommand" -ForegroundColor Gray
    }
}

# Function to display header
function Show-Header {
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "Running Code Quality Analysis" -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan
}

# Function to display footer
function Show-Footer {
    Write-Host ""
    Write-Host "===================================" -ForegroundColor Green
    Write-Host "Code Quality Analysis Complete" -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Green
}

# Main execution
Show-Header

# Define code quality tools configuration
$QualityTools = @(
    @{
        ToolName = "ruff"
        Command = "ruff check ."
        InstallCommand = "pip install ruff"
        Description = "Fast Python linter and code formatter"
        Category = "LINTING"
    },
    @{
        ToolName = "flake8"
        Command = "flake8 . --config .flake8"
        InstallCommand = "pip install flake8"
        Description = "Style guide enforcement"
        Category = "LINTING"
    },
    @{
        ToolName = "pylint"
        Command = "pylint . --rcfile pyproject.toml"
        InstallCommand = "pip install pylint"
        Description = "Comprehensive Python code analysis"
        Category = "LINTING"
    },
    @{
        ToolName = "vulture"
        Command = "vulture ."
        InstallCommand = "pip install vulture"
        Description = "Dead code detection and analysis"
        Category = "LINTING"
    },
    @{
        ToolName = "mypy"
        Command = "mypy . --config-file pyproject.toml"
        InstallCommand = "pip install mypy"
        Description = "Static type checking"
        Category = "TYPE CHECKING"
    },
    @{
        ToolName = "pyright"
        Command = "pyright"
        InstallCommand = "pip install pyright"
        Description = "Microsoft Python type checker"
        Category = "TYPE CHECKING"
    },
    @{
        ToolName = "ty"
        Command = "ty check ."
        InstallCommand = "pip install ty"
        Description = "Astral's fast Python type checker"
        Category = "TYPE CHECKING"
    },
    @{
        ToolName = "pip-audit"
        Command = "pip-audit --local --skip-editable"
        InstallCommand = "pip install pip-audit"
        Description = "PyPA's official security vulnerability scanner"
        Category = "SECURITY"
    },
    @{
        ToolName = "safety"
        Command = "safety scan"
        InstallCommand = "pip install safety"
        Description = "Python package vulnerability scanning"
        Category = "SECURITY"
    },
    @{
        ToolName = "snyk"
        Command = "snyk test"
        InstallCommand = "npm install -g snyk"
        Description = "Security vulnerability scanning"
        Category = "SECURITY"
    }
)

# Execute each quality tool
$TotalSteps = $QualityTools.Count
for ($i = 0; $i -lt $QualityTools.Count; $i++) {
    $tool = $QualityTools[$i]
    Invoke-QualityTool -ToolName $tool.ToolName -Command $tool.Command -InstallCommand $tool.InstallCommand -Description $tool.Description -Category $tool.Category -StepNumber ($i + 1) -TotalSteps $TotalSteps
}

Show-Footer


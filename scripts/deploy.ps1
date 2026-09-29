<#
.SYNOPSIS
    Full AI-Augmented SOC Lab deployment script for Windows PowerShell.
.DESCRIPTION
    Validates Docker environment, creates the soc-network Docker bridge,
    and deploys all SOC stack tiers: Wazuh, TheHive, Cortex, Shuffle SOAR,
    MISP, Ollama, and the AI Engine.
#>

[CmdletBinding()]
param (
    [switch]$SkipCheck,
    [switch]$Tiered
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
    exit 1
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Err "Docker is not installed or not in PATH. Please install Docker Desktop."
    }

    try {
        docker info | Out-Null
    } catch {
        Write-Err "Docker daemon is not running. Please start Docker Desktop."
    }

    $osMem = Get-CimInstance Win32_OperatingSystem
    $totalRamGb = [math]::Round($osMem.TotalVisibleMemorySize / 1MB, 1)
    Write-Log "Detected RAM: $totalRamGb GB"
    if ($totalRamGb -lt 16) {
        Write-Warn "Less than 16GB RAM detected ($totalRamGb GB). Full stack execution may be constrained."
    }

    $systemDrive = Get-PSDrive -Name C -ErrorAction SilentlyContinue
    if ($systemDrive) {
        $freeDiskGb = [math]::Round($systemDrive.Free / 1GB, 1)
        Write-Log "Free Disk Space: $freeDiskGb GB"
        if ($freeDiskGb -lt 50) {
            Write-Warn "Less than 50GB free disk space ($freeDiskGb GB). Docker images require ~30-50GB."
        }
    }
}

function Initialize-Network {
    Write-Log "Ensuring Docker network 'soc-network' exists..."
    $networkExists = docker network ls --filter name=^soc-network$ --format "{{.Name}}"
    if (-not $networkExists) {
        docker network create soc-network | Out-Null
        Write-Log "Created Docker network 'soc-network'"
    } else {
        Write-Log "Network 'soc-network' already exists."
    }
}

function Deploy-Service {
    param(
        [string]$ServiceName,
        [string]$ComposeFile
    )
    Write-Log "Deploying $ServiceName using $ComposeFile..."
    docker compose -f $ComposeFile up -d
    Write-Log "$ServiceName deployed successfully."
}

function Show-Summary {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "         AI-Augmented SOC Lab Deployed Successfully!         " -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Platform Endpoints & Consoles:" -ForegroundColor White
    Write-Host "  - Wazuh Dashboard   : https://localhost:443" -ForegroundColor Yellow
    Write-Host "  - TheHive (IR)     : http://localhost:9000" -ForegroundColor Yellow
    Write-Host "  - Cortex Analyzers  : http://localhost:9001" -ForegroundColor Yellow
    Write-Host "  - Shuffle SOAR      : http://localhost:3001" -ForegroundColor Yellow
    Write-Host "  - MISP CTI Platform : http://localhost:8080" -ForegroundColor Yellow
    Write-Host "  - AI SOC Engine API : http://localhost:8888" -ForegroundColor Yellow
    Write-Host "  - Ollama Inference  : http://localhost:11434" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Default Credentials:" -ForegroundColor White
    Write-Host "  - Wazuh   : admin / SecretPassword" -ForegroundColor Gray
    Write-Host "  - TheHive : admin@thehive.local / secret" -ForegroundColor Gray
    Write-Host "  - Shuffle : admin / password" -ForegroundColor Gray
    Write-Host "  - MISP    : admin@admin.test / admin" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Pull local LLM model : docker exec -it ollama ollama pull llama3"
    Write-Host "  2. Import TheHive templates from thehive-config/case-templates.json"
    Write-Host "  3. Import Shuffle workflows from shuffle-workflows/"
    Write-Host "  4. Execute pipeline test: python scripts/send-test-alert.py all"
    Write-Host ""
}

# Execution
Write-Host "=== AI-Augmented SOC Lab: Automated Deployment ===" -ForegroundColor Cyan
if (-not $SkipCheck) {
    Test-Prerequisites
}

Initialize-Network

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Split-Path -Parent $scriptDir
$dockerDir = Join-Path $rootDir "docker"
$unifiedCompose = Join-Path $rootDir "docker-compose.yml"

if ($Tiered -or (-not (Test-Path $unifiedCompose))) {
    Write-Log "Deploying in tiered mode..."
    Deploy-Service -ServiceName "Wazuh SIEM & EDR" -ComposeFile (Join-Path $dockerDir "docker-compose.wazuh.yml")
    Start-Sleep -Seconds 10

    Deploy-Service -ServiceName "TheHive & Cortex" -ComposeFile (Join-Path $dockerDir "docker-compose.thehive.yml")
    Deploy-Service -ServiceName "Shuffle SOAR" -ComposeFile (Join-Path $dockerDir "docker-compose.shuffle.yml")
    Deploy-Service -ServiceName "MISP Threat Intel" -ComposeFile (Join-Path $dockerDir "docker-compose.misp.yml")
    Deploy-Service -ServiceName "Ollama & AI Engine" -ComposeFile (Join-Path $dockerDir "docker-compose.ollama.yml")
} else {
    Write-Log "Deploying unified stack via root docker-compose.yml..."
    docker compose -f $unifiedCompose up -d
}

Show-Summary

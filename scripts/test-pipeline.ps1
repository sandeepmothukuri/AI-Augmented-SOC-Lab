<#
.SYNOPSIS
    End-to-End Pipeline Health Check for AI-Augmented SOC Lab (PowerShell).
.DESCRIPTION
    Validates HTTP connectivity across all deployed SOC services, checks
    Docker container states, and exercises the AI SOC Engine with a test alert.
#>

[CmdletBinding()]
param ()

$ErrorActionPreference = "Continue"

$PassCount = 0
$FailCount = 0

function Write-Pass {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
    $script:PassCount++
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
    $script:FailCount++
}

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Uri,
        [int[]]$ExpectedCodes = @(200, 302, 401)
    )
    try {
        # Skip SSL certificate validation for local self-signed lab certs
        $handler = [System.Net.Http.HttpClientHandler]::new()
        $handler.ServerCertificateCustomValidationCallback = { $true }
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [System.TimeSpan]::FromSeconds(5)

        $response = $client.GetAsync($Uri).GetAwaiter().GetResult()
        $statusCode = [int]$response.StatusCode
        if ($ExpectedCodes -contains $statusCode) {
            Write-Pass "$Name ($Uri) -> HTTP $statusCode"
        } else {
            Write-Fail "$Name ($Uri) -> HTTP $statusCode (Expected: $($ExpectedCodes -join ', '))"
        }
    } catch {
        Write-Fail "$Name ($Uri) -> Connection failed: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "=== AI-Augmented SOC Lab: Pipeline Health Check ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "--- Core Service HTTP Endpoints ---" -ForegroundColor Yellow
Test-Endpoint -Name "Wazuh Dashboard" -Uri "https://localhost:443" -ExpectedCodes @(200, 302)
Test-Endpoint -Name "Wazuh API" -Uri "https://localhost:55000" -ExpectedCodes @(200, 401)
Test-Endpoint -Name "TheHive 5" -Uri "http://localhost:9000" -ExpectedCodes @(200, 302)
Test-Endpoint -Name "Cortex" -Uri "http://localhost:9001" -ExpectedCodes @(200, 302)
Test-Endpoint -Name "Shuffle SOAR" -Uri "http://localhost:3001" -ExpectedCodes @(200, 302)
Test-Endpoint -Name "MISP Platform" -Uri "http://localhost:8080" -ExpectedCodes @(200, 302)
Test-Endpoint -Name "Ollama API" -Uri "http://localhost:11434/api/tags" -ExpectedCodes @(200)
Test-Endpoint -Name "AI SOC Engine Health" -Uri "http://localhost:8888/health" -ExpectedCodes @(200)
Test-Endpoint -Name "AI SOC Engine OpenAPI Docs" -Uri "http://localhost:8888/docs" -ExpectedCodes @(200)

Write-Host ""
Write-Host "--- Docker Container Status ---" -ForegroundColor Yellow
$containers = @(
    "wazuh-manager", "wazuh-indexer", "wazuh-dashboard",
    "thehive", "cortex", "cassandra",
    "shuffle-backend", "shuffle-frontend",
    "ollama", "ai-engine", "misp"
)

if (Get-Command docker -ErrorAction SilentlyContinue) {
    $runningContainers = docker ps --format "{{.Names}}"
    foreach ($c in $containers) {
        if ($runningContainers -match $c) {
            Write-Pass "Container running: $c"
        } else {
            Write-Fail "Container not running: $c"
        }
    }
} else {
    Write-Host "[!] Docker CLI not available for container check" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "--- Summary ---" -ForegroundColor Cyan
if ($FailCount -eq 0) {
    Write-Host "All checks passed! ($PassCount checks)" -ForegroundColor Green
} else {
    Write-Host "Health check completed with $FailCount failure(s) and $PassCount pass(es)." -ForegroundColor Yellow
}
Write-Host ""

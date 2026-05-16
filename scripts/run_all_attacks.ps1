<#
.SYNOPSIS
Run the rules-farmer CLI once per attack family (Windows port).

.DESCRIPTION
Each invocation runs ONE experiment whose internal cycle count is controlled by
config.yaml -> experiment_defaults.variant_count (set to 49, so each experiment runs
1 base + 49 variants = 50 attack executions). The orchestrator runs in
continue_on_failure=true mode so all 50 cycles execute even if some don't fire.

Validated rules (those that produced fired=True) are accumulated across runs in
data/validated_rules/all_validated_rules.rules and consulted by the Rules Agent BEFORE
generating a new rule for the same attack family.

.EXAMPLE
.\scripts\run_all_attacks.ps1

.EXAMPLE
$env:ATTACKS="xrce-dds-udp-dos mqtt-bruteforce"
.\scripts\run_all_attacks.ps1

.NOTES
Environment overrides:
  PROJECT_DIR     - defaults to the repo root inferred from this script's location.
  ATTACKS         - space-separated list of attack_ids; defaults to all 10.
  LOG_DIR         - directory for per-run logs; defaults to .\output_batch.
#>

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DefaultProjectDir = Split-Path -Parent $ScriptDir

$ProjectDir = if ([string]::IsNullOrEmpty($env:PROJECT_DIR)) { $DefaultProjectDir } else { $env:PROJECT_DIR }
$LogDir = if ([string]::IsNullOrEmpty($env:LOG_DIR)) { Join-Path $ProjectDir "output_batch" } else { $env:LOG_DIR }

$DefaultAttacks = @(
    "xrce-dds-udp-dos",
    "xrce-dds-entity-flood",
    "xrce-dds-fragment-abuse",
    "xrce-dds-malformed-inject",
    "xrce-dds-session-hijack",
    "xrce-dds-time-desync",
    "mqtt-bruteforce",
    "mqtt-lwt-abuse",
    "mqtt-publisher-flood",
    "mqtt-qos-amplification"
)

$AttacksList = @()
if (-not [string]::IsNullOrEmpty($env:ATTACKS)) {
    $AttacksList = $env:ATTACKS -split '\s+' | Where-Object { $_ -match '\S' }
} else {
    $AttacksList = $DefaultAttacks
}

if (-not (Test-Path -Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}

$RunStartedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "==> Batch run started at $RunStartedAt"
Write-Host "    Project dir : $ProjectDir"
Write-Host "    Log dir     : $LogDir"
Write-Host "    Attacks     : $($AttacksList -join ' ')"
Write-Host "    Iterations  : 50 internal cycles per attack (variant_count=49 + base)"

Set-Location -Path $ProjectDir

$Failures = 0

foreach ($AttackId in $AttacksList) {
    $Intent = "quero gerar regras $AttackId"
    $Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $LogFile = Join-Path $LogDir "${Stamp}_${AttackId}.log"

    Write-Host ""
    Write-Host "===================================================================="
    Write-Host " ATTACK: $AttackId"
    Write-Host " INTENT: $Intent"
    Write-Host " LOG   : $LogFile"
    Write-Host " START : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "===================================================================="

    $LASTEXITCODE = 0
    try {
        $Intent | uv run --python 3.12 rules-farmer 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $LogFile
        if ($LASTEXITCODE -ne 0) {
            $Status = "failed"
            $Failures++
        } else {
            $Status = "ok"
        }
    } catch {
        $Status = "failed"
        $Failures++
        Write-Warning "Execution failed with exception: $_"
    }

    Write-Host " END   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ($Status)"
}

Write-Host ""
Write-Host "==> Batch run finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "    Attacks run : $($AttacksList.Count)"
Write-Host "    Failures    : $Failures"

if ($Failures -gt 0) {
    exit 1
}

#!/usr/bin/env bash
# Run the rules-farmer CLI once per attack family.
#
# Each invocation runs ONE experiment whose internal cycle count is controlled by
# config.yaml -> experiment_defaults.variant_count (set to 49, so each experiment runs
# 1 base + 49 variants = 50 attack executions). The orchestrator runs in
# continue_on_failure=true mode so all 50 cycles execute even if some don't fire.
#
# Validated rules (those that produced fired=True) are accumulated across runs in
# data/validated_rules/<attack_id>.rules and consulted by the Rules Agent BEFORE
# generating a new rule for the same attack family.
#
# Usage:
#   ./scripts/run_all_attacks.sh
#   ATTACKS="xrce-dds-udp-dos mqtt-bruteforce" ./scripts/run_all_attacks.sh
#
# Environment overrides:
#   PROJECT_DIR     — defaults to the repo root inferred from this script's location.
#   ATTACKS         — space-separated list of attack_ids; defaults to all 10.
#   LOG_DIR         — directory for per-run logs; defaults to ./output_batch.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
LOG_DIR="${LOG_DIR:-${PROJECT_DIR}/output_batch}"

DEFAULT_ATTACKS=(
  xrce-dds-udp-dos
  xrce-dds-entity-flood
  xrce-dds-fragment-abuse
  xrce-dds-malformed-inject
  xrce-dds-session-hijack
  xrce-dds-time-desync
  mqtt-bruteforce
  mqtt-lwt-abuse
  mqtt-publisher-flood
  mqtt-qos-amplification
)

if [[ -n "${ATTACKS:-}" ]]; then
  read -r -a ATTACK_LIST <<< "${ATTACKS}"
else
  ATTACK_LIST=("${DEFAULT_ATTACKS[@]}")
fi

mkdir -p "${LOG_DIR}"

run_started_at="$(date '+%Y-%m-%d %H:%M:%S')"
echo "==> Batch run started at ${run_started_at}"
echo "    Project dir : ${PROJECT_DIR}"
echo "    Log dir     : ${LOG_DIR}"
echo "    Attacks     : ${ATTACK_LIST[*]}"
echo "    Iterations  : 50 internal cycles per attack (variant_count=49 + base)"

cd "${PROJECT_DIR}"

failures=0
for attack_id in "${ATTACK_LIST[@]}"; do
  intent="quero gerar regras ${attack_id}"
  stamp="$(date '+%Y%m%d_%H%M%S')"
  log_file="${LOG_DIR}/${stamp}_${attack_id}.log"

  echo
  echo "===================================================================="
  echo " ATTACK: ${attack_id}"
  echo " INTENT: ${intent}"
  echo " LOG   : ${log_file}"
  echo " START : $(date '+%Y-%m-%d %H:%M:%S')"
  echo "===================================================================="

  # rules-farmer reads the intent from stdin (input() in cli.main).
  if printf '%s\n' "${intent}" \
      | uv run --python 3.12 rules-farmer 2>&1 \
      | tee "${log_file}"; then
    status="ok"
  else
    status="failed"
    failures=$((failures + 1))
  fi

  echo " END   : $(date '+%Y-%m-%d %H:%M:%S') (${status})"
done

echo
echo "==> Batch run finished at $(date '+%Y-%m-%d %H:%M:%S')"
echo "    Attacks run : ${#ATTACK_LIST[@]}"
echo "    Failures    : ${failures}"

if [[ ${failures} -gt 0 ]]; then
  exit 1
fi

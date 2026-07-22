#!/usr/bin/env python3
"""Self-contained functional test (teste mínimo) for the Salão de Ferramentas.

Runs the tool's real IDS machinery end-to-end against a **local Snort 3 container**
— no SSH, no remote testbed, no LLM key, no live packet capture. It drives the
exact production classes an experiment uses:

  * ``SnortRuleValidator``  → validates a candidate rule against the real Snort engine
  * ``IDSRuleInjector``     → deploys the rule and reloads the IDS container
  * ``IDSMonitor``          → reads Snort's alert log to decide whether a rule fired

by pointing them at a ``LocalCommandClient`` (a drop-in for ``SSHClient`` that runs
commands locally). Attack traffic is supplied as tiny PCAPs replayed through Snort in
read-file mode, so the whole thing is deterministic and needs no elevated privileges.

Checks performed:
  1. A well-formed rule is ACCEPTED by the real Snort validator.
  2. A rule the Snort engine cannot parse is REJECTED (with Snort's error).
  3. After deploying the rule, an attack PCAP makes the IDS FIRE the alert.
  4. A benign PCAP does NOT fire the alert (no false positive).

Exit code 0 = all checks passed.

Usage:
    uv run --python 3.12 python teste_minimo/run_teste_minimo.py [--keep]

Requires only Docker. The first run pulls/builds the Snort image (~1.8 GB base).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import make_pcaps  # noqa: E402  (local sibling module)
from local_command_client import LocalCommandClient  # noqa: E402

from rules_farmer.ids_monitor import IDSMonitor  # noqa: E402
from rules_farmer.ids_rule_injector import IDSRuleInjector  # noqa: E402
from rules_farmer.ids_rule_validator import SnortRuleValidator  # noqa: E402


# --------------------------------------------------------------------------- config
IMAGE = "rules-farmer-snort-min:latest"
CONTAINER = "rules_farmer_teste_minimo"
SID = 9000001
SIGNATURE = make_pcaps.SIGNATURE.decode()

CFG_DIR_HOST = HERE / "snort"
RUNTIME = HERE / ".runtime"
LOG_DIR_HOST = RUNTIME / "logs"
PCAP_DIR_HOST = RUNTIME / "pcaps"
DEPLOYED_RULE_HOST = CFG_DIR_HOST / "rules" / "temp" / "rules_farmer_ai.rules"
ALL_RULES_HOST = CFG_DIR_HOST / "rules" / "all.rules"
ALERT_LOG_HOST = LOG_DIR_HOST / "alert_fast.txt"
CANDIDATE_HOST = RUNTIME / "candidate.rules"

GOOD_RULE = (
    f'alert udp any any -> any any ( msg:"RULES-FARMER MINIMAL TEST"; '
    f'content:"{SIGNATURE}"; sid:0; rev:1; )'
)
# Passes the validator's structural pre-checks but uses an option the real Snort
# engine does not know, so only a genuine `snort -T` run can reject it.
BAD_RULE = (
    'alert udp any any -> any any ( msg:"RULES-FARMER BAD RULE"; '
    "definitely_not_a_snort_option:123; sid:0; rev:1; )"
)
DEPLOYED_RULE = (
    f'alert udp any any -> any any ( msg:"RULES-FARMER MINIMAL TEST"; '
    f'content:"{SIGNATURE}"; sid:{SID}; rev:1; )'
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("teste_minimo")


# --------------------------------------------------------------------------- helpers
def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr or result.stdout}"
        )
    return result


def _replay(client: LocalCommandClient, pcap_name: str) -> None:
    """Process one PCAP through the deployed config in the running container."""
    client.run_command(
        f"docker exec {CONTAINER} snort -c /etc/snort/snort.lua "
        f"-r /pcaps/{pcap_name} -k none -l /var/log/snort -A alert_fast -q"
    )


def setup() -> None:
    log.info("Building Snort image %s ...", IMAGE)
    _run(["docker", "build", "-q", "-t", IMAGE, str(CFG_DIR_HOST)])

    log.info("Generating attack/benign PCAPs ...")
    make_pcaps.generate(PCAP_DIR_HOST)

    LOG_DIR_HOST.mkdir(parents=True, exist_ok=True)
    LOG_DIR_HOST.chmod(0o777)
    RUNTIME.mkdir(parents=True, exist_ok=True)
    DEPLOYED_RULE_HOST.parent.mkdir(parents=True, exist_ok=True)
    DEPLOYED_RULE_HOST.write_text("", encoding="utf-8")
    ALERT_LOG_HOST.write_text("", encoding="utf-8")

    _run(["docker", "rm", "-f", CONTAINER], check=False)
    log.info("Starting Snort container %s (network none, no privileges) ...", CONTAINER)
    _run(
        [
            "docker", "run", "-d", "--name", CONTAINER,
            "--network", "none",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{CFG_DIR_HOST}:/etc/snort",
            "-v", f"{LOG_DIR_HOST}:/var/log/snort",
            "-v", f"{PCAP_DIR_HOST}:/pcaps",
            IMAGE,
        ]
    )


def teardown() -> None:
    _run(["docker", "rm", "-f", CONTAINER], check=False)


# --------------------------------------------------------------------------- checks
def main() -> int:
    keep = "--keep" in sys.argv
    setup()
    client = LocalCommandClient()

    validator = SnortRuleValidator(
        ssh_client=client,
        temp_rule_path=str(CANDIDATE_HOST),
        container_name=CONTAINER,
        container_temp_rule_path="/tmp/rules_farmer_candidate.rules",
        snort_config_path="/etc/snort/snort.lua",
    )
    injector = IDSRuleInjector(
        ssh_client=client,
        rules_file_path=str(DEPLOYED_RULE_HOST),
        include_file_path=str(ALL_RULES_HOST),
        include_statement="include /etc/snort/rules/temp/rules_farmer_ai.rules",
        container_name=CONTAINER,
        poll_interval_seconds=0.5,
        max_health_polls=20,
    )
    monitor = IDSMonitor(ssh_client=client, alert_log_path=str(ALERT_LOG_HOST))

    results: list[tuple[str, bool, str]] = []

    try:
        # 1 — real Snort accepts a well-formed rule.
        good = validator.validate(GOOD_RULE)
        results.append(("Regra valida aceita pelo Snort real", good.valid, good.error or "ok"))

        # 2 — real Snort rejects a rule it cannot parse.
        bad = validator.validate(BAD_RULE)
        detail = (bad.error or "").splitlines()[0] if bad.error else "sem erro (inesperado)"
        results.append(("Regra invalida rejeitada pelo Snort real", not bad.valid, detail))

        # 3 — deploy the rule and fire it with an attack PCAP.
        injector.inject([DEPLOYED_RULE])
        monitor.clear_alert_log()
        _replay(client, "attack.pcap")
        fired_attack = monitor.check_fired(SID)
        results.append(("Ataque detectado (alerta disparado)", fired_attack, f"fired={fired_attack}"))

        # 4 — benign PCAP must not fire (no false positive).
        monitor.clear_alert_log()
        _replay(client, "benign.pcap")
        fired_benign = monitor.check_fired(SID)
        results.append(("Trafego benigno NAO dispara alerta", not fired_benign, f"fired={fired_benign}"))
    finally:
        if keep:
            log.info("Deixando o container %s de pe (--keep).", CONTAINER)
        else:
            teardown()

    # --------------------------------------------------------------------- report
    print("\n" + "=" * 68)
    print("  TESTE MINIMO — Rules Farmer (ciclo de detecao contra Snort real)")
    print("=" * 68)
    all_ok = True
    for name, ok, detail in results:
        status = "PASS" if ok else "FALHOU"
        all_ok = all_ok and ok
        print(f"  [{status:6}] {name}")
        print(f"            -> {detail}")
    print("=" * 68)
    print("  RESULTADO:", "TODOS OS TESTES PASSARAM [OK]" if all_ok else "HOUVE FALHAS [FAIL]")
    print("=" * 68 + "\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

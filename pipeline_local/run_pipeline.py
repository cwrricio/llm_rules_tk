#!/usr/bin/env python3
"""Run the COMPLETE Rules Farmer pipeline for one attack, self-contained, real LLM.

The evaluator runs this to watch the full loop end to end:
  intent -> Rules Agent generates/validates/deploys a Snort rule -> benign false-positive
  check -> Attack Agent runs the attack container -> Snort detection feedback -> the Attack
  Agent MUTATES the attack source and REBUILDS its image to evade -> the Rules Agent refines.

Everything is the real production code (Orchestrator, both agno agents, validator/injector/
monitor, executor, discovery, recorders). The only local substitutions — both honest and
documented — are: SSH transport -> local Docker, and live packet capture -> pcap replay
through the real Snort engine (live capture needs privileges unavailable in a self-contained
run). See pipeline_local/README.md.

Requires: Docker + ONE LLM API key (the pipeline makes real, non-deterministic LLM calls).
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from rules_farmer.config import AgentModelConfig, AttackDestinationsConfig, _load_dotenv  # noqa: E402
from rules_farmer.execution_logging import configure_execution_logging, log_stage  # noqa: E402

from pipeline_local.build_runtime import build_local_runtime  # noqa: E402

HERE = Path(__file__).resolve().parent
SNORT_CFG_DIR = REPO_ROOT / "teste_minimo" / "snort"     # reuse the teste mínimo Snort image/config
RUNTIME_DIR = HERE / ".runtime"
LOG_DIR = RUNTIME_DIR / "logs"
PCAP_DIR = RUNTIME_DIR / "pcaps"
ATTACKS_ROOT = HERE / "attacks"
RESULTS_DIR = REPO_ROOT / "results"
CONFIG_PATH = HERE / "config.pipeline.yaml"

SNORT_IMAGE = "rules-farmer-snort-min:latest"
SNORT_CONTAINER = "rules_farmer_pipeline_snort"
ATTACK_IMAGE = "iotedu-attack-xrce-dds-udp-dos:latest"

_KEY_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "groq": "GROQ_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
}

log = logging.getLogger("pipeline_local.run")


def _sh(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr or result.stdout}"
        )
    return result


def setup() -> None:
    log_stage("BUILD DA IMAGEM DO SNORT")
    _sh(["docker", "build", "-q", "-t", SNORT_IMAGE, str(SNORT_CFG_DIR)])
    log_stage("BUILD DA IMAGEM DO ATAQUE")
    _sh(["docker", "build", "-q", "-t", ATTACK_IMAGE, str(ATTACKS_ROOT / "xrce-dds-udp-dos")])

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.chmod(0o777)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    PCAP_DIR.chmod(0o777)
    (SNORT_CFG_DIR / "rules" / "temp").mkdir(parents=True, exist_ok=True)
    (LOG_DIR / "alert_fast.txt").write_text("", encoding="utf-8")

    _sh(["docker", "rm", "-f", SNORT_CONTAINER], check=False)
    log_stage("SUBINDO O CONTAINER DO SNORT (network none, sem privilegios)")
    _sh([
        "docker", "run", "-d", "--name", SNORT_CONTAINER,
        "--network", "none",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{SNORT_CFG_DIR}:/etc/snort",
        "-v", f"{LOG_DIR}:/var/log/snort",
        "-v", f"{PCAP_DIR}:/pcaps",
        SNORT_IMAGE,
    ])


def teardown() -> None:
    _sh(["docker", "rm", "-f", SNORT_CONTAINER], check=False)


def _model_cfg(raw: dict, provider_override: str | None, model_override: str | None) -> AgentModelConfig:
    cfg = dict(raw)
    if provider_override:
        cfg["provider"] = provider_override
    if model_override:
        cfg["model"] = model_override
    return AgentModelConfig(**cfg)


def main() -> int:
    parser = argparse.ArgumentParser(description="Self-contained real-LLM Rules Farmer pipeline")
    parser.add_argument(
        "--intent",
        default="Detect XRCE-DDS UDP DoS flood against the XRCE-DDS Agent on 172.17.0.2 port 8888",
    )
    parser.add_argument("--variant-count", type=int, default=None, help="override variant_count")
    parser.add_argument("--provider", default=os.environ.get("RF_PROVIDER"))
    parser.add_argument("--model", default=os.environ.get("RF_MODEL"))
    parser.add_argument("--keep", action="store_true", help="keep the Snort container after the run")
    args = parser.parse_args()

    # Load .env next to config.yaml (root), then configure logging so every stage streams.
    _load_dotenv(REPO_ROOT / "config.yaml")
    configure_execution_logging(REPO_ROOT / "output.log")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s",
                        stream=sys.stdout)
    for noisy in ("httpx", "httpcore", "urllib3", "openai", "anthropic", "agno", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    raw = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    rule_cfg = _model_cfg(raw["llm"]["rule_agent"], args.provider, args.model)
    attacker_cfg = _model_cfg(raw["llm"]["attacker_agent"], args.provider, args.model)
    defaults = raw["experiment_defaults"]
    destinations = AttackDestinationsConfig(**raw["attack_destinations"])
    variant_count = args.variant_count if args.variant_count is not None else defaults["variant_count"]

    key_env = _KEY_ENV.get(rule_cfg.provider.lower())
    if not key_env or not os.environ.get(key_env):
        print(
            f"\n[ERRO] O pipeline faz chamadas REAIS ao LLM e precisa da chave "
            f"{key_env or '<provider>_API_KEY'} para o provider '{rule_cfg.provider}'.\n"
            f"       Defina-a no ambiente (export {key_env}=...) ou em um .env ao lado de "
            f"config.yaml, ou escolha outro provider com --provider/--model "
            f"(anthropic|openai|groq|deepseek).\n",
            file=sys.stderr,
        )
        return 2

    print("=" * 74)
    print("  PIPELINE COMPLETO — Rules Farmer (geracao de regra + variacoes de ataque)")
    print("=" * 74)
    print(f"  intent        : {args.intent}")
    print(f"  provider/model: {rule_cfg.provider} / {rule_cfg.model}")
    print(f"  base+variantes: 1 + {variant_count}   (max_iterations={defaults['max_iterations']}, "
          f"convergence={defaults['convergence_threshold']})")
    print("=" * 74 + "\n")

    setup()
    try:
        runtime = build_local_runtime(
            rule_model_cfg=rule_cfg,
            attacker_model_cfg=attacker_cfg,
            attack_destinations=destinations,
            snort_container=SNORT_CONTAINER,
            snort_cfg_dir=SNORT_CFG_DIR,
            log_dir=LOG_DIR,
            pcap_dir=PCAP_DIR,
            attacks_root=ATTACKS_ROOT,
            runtime_dir=RUNTIME_DIR,
            results_dir=RESULTS_DIR,
            continue_on_failure=defaults.get("continue_on_failure", True),
        )
        result = runtime.orchestrator.run_experiment(
            intent=args.intent,
            max_iterations=defaults["max_iterations"],
            variant_count=variant_count,
            convergence_threshold=defaults["convergence_threshold"],
        )
    finally:
        if args.keep:
            log.info("Mantendo o container %s de pe (--keep).", SNORT_CONTAINER)
        else:
            teardown()

    print("\n" + "=" * 74)
    print("  PIPELINE FINALIZADO")
    print("=" * 74)
    print(f"  status        : {result.status}")
    print(f"  experiment_id : {result.experiment_id}")
    print(f"  dados gerados :")
    print(f"    - {result.json_path}")
    print(f"    - {result.csv_path}")
    mut = RESULTS_DIR / result.experiment_id / "mutations"
    if mut.exists():
        print(f"    - {mut}/   (fontes de ataque mutadas por variante)")
    print("=" * 74 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

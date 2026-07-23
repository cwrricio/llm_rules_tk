"""Wire the REAL pipeline against local Docker (no SSH, no remote testbed).

This mirrors ``rules_farmer.app_factory.build_runtime`` one-for-one, but:
  * both "SSH" clients are a single local ``LocalCommandClient`` (runs docker locally);
  * the attack executor is ``LocalAttackExecutor`` (runs the attack container + replays
    its pcap through Snort) and the benign runner is ``LocalBenignTrafficRunner``;
  * every path points at a local runtime tree instead of the testbed;
  * the two agents use the REAL model provider from config (live LLM).

Everything else is untouched production code: SnortRuleValidator, IDSRuleInjector,
IDSMonitor, RemoteAttackDiscovery, AttackerAgent, RulesAgent, Orchestrator, the
recorders and the SID manager.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from rules_farmer.agents import AttackerAgent, RulesAgent
from rules_farmer.app_factory import _create_agno_model
from rules_farmer.attack_discovery import RemoteAttackDiscovery
from rules_farmer.config import AgentModelConfig, AttackDestinationsConfig
from rules_farmer.execution_logging import log_stage
from rules_farmer.experiment_recorder import ExperimentIDFactory, ExperimentRecorder
from rules_farmer.ids_monitor import IDSMonitor
from rules_farmer.ids_rule_injector import IDSRuleInjector
from rules_farmer.ids_rule_validator import SnortRuleValidator
from rules_farmer.mutation_recorder import MutationContext
from rules_farmer.orchestrator import Orchestrator
from rules_farmer.sid_manager import SIDManager
from rules_farmer.validated_rules import ValidatedRulesStore

from pipeline_local.local_harness import LocalAttackExecutor, LocalBenignTrafficRunner
from pipeline_local.local_command_client import LocalCommandClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LocalRuntime:
    orchestrator: Orchestrator
    results_dir: Path
    snort_container: str


def build_local_runtime(
    *,
    rule_model_cfg: AgentModelConfig,
    attacker_model_cfg: AgentModelConfig,
    attack_destinations: AttackDestinationsConfig,
    snort_container: str,
    snort_cfg_dir: Path,
    log_dir: Path,
    pcap_dir: Path,
    attacks_root: Path,
    runtime_dir: Path,
    results_dir: Path,
    continue_on_failure: bool = True,
) -> LocalRuntime:
    log_stage("MONTANDO COMPONENTES (PIPELINE LOCAL)")
    client = LocalCommandClient(command_timeout=180)

    deployed_rule_host = snort_cfg_dir / "rules" / "temp" / "rules_farmer_ai.rules"
    all_rules_host = snort_cfg_dir / "rules" / "all.rules"
    alert_log_host = log_dir / "alert_fast.txt"
    candidate_host = runtime_dir / "candidate.rules"

    validator = SnortRuleValidator(
        ssh_client=client,
        temp_rule_path=str(candidate_host),
        container_name=snort_container,
        container_temp_rule_path="/tmp/rules_farmer_candidate.rules",
        snort_config_path="/etc/snort/snort.lua",
    )
    injector = IDSRuleInjector(
        ssh_client=client,
        rules_file_path=str(deployed_rule_host),
        include_file_path=str(all_rules_host),
        include_statement="include /etc/snort/rules/temp/rules_farmer_ai.rules",
        container_name=snort_container,
        poll_interval_seconds=0.5,
        max_health_polls=20,
    )
    monitor = IDSMonitor(ssh_client=client, alert_log_path=str(alert_log_host))
    injector.ensure_rules_file()

    runtime_dir = Path(runtime_dir)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    sid_counter_path = runtime_dir / "sid_counter.json"
    if not sid_counter_path.exists():
        sid_counter_path.write_text('{"counter": 9000000}', encoding="utf-8")
    sid_manager = SIDManager(
        counter_path=sid_counter_path,
        mapping_path=runtime_dir / "sid_mappings.json",
    )
    recorder = ExperimentRecorder(output_dir=results_dir)
    validated_rules_store = ValidatedRulesStore(root=runtime_dir / "validated_rules")
    mutation_context = MutationContext(output_dir=results_dir)

    log_stage("DESCOBRINDO ATAQUES DISPONIVEIS (LOCAL)")
    discovered = RemoteAttackDiscovery(
        ssh_client=client, attacks_root=str(attacks_root)
    ).discover()
    logger.info("Discovered attacks count=%s ids=%s", len(discovered),
                [a.attack_id for a in discovered])
    if not discovered:
        raise RuntimeError(f"No attacks discovered under {attacks_root}")

    executor = LocalAttackExecutor(
        ssh_client=client,
        attacks={a.attack_id: a for a in discovered},
        snort_container=snort_container,
        pcap_dir_host=pcap_dir,
    )
    benign_runner = LocalBenignTrafficRunner(
        ssh_client=client, snort_container=snort_container, pcap_dir_host=pcap_dir
    )

    attacker_agent = AttackerAgent(
        model=_create_agno_model(attacker_model_cfg),
        attacks=discovered,
        executor=executor,
        mutation_context=mutation_context,
    )
    rules_agent = RulesAgent(
        model=_create_agno_model(rule_model_cfg),
        validator=validator,
        sid_manager=sid_manager,
        injector=injector,
        monitor=monitor,
        attacker_agent=attacker_agent,
        recorder=recorder,
        validated_rules_store=validated_rules_store,
        mutation_context=mutation_context,
        benign_runner=benign_runner,
    )

    orchestrator = Orchestrator(
        rules_agent=rules_agent,
        recorder=recorder,
        attack_destinations=attack_destinations,
        experiment_id_factory=ExperimentIDFactory(runtime_dir / "experiment_counter.json"),
        continue_on_failure=continue_on_failure,
        validated_rules_store=validated_rules_store,
    )
    log_stage("RUNTIME LOCAL PRONTO")
    return LocalRuntime(
        orchestrator=orchestrator,
        results_dir=Path(results_dir),
        snort_container=snort_container,
    )

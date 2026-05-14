from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import FastAPI

from rules_farmer.agents import AttackerAgent, RulesAgent
from rules_farmer.api import create_app
from rules_farmer.attack_discovery import RemoteAttackDiscovery
from rules_farmer.attack_executor import AttackExecutor
from rules_farmer.config import AgentModelConfig, load_config
from rules_farmer.execution_logging import configure_execution_logging, log_stage
from rules_farmer.experiment_recorder import ExperimentIDFactory, ExperimentRecorder
from rules_farmer.ids_monitor import IDSMonitor
from rules_farmer.ids_rule_injector import IDSRuleInjector
from rules_farmer.ids_rule_validator import SnortRuleValidator
from rules_farmer.orchestrator import Orchestrator
from rules_farmer.sid_manager import SIDManager
from rules_farmer.ssh import SSHClient


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuntimeStack:
    orchestrator: Orchestrator
    default_max_iterations: int
    default_variant_count: int
    orchestrator_host: str
    orchestrator_port: int


def build_runtime(config_path: str = "config.yaml") -> RuntimeStack:
    log_stage("MONTANDO COMPONENTES")
    logger.debug("Runtime build started config_path=%s", config_path)
    config = load_config(config_path)

    log_stage("CONECTANDO NO IDS")
    logger.info(
        "Connecting to IDS over SSH host=%s user=%s",
        config.ssh.entity2_host,
        config.ssh.entity2_user,
    )
    ids_ssh = SSHClient(
        host=config.ssh.entity2_host,
        user=config.ssh.entity2_user,
        key_path=config.ssh.entity2_key_path,
        connect_timeout=config.timeouts.ssh_connect_seconds,
        max_attempts=config.ssh_retry.max_attempts,
        base_delay_seconds=config.ssh_retry.base_delay_seconds,
    )
    log_stage("CONECTANDO NO ATACANTE")
    logger.info(
        "Connecting to attacker over SSH host=%s user=%s",
        config.ssh.entity3_host,
        config.ssh.entity3_user,
    )
    attacker_ssh = SSHClient(
        host=config.ssh.entity3_host,
        user=config.ssh.entity3_user,
        key_path=config.ssh.entity3_key_path,
        connect_timeout=config.timeouts.ssh_connect_seconds,
        max_attempts=config.ssh_retry.max_attempts,
        base_delay_seconds=config.ssh_retry.base_delay_seconds,
    )

    validator = SnortRuleValidator(
        ssh_client=ids_ssh,
        container_name=config.testbed.ids_container_name,
        snort_config_path=config.testbed.ids_snort_config_path,
    )
    injector = IDSRuleInjector(
        ssh_client=ids_ssh,
        rules_file_path=config.testbed.ids_rules_file_path,
        include_file_path=config.testbed.ids_rules_include_file_path,
        include_statement=config.testbed.ids_rule_include_statement,
        container_name=config.testbed.ids_container_name,
    )
    monitor = IDSMonitor(ssh_client=ids_ssh, alert_log_path=config.testbed.ids_alert_log_path)

    sid_manager = SIDManager(
        counter_path=config.testbed.sid_counter_file_path,
        mapping_path=config.testbed.sid_mapping_file_path,
    )
    recorder = ExperimentRecorder(output_dir=config.testbed.results_output_dir)

    injector.ensure_rules_file()

    log_stage("DESCOBRINDO ATAQUES DISPONIVEIS")
    discovered_attacks = RemoteAttackDiscovery(
        ssh_client=attacker_ssh,
        attacks_root=config.testbed.attacker_attacks_root,
    ).discover()
    logger.info("Discovered attacks count=%s", len(discovered_attacks))
    if not discovered_attacks:
        raise RuntimeError(
            "No attacks were discovered. "
            f"Check testbed.attacker_attacks_root={config.testbed.attacker_attacks_root!r}."
        )

    attack_executor = AttackExecutor(
        ssh_client=attacker_ssh,
        attacks={attack.attack_id: attack for attack in discovered_attacks},
    )

    attacker_agent = AttackerAgent(
        model=_create_agno_model(config.llm.attacker_agent),
        attacks=discovered_attacks,
        executor=attack_executor,
    )
    rules_agent = RulesAgent(
        model=_create_agno_model(config.llm.rule_agent),
        validator=validator,
        sid_manager=sid_manager,
        injector=injector,
        monitor=monitor,
        attacker_agent=attacker_agent,
        recorder=recorder,
    )

    experiment_id_factory = ExperimentIDFactory(config.testbed.experiment_counter_file_path)

    orchestrator = Orchestrator(
        rules_agent=rules_agent,
        recorder=recorder,
        attack_destinations=config.attack_destinations,
        experiment_id_factory=experiment_id_factory,
    )

    logger.debug(
        "Runtime build completed default_max_iterations=%s default_variant_count=%s",
        config.experiment_defaults.max_iterations,
        config.experiment_defaults.variant_count,
    )
    log_stage("RUNTIME PRONTO")
    return RuntimeStack(
        orchestrator=orchestrator,
        default_max_iterations=config.experiment_defaults.max_iterations,
        default_variant_count=config.experiment_defaults.variant_count,
        orchestrator_host=config.testbed.orchestrator_host,
        orchestrator_port=config.testbed.orchestrator_port,
    )


def _create_agno_model(cfg: AgentModelConfig):
    """Instantiate the right agno model class from the per-agent provider configuration.

    Agno reads API keys from env vars (ANTHROPIC_API_KEY / OPENAI_API_KEY / GROQ_API_KEY /
    DEEPSEEK_API_KEY) — config.load_config() ensures the .env file has been merged into the
    process environment before this is called.
    """
    provider = cfg.provider.lower()
    if provider == "anthropic":
        from agno.models.anthropic import Claude

        return Claude(id=cfg.model, temperature=cfg.temperature, max_tokens=cfg.max_tokens)
    if provider == "openai":
        from agno.models.openai import OpenAIChat

        return OpenAIChat(id=cfg.model, temperature=cfg.temperature, max_tokens=cfg.max_tokens)
    if provider == "groq":
        from agno.models.groq import Groq

        return Groq(id=cfg.model, temperature=cfg.temperature, max_tokens=cfg.max_tokens)
    if provider == "deepseek":
        from agno.models.deepseek import DeepSeek

        return DeepSeek(id=cfg.model, temperature=cfg.temperature, max_tokens=cfg.max_tokens)
    
    if provider == "gemini":
        from agno.models.google import Gemini

        return Gemini(id=cfg.model, temperature=cfg.temperature)
    raise ValueError(
        f"Unsupported llm provider: {cfg.provider!r}. Expected anthropic / openai / groq / deepseek."
    )


def create_real_app(config_path: str = "config.yaml") -> FastAPI:
    configure_execution_logging("output.log")
    logger.info("Creating real FastAPI app")
    runtime = build_runtime(config_path)

    return create_app(
        orchestrator=runtime.orchestrator,
        default_max_iterations=runtime.default_max_iterations,
        default_variant_count=runtime.default_variant_count,
    )

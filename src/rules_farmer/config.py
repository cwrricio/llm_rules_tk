from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


logger = logging.getLogger(__name__)


class AgentModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    model: str
    temperature: float
    max_tokens: int = 8192


class LLMConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_agent: AgentModelConfig
    attacker_agent: AgentModelConfig


class TimeoutConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_tool_seconds: int
    attack_tool_extension_seconds: int
    ssh_connect_seconds: int


class SSHConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity2_host: str
    entity2_user: str
    entity2_key_path: str
    entity3_host: str
    entity3_user: str
    entity3_key_path: str


class SSHRetryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_attempts: int
    base_delay_seconds: float


class AttackPlanValidationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_retries: int


class ExperimentDefaultsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_iterations: int
    variant_count: int


class TestbedConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    orchestrator_host: str = "localhost"
    orchestrator_port: int = 8000
    ids_alert_log_path: str
    ids_rules_file_path: str
    ids_rules_include_file_path: str
    ids_rule_include_statement: str
    ids_container_name: str
    ids_snort_config_path: str
    sid_counter_file_path: str
    sid_mapping_file_path: str = "./data/sid_mappings.json"
    experiment_counter_file_path: str = "./data/experiment_counter.json"
    attacker_attacks_root: str
    attacker_capture_interface: str = "any"
    results_output_dir: str


class APIKeys(BaseModel):
    model_config = ConfigDict(extra="forbid")

    anthropic: str | None = None
    openai: str | None = None
    groq: str | None = None
    deepseek: str | None = None


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    llm: LLMConfig
    timeouts: TimeoutConfig
    ssh: SSHConfig
    ssh_retry: SSHRetryConfig
    attack_plan_validation: AttackPlanValidationConfig
    experiment_defaults: ExperimentDefaultsConfig
    testbed: TestbedConfig
    api_keys: APIKeys = Field(default_factory=APIKeys)


def load_config(path: str | Path) -> Config:
    config_path = Path(path)
    logger.debug("Config load started path=%s", config_path)
    _load_dotenv(config_path)
    with config_path.open("r", encoding="utf-8") as config_file:
        raw_config = yaml.safe_load(config_file) or {}

    raw_config.pop("api_keys", None)
    _apply_env_overrides(raw_config)
    raw_config["api_keys"] = APIKeys(
        anthropic=os.environ.get("ANTHROPIC_API_KEY"),
        openai=os.environ.get("OPENAI_API_KEY"),
        groq=os.environ.get("GROQ_API_KEY"),
        deepseek=os.environ.get("DEEPSEEK_API_KEY"),
    ).model_dump()
    config = Config.model_validate(raw_config)
    logger.debug("Config load finished path=%s", config_path)
    return config


def _load_dotenv(config_path: Path) -> None:
    dotenv_path = config_path.with_name(".env")
    if not dotenv_path.exists():
        logger.debug("Dotenv not found path=%s", dotenv_path)
        return
    logger.debug("Loading dotenv path=%s", dotenv_path)

    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if (
            (value.startswith('"') and value.endswith('"'))
            or (value.startswith("'") and value.endswith("'"))
        ):
            value = value[1:-1]

        os.environ.setdefault(key, value)


def _apply_env_overrides(config: dict[str, Any]) -> None:
    for name, value in os.environ.items():
        if "__" not in name:
            continue

        path = [part.lower() for part in name.split("__")]
        current: dict[str, Any] = config
        for part in path[:-1]:
            next_value = current.get(part)
            if not isinstance(next_value, dict):
                next_value = {}
                current[part] = next_value
            current = next_value
        current[path[-1]] = value

import textwrap

import pytest
from pydantic import ValidationError

from rules_farmer.config import load_config


def write_config(path):
    path.write_text(
        textwrap.dedent(
            """
            llm:
              rule_agent:
                provider: anthropic
                model: claude-sonnet-4-6
                temperature: 0
              attacker_agent:
                provider: openai
                model: gpt-5
                temperature: 0
            timeouts:
              attack_tool_seconds: 60
              attack_tool_extension_seconds: 30
              ssh_connect_seconds: 10
            ssh:
              entity2_host: 192.168.1.2
              entity2_user: admin
              entity2_key_path: ~/.ssh/ids_key
              entity3_host: 192.168.1.3
              entity3_user: admin
              entity3_key_path: ~/.ssh/attacker_key
            ssh_retry:
              max_attempts: 3
              base_delay_seconds: 1
            attack_plan_validation:
              max_retries: 3
            experiment_defaults:
              max_iterations: 5
              variant_count: 3
            testbed:
              orchestrator_host: localhost
              orchestrator_port: 8000
              ids_alert_log_path: /var/log/snort/alert
              ids_rules_file_path: /home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/temp/rules_farmer_ai.rules
              ids_rules_include_file_path: /home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/all.rules
              ids_rule_include_statement: include rules/temp/rules_farmer_ai.rules
              ids_container_name: snort_ids
              ids_snort_config_path: /opt/snort3/etc/snort/snort.lua
              sid_counter_file_path: ./data/sid_counter.json
              attacker_attacks_root: /home/unipampa/ataques/attackers-claude
              attacker_capture_interface: any
              results_output_dir: ./results
            """
        ).strip()
    )


def test_load_config_reads_yaml_and_env_overrides(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    monkeypatch.setenv("LLM__RULE_AGENT__MODEL", "claude-opus-4-1")
    monkeypatch.setenv("TESTBED__ORCHESTRATOR_PORT", "9000")

    config = load_config(config_path)

    assert config.llm.rule_agent.provider == "anthropic"
    assert config.llm.rule_agent.model == "claude-opus-4-1"
    assert config.testbed.orchestrator_port == 9000
    assert config.ssh.entity2_host == "192.168.1.2"
    assert config.testbed.sid_mapping_file_path == "./data/sid_mappings.json"
    assert (
        config.testbed.ids_rule_include_statement
        == "include rules/temp/rules_farmer_ai.rules"
    )
    assert config.testbed.attacker_attacks_root == "/home/unipampa/ataques/attackers-claude"
    assert config.testbed.attacker_capture_interface == "any"


def test_orchestrator_api_host_and_port_default_when_cli_config_omits_them(tmp_path):
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    config_path.write_text(
        config_path.read_text()
        .replace("              orchestrator_host: localhost\n", "")
        .replace("              orchestrator_port: 8000\n", "")
    )

    config = load_config(config_path)

    assert config.testbed.orchestrator_host == "localhost"
    assert config.testbed.orchestrator_port == 8000


def test_api_keys_are_loaded_only_from_environment(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    monkeypatch.setenv("OPENAI_API_KEY", "env-openai-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-anthropic-key")
    monkeypatch.setenv("GROQ_API_KEY", "env-groq-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "env-deepseek-key")

    config = load_config(config_path)

    assert config.api_keys.openai == "env-openai-key"
    assert config.api_keys.anthropic == "env-anthropic-key"
    assert config.api_keys.groq == "env-groq-key"
    assert config.api_keys.deepseek == "env-deepseek-key"


def test_load_config_loads_dotenv_next_to_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    (tmp_path / ".env").write_text("GROQ_API_KEY=dotenv-groq-key\n", encoding="utf-8")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    config = load_config(config_path)

    assert config.api_keys.groq == "dotenv-groq-key"


def test_missing_required_config_field_fails_at_load_time(tmp_path):
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    config_path.write_text(config_path.read_text().replace("ssh:\n", ""))

    with pytest.raises(ValidationError):
        load_config(config_path)

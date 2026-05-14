import textwrap

import pytest
from pydantic import ValidationError

from rules_farmer.config import Config, load_config


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
            attack_destinations:
              mqtt:
                ip: 172.17.0.2
                port: 1883
              xrce:
                ip: 172.17.0.2
                port: 8888
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
    assert config.attack_destinations.mqtt.port == 1883
    assert config.attack_destinations.xrce.port == 8888
    assert config.attack_destinations.mqtt.ip == "172.17.0.2"


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


def test_load_config_drops_legacy_api_keys_block(tmp_path):
    """Legacy configs may still carry api_keys: — load_config must silently drop it because agno
    reads keys directly from environment variables now."""
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    config_path.write_text(
        config_path.read_text()
        + "\napi_keys:\n  anthropic: legacy-should-be-ignored\n"
    )

    # Should not raise — the legacy key is popped before validation.
    config = load_config(config_path)
    assert isinstance(config, Config)
    assert not hasattr(config, "api_keys")


def test_load_config_drops_legacy_attack_plan_validation(tmp_path):
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    # The base fixture already has attack_plan_validation: — just confirm it doesn't break.

    config = load_config(config_path)
    assert isinstance(config, Config)
    assert not hasattr(config, "attack_plan_validation")


def test_load_config_loads_dotenv_next_to_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=dotenv-anthropic-key\n", encoding="utf-8")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    load_config(config_path)

    # .env must have been merged into os.environ for agno to find it later.
    import os
    assert os.environ.get("ANTHROPIC_API_KEY") == "dotenv-anthropic-key"


def test_missing_required_config_field_fails_at_load_time(tmp_path):
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    config_path.write_text(config_path.read_text().replace("ssh:\n", ""))

    with pytest.raises(ValidationError):
        load_config(config_path)

"""Unit tests for the per-agent tool factories under rules_farmer.tools.

Tools are thin wrappers that turn Python objects (validators, injectors, recorders, sub-agents)
into agno @tool functions. Each test verifies that the produced tool forwards correctly to the
wrapped service and returns the documented payload shape.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.attack_executor import ExecutionResult
from rules_farmer.benign_traffic import BenignRunResult
from rules_farmer.ids_rule_validator import ValidationResult
from rules_farmer.schemas import AttackerResult
from rules_farmer.sid_manager import AssignedRule
from rules_farmer.tools import (
    RunContext,
    make_assign_sid,
    make_check_alert_fired,
    make_deploy_rule,
    make_execute_attack,
    make_list_available_attacks,
    make_read_attack_definition,
    make_record_iteration,
    make_run_benign_traffic,
    make_trigger_attacker,
    make_validate_rule_syntax,
)


def _call(tool, **kwargs):
    """Invoke the underlying Python callable that the @tool decorator wrapped."""
    return tool.entrypoint(**kwargs)


def _benign_ok(protocol: str = "mqtt") -> BenignRunResult:
    """A successful benign run (exit_code 0, no stderr)."""
    return BenignRunResult(protocol=protocol, exit_code=0, stdout="ok", stderr="")


_MQTT = DiscoveredAttack(
    attack_id="mqtt-bruteforce",
    remote_path="/r",
    description="MQTT brute force",
    docker_image="iotedu-attack-mqtt-bruteforce:latest",
    required_arguments=["target", "port"],
    readme_excerpt="excerpt",
)


def test_validate_rule_syntax_returns_valid_string_when_validator_accepts():
    validator = MagicMock()
    validator.validate.return_value = ValidationResult(valid=True, error=None)
    tool = make_validate_rule_syntax(validator)

    assert _call(tool, rule="alert udp any any -> any any (sid:0;)") == "VALID"


def test_validate_rule_syntax_returns_error_prefixed_string_when_validator_rejects():
    validator = MagicMock()
    validator.validate.return_value = ValidationResult(valid=False, error="bad option")
    tool = make_validate_rule_syntax(validator)

    assert _call(tool, rule="x") == "INVALID: bad option"


def test_assign_sid_replaces_sid_zero_with_real_sid_via_sid_manager():
    sid_manager = MagicMock()
    sid_manager.assign_sids.return_value = [
        AssignedRule(sid=9000001, rule='alert udp any any -> any any (sid:9000001;)')
    ]
    tool = make_assign_sid(sid_manager)

    result = _call(tool, intent="Detect X", rule='alert udp any any -> any any (sid:0;)')

    assert result == {
        "sid": 9000001,
        "rule": 'alert udp any any -> any any (sid:9000001;)',
    }
    sid_manager.assign_sids.assert_called_once_with(
        "Detect X", ['alert udp any any -> any any (sid:0;)']
    )


def test_deploy_rule_forwards_to_injector():
    injector = MagicMock()
    monitor = MagicMock()
    tool = make_deploy_rule(injector, monitor)

    assert _call(tool, rule_with_sid="alert udp any any -> any any (sid:9000001;)") == "DEPLOYED"
    injector.inject.assert_called_once_with(["alert udp any any -> any any (sid:9000001;)"])
    monitor.clear_alert_log.assert_called_once_with()


def test_check_alert_fired_forwards_to_monitor():
    monitor = MagicMock()
    monitor.check_fired.return_value = True
    tool = make_check_alert_fired(monitor)

    assert _call(tool, sid=9000001) is True
    monitor.check_fired.assert_called_once_with(9000001)


def test_list_available_attacks_returns_catalog_summary():
    tool = make_list_available_attacks({_MQTT.attack_id: _MQTT})

    result = _call(tool)
    assert result == [
        {
            "attack_id": "mqtt-bruteforce",
            "description": "MQTT brute force",
            "required_arguments": ["target", "port"],
        }
    ]


def test_read_attack_definition_returns_full_definition_or_error():
    tool = make_read_attack_definition({_MQTT.attack_id: _MQTT})

    ok = _call(tool, attack_id="mqtt-bruteforce")
    assert ok["docker_image"] == "iotedu-attack-mqtt-bruteforce:latest"
    assert ok["required_arguments"] == ["target", "port"]

    err = _call(tool, attack_id="unknown")
    assert err == {"error": "unknown attack_id: unknown"}


def test_execute_attack_validates_argument_count_before_running(tmp_path):
    executor = MagicMock()
    tool = make_execute_attack(executor, {_MQTT.attack_id: _MQTT})

    err = _call(tool, attack_id="mqtt-bruteforce", arguments=["only-one-arg"])

    assert err["error"].startswith("argument count mismatch")
    executor.execute.assert_not_called()


def test_execute_attack_forwards_to_executor_and_serializes_result():
    executor = MagicMock()
    executor.execute.return_value = ExecutionResult(
        exit_code=0,
        stdout_json={"exit_code": 0},
        container_exit_code=0,
        container_stderr="",
    )
    tool = make_execute_attack(executor, {_MQTT.attack_id: _MQTT})

    result = _call(tool, attack_id="mqtt-bruteforce", arguments=["10.0.0.5", "1883"])

    assert result == {
        "attack_id": "mqtt-bruteforce",
        "arguments": ["10.0.0.5", "1883"],
        "container_exit_code": 0,
        "container_stderr": "",
    }


def test_record_iteration_uses_context_for_experiment_id_and_variant_label():
    recorder = MagicMock()
    context = RunContext(experiment_id="exp-1", variant_label="variant_2")
    tool = make_record_iteration(recorder, context)

    _call(
        tool,
        iteration=3,
        attack_id="mqtt-bruteforce",
        arguments=["10.0.0.5", "1883"],
        fired=True,
        evasion_rationale="ok",
        rule="alert ...",
        container_exit_code=0,
        container_stderr="",
    )

    recorder.record_execution.assert_called_once()
    kwargs = recorder.record_execution.call_args.kwargs
    assert kwargs["experiment_id"] == "exp-1"
    assert kwargs["iteration"] == 3
    assert kwargs["execution_type"] == "variant"
    assert kwargs["attack_id"] == "mqtt-bruteforce"
    assert kwargs["fired"] is True


def test_record_iteration_marks_base_execution_when_label_is_base():
    recorder = MagicMock()
    context = RunContext(experiment_id="exp-1", variant_label="base")
    tool = make_record_iteration(recorder, context)

    _call(
        tool,
        iteration=1,
        attack_id="x",
        arguments=["1"],
        fired=False,
        evasion_rationale="r",
        rule="alert ...",
    )

    assert recorder.record_execution.call_args.kwargs["execution_type"] == "base"


def test_trigger_attacker_calls_inner_agent_and_unpacks_result():
    attacker_agent = MagicMock()
    attacker_agent.run.return_value = AttackerResult(
        attack_id="mqtt-bruteforce",
        arguments=["172.17.0.2", "1883"],
        evasion_rationale="baseline",
        container_exit_code=0,
        container_stderr="",
    )
    context = RunContext(
        experiment_id="exp-1",
        variant_label="base",
        fixed_destination_ip="172.17.0.2",
        fixed_destination_port=1883,
        # SID has cleared the benign check, so the attack is allowed to run.
        benign_validated_sids={9000001},
    )
    tool = make_trigger_attacker(attacker_agent, context)

    result = _call(
        tool,
        intent="Detect MQTT",
        rule="alert ...",
        sid=9000001,
        request_variant=False,
        previous_attacks=[],
    )

    assert result["attack_id"] == "mqtt-bruteforce"
    assert result["arguments"] == ["172.17.0.2", "1883"]
    attacker_agent.run.assert_called_once()
    request = attacker_agent.run.call_args.args[0]
    assert request.intent == "Detect MQTT"
    assert request.request_variant is False
    # The fixed destination from RunContext must flow into the AttackerRequest.
    assert request.fixed_destination_ip == "172.17.0.2"
    assert request.fixed_destination_port == 1883


def test_trigger_attacker_refuses_sid_that_skipped_benign_check():
    attacker_agent = MagicMock()
    context = RunContext(
        experiment_id="exp-1",
        variant_label="base",
        fixed_destination_ip="172.17.0.2",
        fixed_destination_port=1883,
    )  # benign_validated_sids is empty — the benign check never ran for this SID.
    tool = make_trigger_attacker(attacker_agent, context)

    result = _call(
        tool,
        intent="Detect MQTT",
        rule="alert ...",
        sid=9000001,
        request_variant=False,
        previous_attacks=[],
    )

    assert result["error"] == "benign_check_required"
    # The attack agent must NOT have been invoked for an unvalidated rule.
    attacker_agent.run.assert_not_called()


def test_run_benign_traffic_validates_sid_on_clean_run():
    runner = MagicMock()
    runner.run.return_value = _benign_ok()
    monitor = MagicMock()
    monitor.check_fired.return_value = False  # rule stayed silent → no false positive
    context = RunContext(experiment_id="exp-1", fixed_destination_ip="172.17.0.2")
    tool = make_run_benign_traffic(runner, monitor, context)

    result = _call(tool, protocol="mqtt", sid=9000001, duration_seconds=5.0)

    assert result["false_positive"] is False
    assert 9000001 in context.benign_validated_sids
    monitor.clear_alert_log.assert_called_once()


def test_run_benign_traffic_does_not_validate_sid_on_false_positive():
    runner = MagicMock()
    runner.run.return_value = _benign_ok()
    monitor = MagicMock()
    monitor.check_fired.return_value = True  # rule fired on benign traffic
    context = RunContext(
        experiment_id="exp-1",
        fixed_destination_ip="172.17.0.2",
        benign_validated_sids={9000001},  # a stale pass that must be revoked
    )
    tool = make_run_benign_traffic(runner, monitor, context)

    result = _call(tool, protocol="mqtt", sid=9000001, duration_seconds=5.0)

    assert result["false_positive"] is True
    assert 9000001 not in context.benign_validated_sids

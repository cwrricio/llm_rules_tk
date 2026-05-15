"""Unit tests for the RulesAgent wrapper.

These tests do NOT make real LLM calls. The inner agno.Agent is patched after construction so
we can assert on what the wrapper feeds into the agent and how it processes the structured
output.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from rules_farmer.schemas import IterationResult


# Make sure agno does not refuse to instantiate the Claude model class for lack of API key.
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-test-dummy")


from unittest.mock import MagicMock  # noqa: E402

from rules_farmer.agents import RulesAgent  # noqa: E402
from rules_farmer.app_factory import _create_agno_model  # noqa: E402
from rules_farmer.config import AgentModelConfig  # noqa: E402


@dataclass
class _StubResponse:
    """Mimics agno's RunOutput just enough for our wrapper code."""

    content: Any


def _build_agent(stub_response: IterationResult, attacker_agent: Any | None = None) -> RulesAgent:
    model_cfg = AgentModelConfig(
        provider="anthropic",
        model="claude-sonnet-4-6",
        temperature=0.0,
        max_tokens=8192,
    )
    agent = RulesAgent(
        model=_create_agno_model(model_cfg),
        validator=MagicMock(),
        sid_manager=MagicMock(),
        injector=MagicMock(),
        monitor=MagicMock(),
        attacker_agent=attacker_agent or MagicMock(),
        recorder=MagicMock(),
        validated_rules_store=MagicMock(),
    )
    agent._agent = MagicMock()  # type: ignore[attr-defined]
    agent._agent.run.return_value = _StubResponse(content=stub_response)
    return agent


def test_rules_agent_returns_inner_iteration_result():
    expected = IterationResult(
        fired=True,
        final_rule='alert udp any any -> 172.17.0.2 8888 (msg:"Detect XRCE-DDS UDP DoS"; sid:9000001; rev:1;)',
        final_sid=9000001,
        rules_attempted=[
            'alert udp any any -> 172.17.0.2 8888 (msg:"Detect XRCE-DDS UDP DoS"; sid:0; rev:1;)',
        ],
        attack_id="xrce-dds-udp-dos",
        arguments=["172.17.0.2", "8888"],
        evasion_rationale="Baseline UDP flood",
    )
    agent = _build_agent(stub_response=expected)

    result = agent.run_iteration(
        intent="Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888",
        variant_label="base",
        previous_iterations=[],
        max_internal_attempts=3,
        experiment_id="exp-1",
    )

    assert result == expected
    agent._agent.run.assert_called_once()


def test_rules_agent_serializes_prompt_with_cycle_context():
    agent = _build_agent(
        stub_response=IterationResult(
            fired=True,
            final_rule="rule",
            final_sid=9000001,
            attack_id="xrce-dds-udp-dos",
            arguments=["172.17.0.2", "8888"],
            evasion_rationale="ok",
        )
    )

    agent.run_iteration(
        intent="Detect XRCE-DDS UDP DoS",
        variant_label="variant_2",
        previous_iterations=[
            IterationResult(
                fired=True,
                final_rule="prior-rule",
                final_sid=9000001,
                attack_id="xrce-dds-udp-dos",
                arguments=["172.17.0.2", "8888"],
                evasion_rationale="prev",
            )
        ],
        max_internal_attempts=5,
        experiment_id="exp-42",
        fixed_destination_ip="172.17.0.2",
        fixed_destination_port=8888,
    )

    raw_prompt = agent._agent.run.call_args.args[0]
    payload = json.loads(raw_prompt)
    assert payload["intent"] == "Detect XRCE-DDS UDP DoS"
    assert payload["variant_label"] == "variant_2"
    assert payload["request_variant"] is True
    assert payload["max_internal_attempts"] == 5
    assert payload["previous_attacks"] == [
        {"attack_id": "xrce-dds-udp-dos", "arguments": ["172.17.0.2", "8888"], "fired": True}
    ]
    assert payload["last_successful_rule"] == {"sid": 9000001, "rule": "prior-rule"}
    assert payload["fixed_destination"] == {"ip": "172.17.0.2", "port": 8888}


def test_rules_agent_updates_context_with_fixed_destination():
    agent = _build_agent(
        stub_response=IterationResult(
            fired=True,
            attack_id="x",
            arguments=["1"],
            evasion_rationale="r",
        )
    )

    agent.run_iteration(
        intent="Detect MQTT brute force",
        variant_label="base",
        previous_iterations=[],
        max_internal_attempts=1,
        experiment_id="exp-mqtt",
        fixed_destination_ip="172.17.0.2",
        fixed_destination_port=1883,
    )

    # The same context object is shared with trigger_attacker / record_iteration tools.
    assert agent._context.fixed_destination_ip == "172.17.0.2"
    assert agent._context.fixed_destination_port == 1883


def test_rules_agent_updates_run_context_before_each_call():
    agent = _build_agent(
        stub_response=IterationResult(
            fired=False,
            attack_id="x",
            arguments=["1"],
            evasion_rationale="r",
        )
    )

    agent.run_iteration(
        intent="Detect X",
        variant_label="base",
        previous_iterations=[],
        max_internal_attempts=1,
        experiment_id="exp-A",
    )
    # context is shared with the persistence skill — it must reflect the latest cycle
    assert agent._context.experiment_id == "exp-A"
    assert agent._context.variant_label == "base"

    agent.run_iteration(
        intent="Detect X",
        variant_label="variant_1",
        previous_iterations=[],
        max_internal_attempts=1,
        experiment_id="exp-B",
    )
    assert agent._context.experiment_id == "exp-B"
    assert agent._context.variant_label == "variant_1"


def test_rules_agent_has_expected_tools_and_skills():
    agent = _build_agent(
        stub_response=IterationResult(
            fired=False,
            attack_id="x",
            arguments=["1"],
            evasion_rationale="r",
        )
    )

    # Rebuild without mocking _agent so we can inspect the wired Agent.
    model_cfg = AgentModelConfig(
        provider="anthropic", model="claude-sonnet-4-6", temperature=0.0, max_tokens=8192
    )
    fresh = RulesAgent(
        model=_create_agno_model(model_cfg),
        validator=MagicMock(),
        sid_manager=MagicMock(),
        injector=MagicMock(),
        monitor=MagicMock(),
        attacker_agent=MagicMock(),
        recorder=MagicMock(),
        validated_rules_store=MagicMock(),
    )

    tool_names = [tool.name for tool in fresh._agent.tools]
    assert tool_names == [
        "validate_rule_syntax",
        "assign_sid",
        "deploy_rule",
        "trigger_attacker",
        "check_alert_fired",
        "record_iteration",
        "get_validated_rules",
    ]

    skill_names = set(fresh._agent.skills.get_skill_names())
    # Workflow skills (rules + shared).
    assert {
        "snort-rule-generation",
        "rule-validation-workflow",
        "rule-deployment",
        "alert-interpretation",
        "iteration-recording",
        "experiment-cycle",
    } <= skill_names
    # All 10 per-attack refinement playbooks must be loaded too.
    assert {
        "mqtt-bruteforce",
        "mqtt-lwt-abuse",
        "mqtt-publisher-flood",
        "mqtt-qos-amplification",
        "xrce-dds-entity-flood",
        "xrce-dds-fragment-abuse",
        "xrce-dds-malformed-inject",
        "xrce-dds-session-hijack",
        "xrce-dds-time-desync",
        "xrce-dds-udp-dos",
    } <= skill_names
    assert fresh._agent.output_schema is IterationResult

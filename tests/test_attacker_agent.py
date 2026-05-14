"""Unit tests for the AttackerAgent wrapper."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import pytest

from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.errors import UnmappedIntentError
from rules_farmer.schemas import AttackerRequest, AttackerResult


os.environ.setdefault("ANTHROPIC_API_KEY", "sk-test-dummy")


from unittest.mock import MagicMock  # noqa: E402

from rules_farmer.agents import AttackerAgent  # noqa: E402
from rules_farmer.app_factory import _create_agno_model  # noqa: E402
from rules_farmer.config import AgentModelConfig  # noqa: E402


@dataclass
class _StubResponse:
    content: Any


_MQTT_BRUTEFORCE = DiscoveredAttack(
    attack_id="mqtt-bruteforce",
    remote_path="/home/unipampa/ataques/attackers-claude/mqtt-bruteforce",
    description="MQTT credential brute force",
    docker_image="iotedu-attack-mqtt-bruteforce:latest",
    required_arguments=["target", "port"],
    readme_excerpt="Run MQTT brute force against <target> <port>.",
)


def _build_agent(stub_response: AttackerResult, attacks=None) -> AttackerAgent:
    model_cfg = AgentModelConfig(
        provider="anthropic", model="claude-sonnet-4-6", temperature=0.0, max_tokens=8192
    )
    agent = AttackerAgent(
        model=_create_agno_model(model_cfg),
        attacks=attacks if attacks is not None else [_MQTT_BRUTEFORCE],
        executor=MagicMock(),
    )
    agent._agent = MagicMock()  # type: ignore[attr-defined]
    agent._agent.run.return_value = _StubResponse(content=stub_response)
    return agent


def test_attacker_agent_returns_structured_result():
    expected = AttackerResult(
        attack_id="mqtt-bruteforce",
        arguments=["10.0.0.5", "1883"],
        evasion_rationale="Baseline MQTT brute force",
        container_exit_code=0,
    )
    agent = _build_agent(stub_response=expected)

    result = agent.run(
        AttackerRequest(
            intent="Detect MQTT brute force",
            rule='alert tcp any any -> any 1883 (msg:"x"; sid:9000001; rev:1;)',
            sid=9000001,
            request_variant=False,
        )
    )

    assert result == expected


def test_attacker_agent_raises_when_attack_id_is_unknown():
    bogus = AttackerResult(
        attack_id="ghost-attack",
        arguments=[],
        evasion_rationale="nonsense",
    )
    agent = _build_agent(stub_response=bogus)

    with pytest.raises(UnmappedIntentError) as exc:
        agent.run(
            AttackerRequest(
                intent="Detect MQTT",
                rule="r",
                sid=1,
                request_variant=False,
            )
        )

    assert "ghost-attack" in str(exc.value)
    assert "mqtt-bruteforce" in str(exc.value)


def test_attacker_agent_has_expected_tools_and_skills():
    model_cfg = AgentModelConfig(
        provider="anthropic", model="claude-sonnet-4-6", temperature=0.0, max_tokens=8192
    )
    fresh = AttackerAgent(
        model=_create_agno_model(model_cfg),
        attacks=[_MQTT_BRUTEFORCE],
        executor=MagicMock(),
    )

    tool_names = [tool.name for tool in fresh._agent.tools]
    assert tool_names == [
        "list_available_attacks",
        "read_attack_definition",
        "execute_attack",
    ]

    skill_names = set(fresh._agent.skills.get_skill_names())
    assert skill_names == {
        "attack-selection",
        "attack-execution",
        "evasion-variants",
        "experiment-cycle",
        "attack-destinations",
    }
    assert fresh._agent.output_schema is AttackerResult

"""Tests for the slim Orchestrator that drives the variant_count outer loop."""

from __future__ import annotations

import json
from typing import Iterable

import pytest

from rules_farmer.config import AttackDestination, AttackDestinationsConfig
from rules_farmer.experiment_recorder import ExperimentRecorder
from rules_farmer.orchestrator import Orchestrator
from rules_farmer.schemas import IterationResult


_DESTINATIONS = AttackDestinationsConfig(
    mqtt=AttackDestination(ip="172.17.0.2", port=1883),
    xrce=AttackDestination(ip="172.17.0.2", port=8888),
)


class FakeRulesAgent:
    """Returns canned IterationResults in order."""

    def __init__(self, results: Iterable[IterationResult]):
        self._results = list(results)
        self.calls: list[dict] = []

    def run_iteration(
        self,
        intent: str,
        variant_label: str,
        previous_iterations: list[IterationResult],
        max_internal_attempts: int,
        experiment_id: str,
        fixed_destination_ip: str | None = None,
        fixed_destination_port: int | None = None,
    ) -> IterationResult:
        self.calls.append(
            {
                "variant_label": variant_label,
                "previous_count": len(previous_iterations),
                "max_internal_attempts": max_internal_attempts,
                "experiment_id": experiment_id,
                "fixed_destination_ip": fixed_destination_ip,
                "fixed_destination_port": fixed_destination_port,
            }
        )
        return self._results.pop(0)


class RaisingRulesAgent:
    def __init__(self, exc: Exception):
        self._exc = exc

    def run_iteration(self, **kwargs):
        raise self._exc


def test_orchestrator_converges_when_every_variant_fires(tmp_path):
    output_dir = tmp_path / "results"
    recorder = ExperimentRecorder(output_dir=output_dir)

    results = [
        IterationResult(
            fired=True,
            final_rule="rule-A",
            final_sid=9000001,
            attack_id="x",
            arguments=["1"],
            evasion_rationale="baseline",
        ),
        IterationResult(
            fired=True,
            final_rule="rule-A",
            final_sid=9000001,
            attack_id="x",
            arguments=["2"],
            evasion_rationale="variant 1",
        ),
        IterationResult(
            fired=True,
            final_rule="rule-A",
            final_sid=9000001,
            attack_id="x",
            arguments=["3"],
            evasion_rationale="variant 2",
        ),
    ]
    rules_agent = FakeRulesAgent(results)
    orchestrator = Orchestrator(
        rules_agent=rules_agent,
        recorder=recorder,
        attack_destinations=_DESTINATIONS,
        experiment_id_factory=lambda: "exp-1",
    )

    result = orchestrator.run_experiment(
        intent="Detect X", max_iterations=5, variant_count=2
    )

    experiment = json.loads(result.json_path.read_text())
    assert result.status == "converged"
    assert experiment["status"] == "converged"
    assert [call["variant_label"] for call in rules_agent.calls] == [
        "base",
        "variant_1",
        "variant_2",
    ]


def test_orchestrator_fails_when_any_variant_does_not_fire(tmp_path):
    recorder = ExperimentRecorder(output_dir=tmp_path / "results")
    results = [
        IterationResult(
            fired=True,
            final_rule="rule",
            final_sid=9000001,
            attack_id="x",
            arguments=["1"],
            evasion_rationale="baseline",
        ),
        IterationResult(
            fired=False,
            attack_id="x",
            arguments=["2"],
            evasion_rationale="variant 1 evaded the rule",
            diagnosis="attempts-exhausted",
        ),
    ]
    orchestrator = Orchestrator(
        rules_agent=FakeRulesAgent(results),
        recorder=recorder,
        attack_destinations=_DESTINATIONS,
        experiment_id_factory=lambda: "exp-fail",
    )

    result = orchestrator.run_experiment(
        intent="Detect X", max_iterations=2, variant_count=2
    )

    experiment = json.loads(result.json_path.read_text())
    assert result.status == "failed"
    assert experiment["status"] == "failed"


def test_orchestrator_records_error_when_rules_agent_raises(tmp_path):
    recorder = ExperimentRecorder(output_dir=tmp_path / "results")
    orchestrator = Orchestrator(
        rules_agent=RaisingRulesAgent(RuntimeError("agno blew up")),
        recorder=recorder,
        attack_destinations=_DESTINATIONS,
        experiment_id_factory=lambda: "exp-error",
    )

    with pytest.raises(RuntimeError, match="agno blew up"):
        orchestrator.run_experiment(
            intent="Detect X", max_iterations=1, variant_count=0
        )

    experiment_path = tmp_path / "results" / "exp-error" / "experiment.json"
    experiment = json.loads(experiment_path.read_text())
    assert experiment["status"] == "error"
    assert experiment["error"] == {"type": "RuntimeError", "message": "agno blew up"}


def test_orchestrator_passes_previous_iterations_to_subsequent_cycles(tmp_path):
    recorder = ExperimentRecorder(output_dir=tmp_path / "results")
    results = [
        IterationResult(
            fired=True,
            final_rule="rule",
            final_sid=9000001,
            attack_id="x",
            arguments=["1"],
            evasion_rationale="baseline",
        ),
        IterationResult(
            fired=True,
            final_rule="rule",
            final_sid=9000001,
            attack_id="x",
            arguments=["2"],
            evasion_rationale="variant 1",
        ),
    ]
    rules_agent = FakeRulesAgent(results)
    orchestrator = Orchestrator(
        rules_agent=rules_agent,
        recorder=recorder,
        attack_destinations=_DESTINATIONS,
        experiment_id_factory=lambda: "exp-prev",
    )

    orchestrator.run_experiment(
        intent="Detect X", max_iterations=1, variant_count=1
    )

    assert rules_agent.calls[0]["previous_count"] == 0
    assert rules_agent.calls[1]["previous_count"] == 1


def test_orchestrator_forwards_mqtt_fixed_destination_to_rules_agent(tmp_path):
    recorder = ExperimentRecorder(output_dir=tmp_path / "results")
    rules_agent = FakeRulesAgent(
        [
            IterationResult(
                fired=True,
                final_rule="rule",
                final_sid=9000001,
                attack_id="mqtt-bruteforce",
                arguments=["172.17.0.2", "1883"],
                evasion_rationale="baseline",
            ),
        ]
    )
    orchestrator = Orchestrator(
        rules_agent=rules_agent,
        recorder=recorder,
        attack_destinations=_DESTINATIONS,
        experiment_id_factory=lambda: "exp-mqtt",
    )

    orchestrator.run_experiment(
        intent="Detect MQTT brute force", max_iterations=1, variant_count=0
    )

    assert rules_agent.calls[0]["fixed_destination_ip"] == "172.17.0.2"
    assert rules_agent.calls[0]["fixed_destination_port"] == 1883


def test_orchestrator_forwards_xrce_fixed_destination_to_rules_agent(tmp_path):
    recorder = ExperimentRecorder(output_dir=tmp_path / "results")
    rules_agent = FakeRulesAgent(
        [
            IterationResult(
                fired=True,
                final_rule="rule",
                final_sid=9000001,
                attack_id="xrce-dds-udp-dos",
                arguments=["172.17.0.2", "8888"],
                evasion_rationale="baseline",
            ),
        ]
    )
    orchestrator = Orchestrator(
        rules_agent=rules_agent,
        recorder=recorder,
        attack_destinations=_DESTINATIONS,
        experiment_id_factory=lambda: "exp-xrce",
    )

    orchestrator.run_experiment(
        intent="Detect XRCE-DDS UDP DoS", max_iterations=1, variant_count=0
    )

    assert rules_agent.calls[0]["fixed_destination_port"] == 8888


def test_orchestrator_passes_none_when_intent_does_not_match_known_family(tmp_path):
    recorder = ExperimentRecorder(output_dir=tmp_path / "results")
    rules_agent = FakeRulesAgent(
        [
            IterationResult(
                fired=True,
                final_rule="rule",
                final_sid=9000001,
                attack_id="x",
                arguments=["1"],
                evasion_rationale="baseline",
            ),
        ]
    )
    orchestrator = Orchestrator(
        rules_agent=rules_agent,
        recorder=recorder,
        attack_destinations=_DESTINATIONS,
        experiment_id_factory=lambda: "exp-unknown",
    )

    orchestrator.run_experiment(
        intent="Detect generic HTTP scanning", max_iterations=1, variant_count=0
    )

    assert rules_agent.calls[0]["fixed_destination_ip"] is None
    assert rules_agent.calls[0]["fixed_destination_port"] is None

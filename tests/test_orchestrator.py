import json
from pathlib import Path

import pytest

from rules_farmer.attack_executor import ExecutionResult
from rules_farmer.experiment_recorder import ExperimentRecorder
from rules_farmer.ids_rule_validator import ValidationResult
from rules_farmer.orchestrator import Orchestrator
from rules_farmer.schemas import AttackPlan, RuleAgentOutput
from rules_farmer.sid_manager import AssignedRule


class FakeRuleAgent:
    def run(self, intent, previous_rules=None, feedback=None):
        return RuleAgentOutput(
            rules=['alert tcp any any -> any 1883 (msg:"Detect MQTT"; sid:0; rev:1;)'],
            diagnosis=None,
        )


class FailingRuleAgent:
    def run(self, intent, previous_rules=None, feedback=None):
        raise RuntimeError("model not found")


class FakeValidator:
    def validate(self, rule):
        return ValidationResult(valid=True, error=None)


class FakeSIDManager:
    def assign_sids(self, intent, rules):
        return [
            AssignedRule(
                sid=9000001,
                rule=rules[0].replace("sid:0;", "sid:9000001;"),
            )
        ]


class FakeInjector:
    def __init__(self):
        self.injected = []

    def inject(self, rules):
        self.injected.append(rules)


class FakeAttackerAgent:
    def __init__(self):
        self.calls = 0

    def run(self, request):
        self.calls += 1
        return AttackPlan(
            attack_id="mqtt-bruteforce",
            arguments=["10.0.0.5", "1883" if self.calls == 1 else "1884"],
            evasion_rationale="Try MQTT brute force traffic",
        )


class FakeAttackExecutor:
    def __init__(self, pcap_dir):
        self.pcap_dir = Path(pcap_dir)

    def execute(self, attack_id, arguments):
        local_path = self.pcap_dir / f"{attack_id}-{arguments[1]}.pcap"
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(b"pcap")
        return ExecutionResult(
            exit_code=0,
            stdout_json={"pcap_path": "/tmp/attack.pcap"},
            pcap_local_path=local_path,
            pcap_summary="packet summary",
            container_exit_code=0,
            container_stderr="",
        )


class FakeMonitor:
    def __init__(self, fired_results):
        self.fired_results = list(fired_results)

    def check_fired(self, sid):
        return self.fired_results.pop(0)


def test_orchestrator_converges_when_base_and_all_variants_fire(tmp_path):
    injector = FakeInjector()
    recorder = ExperimentRecorder(output_dir=tmp_path / "results")
    orchestrator = Orchestrator(
        rule_agent=FakeRuleAgent(),
        validator=FakeValidator(),
        sid_manager=FakeSIDManager(),
        injector=injector,
        attacker_agent=FakeAttackerAgent(),
        attack_executor=FakeAttackExecutor(tmp_path / "results" / "pcaps"),
        monitor=FakeMonitor([True, True]),
        recorder=recorder,
        experiment_id_factory=lambda: "exp-1",
    )

    result = orchestrator.run_experiment(
        intent="Detect MQTT",
        max_iterations=1,
        variant_count=1,
    )

    experiment = json.loads(result.json_path.read_text())
    assert result.status == "converged"
    assert experiment["status"] == "converged"
    assert [row["execution_type"] for row in experiment["executions"]] == [
        "base",
        "variant",
    ]
    assert injector.injected == [
        ['alert tcp any any -> any 1883 (msg:"Detect MQTT"; sid:9000001; rev:1;)']
    ]


def test_orchestrator_marks_experiment_error_when_rule_generation_raises(tmp_path):
    recorder = ExperimentRecorder(output_dir=tmp_path / "results")
    orchestrator = Orchestrator(
        rule_agent=FailingRuleAgent(),
        validator=FakeValidator(),
        sid_manager=FakeSIDManager(),
        injector=FakeInjector(),
        attacker_agent=FakeAttackerAgent(),
        attack_executor=FakeAttackExecutor(tmp_path / "results" / "pcaps"),
        monitor=FakeMonitor([]),
        recorder=recorder,
        experiment_id_factory=lambda: "exp-error",
    )

    with pytest.raises(RuntimeError, match="model not found"):
        orchestrator.run_experiment(
            intent="Detect XRCE-DDS",
            max_iterations=1,
            variant_count=1,
        )

    experiment_path = tmp_path / "results" / "exp-error" / "experiment.json"
    experiment = json.loads(experiment_path.read_text())
    assert experiment["status"] == "error"
    assert experiment["error"] == {
        "type": "RuntimeError",
        "message": "model not found",
    }

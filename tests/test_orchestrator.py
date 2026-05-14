import json
from pathlib import Path

import pytest

from rules_farmer.attack_executor import ExecutionResult
from rules_farmer.experiment_recorder import ExperimentRecorder
from rules_farmer.ids_rule_validator import ValidationResult
from rules_farmer.llm_client import LLMClientError
from rules_farmer.orchestrator import Orchestrator
from rules_farmer.schemas import AttackPlan, FeedbackPayload, RuleAgentOutput
from rules_farmer.sid_manager import AssignedRule


class FakeRuleAgent:
    def __init__(self):
        self.received_feedbacks = []

    def run(self, intent, previous_rules=None, feedback=None):
        self.received_feedbacks.append(feedback)
        return RuleAgentOutput(
            rules=['alert tcp any any -> any 1883 (msg:"Detect MQTT"; sid:0; rev:1;)'],
            diagnosis=None,
        )


class FailingRuleAgent:
    def run(self, intent, previous_rules=None, feedback=None):
        raise RuntimeError("model not found")


class LLMErrorRuleAgent:
    def __init__(self, fail_on_iteration: int, good_output: RuleAgentOutput):
        self.call_count = 0
        self.fail_on_iteration = fail_on_iteration
        self.good_output = good_output

    def run(self, intent, previous_rules=None, feedback=None):
        self.call_count += 1
        if self.call_count == self.fail_on_iteration:
            raise LLMClientError("empty response from model")
        return self.good_output


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


def test_orchestrator_continues_when_llm_returns_empty_on_one_iteration(tmp_path):
    good_output = RuleAgentOutput(
        rules=['alert tcp any any -> any 1883 (msg:"Detect MQTT"; sid:0; rev:1;)'],
        diagnosis=None,
    )
    injector = FakeInjector()
    recorder = ExperimentRecorder(output_dir=tmp_path / "results")
    orchestrator = Orchestrator(
        rule_agent=LLMErrorRuleAgent(fail_on_iteration=1, good_output=good_output),
        validator=FakeValidator(),
        sid_manager=FakeSIDManager(),
        injector=injector,
        attacker_agent=FakeAttackerAgent(),
        attack_executor=FakeAttackExecutor(tmp_path / "results" / "pcaps"),
        monitor=FakeMonitor([True, True]),
        recorder=recorder,
        experiment_id_factory=lambda: "exp-llm-err",
    )

    result = orchestrator.run_experiment(
        intent="Detect MQTT",
        max_iterations=2,
        variant_count=1,
    )

    assert result.status == "converged"


class RejectingValidator:
    def __init__(self, error_msg: str):
        self.error_msg = error_msg
        self.received_rules = []

    def validate(self, rule):
        self.received_rules.append(rule)
        return ValidationResult(valid=False, error=self.error_msg)


class CapturingRuleAgent:
    def __init__(self, output: RuleAgentOutput):
        self.output = output
        self.received_feedbacks = []

    def run(self, intent, previous_rules=None, feedback=None):
        self.received_feedbacks.append(feedback)
        return self.output


def test_orchestrator_passes_snort_error_in_feedback_when_validation_fails(tmp_path):
    snort_error = "flow:stateless cannot be combined with other flow options in Snort 3"
    rule_agent = CapturingRuleAgent(
        RuleAgentOutput(
            rules=['alert udp any any -> any any (msg:"X"; sid:0; rev:1;)'],
            diagnosis=None,
        )
    )
    recorder = ExperimentRecorder(output_dir=tmp_path / "results")
    orchestrator = Orchestrator(
        rule_agent=rule_agent,
        validator=RejectingValidator(snort_error),
        sid_manager=FakeSIDManager(),
        injector=FakeInjector(),
        attacker_agent=FakeAttackerAgent(),
        attack_executor=FakeAttackExecutor(tmp_path / "results" / "pcaps"),
        monitor=FakeMonitor([]),
        recorder=recorder,
        experiment_id_factory=lambda: "exp-val-err",
    )

    result = orchestrator.run_experiment(
        intent="Detect XRCE-DDS",
        max_iterations=2,
        variant_count=1,
    )

    assert result.status == "failed"
    # Second call must have received the Snort error in validation_error field
    second_feedback: FeedbackPayload = rule_agent.received_feedbacks[1]
    assert second_feedback is not None
    assert second_feedback.validation_error == snort_error

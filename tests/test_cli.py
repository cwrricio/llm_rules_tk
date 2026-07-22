from pathlib import Path
from types import SimpleNamespace

from rules_farmer.cli import main, run_terminal_prompt
from rules_farmer.orchestrator import ExperimentRunResult


class FakeOrchestrator:
    def __init__(self):
        self.calls = []

    def run_experiment(
        self, intent, max_iterations, variant_count, convergence_threshold=None
    ):
        self.calls.append(
            {
                "intent": intent,
                "max_iterations": max_iterations,
                "variant_count": variant_count,
            }
        )
        return ExperimentRunResult(
            status="converged",
            experiment_id="exp-1",
            json_path=Path("/tmp/results/exp-1/experiment.json"),
            csv_path=Path("/tmp/results/exp-1/metrics.csv"),
        )


def test_terminal_prompt_waits_for_textual_intent_and_runs_experiment():
    orchestrator = FakeOrchestrator()
    output = []

    result = run_terminal_prompt(
        orchestrator=orchestrator,
        default_max_iterations=5,
        default_variant_count=3,
        input_func=lambda prompt: "Detect XRCE-DDS UDP DoS",
        output_func=output.append,
    )

    assert result.status == "converged"
    assert orchestrator.calls == [
        {
            "intent": "Detect XRCE-DDS UDP DoS",
            "max_iterations": 5,
            "variant_count": 3,
        }
    ]
    assert output == [
        "Running experiment for: Detect XRCE-DDS UDP DoS",
        "Status: converged",
        f"JSON: {Path('/tmp/results/exp-1/experiment.json')}",
        f"CSV: {Path('/tmp/results/exp-1/metrics.csv')}",
    ]


def test_main_reads_intent_before_building_runtime():
    events = []
    orchestrator = FakeOrchestrator()
    config = SimpleNamespace(
        experiment_defaults=SimpleNamespace(
            max_iterations=5, variant_count=3, convergence_threshold=5
        )
    )
    runtime = SimpleNamespace(orchestrator=orchestrator)

    def fake_input(prompt):
        events.append("input")
        return "Detect MQTT flood"

    def fake_build_runtime(config_path):
        events.append("build_runtime")
        return runtime

    main(
        config_path="config.yaml",
        input_func=fake_input,
        output_func=lambda message: None,
        config_loader=lambda config_path: config,
        runtime_builder=fake_build_runtime,
        log_path="/tmp/rules-farmer-test-output.log",
    )

    assert events == ["input", "build_runtime"]
    assert orchestrator.calls[0]["intent"] == "Detect MQTT flood"


def test_main_writes_realtime_trace_to_output_log(tmp_path):
    orchestrator = FakeOrchestrator()
    config = SimpleNamespace(
        experiment_defaults=SimpleNamespace(
            max_iterations=5, variant_count=3, convergence_threshold=5
        )
    )
    runtime = SimpleNamespace(orchestrator=orchestrator)
    log_path = tmp_path / "output.log"

    main(
        config_path="config.yaml",
        input_func=lambda prompt: "Detect XRCE",
        config_loader=lambda config_path: config,
        runtime_builder=lambda config_path: runtime,
        log_path=log_path,
    )

    log_text = log_path.read_text(encoding="utf-8")
    assert "Execution logging started" in log_text
    assert "<------------- INTENCAO RECEBIDA ------------->" in log_text
    assert "<------------- MONTANDO RUNTIME ------------->" in log_text
    assert "<------------- INICIANDO EXPERIMENTO ------------->" in log_text
    assert "<------------- EXECUCAO FINALIZADA ------------->" in log_text
    assert "Experiment finished status=converged experiment_id=exp-1" in log_text

import csv
import json

from rules_farmer.experiment_recorder import ExperimentIDFactory, ExperimentRecorder


def test_recorder_writes_experiment_json_and_metrics_csv(tmp_path):
    recorder = ExperimentRecorder(output_dir=tmp_path)

    recorder.initialize_experiment("exp-1", "Detect MQTT brute force attempts")
    recorder.record_execution(
        experiment_id="exp-1",
        iteration=1,
        execution_type="base",
        attack_id="mqtt-bruteforce",
        arguments=["10.0.0.5", "1883"],
        fired=False,
        evasion_rationale="Baseline attack should match the generated rule",
        pcap_filename="iter1_base.pcap",
    )
    artifacts = recorder.finalize("exp-1", converged=False)

    experiment = json.loads(artifacts.json_path.read_text())
    assert experiment["experiment_id"] == "exp-1"
    assert experiment["intent"] == "Detect MQTT brute force attempts"
    assert experiment["status"] == "failed"
    assert experiment["executions"] == [
        {
            "iteration": 1,
            "execution_type": "base",
            "attacker": {
                "attack_id": "mqtt-bruteforce",
                "arguments": ["10.0.0.5", "1883"],
                "evasion_rationale": "Baseline attack should match the generated rule",
                "container_exit_code": None,
                "container_stderr": "",
            },
            "victim": {
                "rule": "",
                "fired": False,
            },
            "pcap_path": "pcaps/iter1_base.pcap",
        }
    ]

    with artifacts.csv_path.open(newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert rows == [
        {
            "iteration": "1",
            "execution_type": "base",
            "attack_id": "mqtt-bruteforce",
            "arguments": '["10.0.0.5","1883"]',
            "container_exit_code": "",
            "fired": "false",
            "evasion_rationale": "Baseline attack should match the generated rule",
            "rule": "",
        }
    ]


def test_experiment_id_factory_produces_sequential_zero_padded_ids(tmp_path):
    factory = ExperimentIDFactory(tmp_path / "experiment_counter.json")

    assert factory() == "0001"
    assert factory() == "0002"
    assert factory() == "0003"


def test_experiment_id_factory_resumes_from_existing_counter(tmp_path):
    counter_path = tmp_path / "experiment_counter.json"
    counter_path.write_text('{"counter": 41}', encoding="utf-8")
    factory = ExperimentIDFactory(counter_path)

    assert factory() == "0042"


def test_recorder_marks_experiment_error_and_writes_metrics_header(tmp_path):
    recorder = ExperimentRecorder(output_dir=tmp_path)

    recorder.initialize_experiment("exp-error", "Detect XRCE-DDS")
    artifacts = recorder.finalize_error("exp-error", RuntimeError("model not found"))

    experiment = json.loads(artifacts.json_path.read_text())
    assert experiment["status"] == "error"
    assert experiment["error"] == {
        "type": "RuntimeError",
        "message": "model not found",
    }

    with artifacts.csv_path.open(newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert rows == []

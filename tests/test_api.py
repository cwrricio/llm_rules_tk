from pathlib import Path

from fastapi.testclient import TestClient

from rules_farmer.api import create_app
from rules_farmer.orchestrator import ExperimentRunResult


class FakeOrchestrator:
    def __init__(self):
        self.calls = []

    def run_experiment(self, intent, max_iterations, variant_count, experiment_id=None):
        self.calls.append(
            {
                "intent": intent,
                "max_iterations": max_iterations,
                "variant_count": variant_count,
                "experiment_id": experiment_id,
            }
        )
        return ExperimentRunResult(
            status="converged",
            experiment_id=experiment_id,
            json_path=Path("/tmp/results/exp-1/experiment.json"),
            csv_path=Path("/tmp/results/exp-1/metrics.csv"),
        )


def test_post_experiments_starts_background_run_and_get_returns_result():
    orchestrator = FakeOrchestrator()
    app = create_app(
        orchestrator=orchestrator,
        default_max_iterations=5,
        default_variant_count=3,
        experiment_id_factory=lambda: "exp-1",
    )
    client = TestClient(app)

    response = client.post("/experiments", json={"intent": "Detect MQTT"})

    assert response.status_code == 200
    assert response.json() == {"experiment_id": "exp-1"}
    assert orchestrator.calls == [
        {
            "intent": "Detect MQTT",
            "max_iterations": 5,
            "variant_count": 3,
            "experiment_id": "exp-1",
        }
    ]
    assert client.get("/experiments/exp-1").json() == {
        "status": "converged",
        "result": {
            "json_path": "/tmp/results/exp-1/experiment.json",
            "csv_path": "/tmp/results/exp-1/metrics.csv",
        },
    }


def test_get_experiment_returns_404_for_unknown_id():
    app = create_app(orchestrator=FakeOrchestrator())
    client = TestClient(app)

    response = client.get("/experiments/missing")

    assert response.status_code == 404

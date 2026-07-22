from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import FastAPI

from rules_farmer.api import create_app
from rules_farmer.config import load_config
from rules_farmer.orchestrator import ExperimentRunResult


class DevOrchestrator:
    def run_experiment(
        self,
        intent: str,
        max_iterations: int,
        variant_count: int,
        experiment_id: str | None = None,
        convergence_threshold: int | None = None,
    ) -> ExperimentRunResult:
        experiment_id = experiment_id or str(uuid.uuid4())
        return ExperimentRunResult(
            status="converged",
            experiment_id=experiment_id,
            json_path=Path(f"/tmp/rules-farmer/{experiment_id}/experiment.json"),
            csv_path=Path(f"/tmp/rules-farmer/{experiment_id}/metrics.csv"),
        )


def create_dev_app(config_path: str = "config.yaml") -> FastAPI:
    """Dev-only app factory.

    This starts the FastAPI service without requiring SSH/Docker testbed wiring.
    The orchestrator is a stub that immediately returns a converged result.
    """

    config = load_config(config_path)
    return create_app(
        orchestrator=DevOrchestrator(),
        default_max_iterations=config.experiment_defaults.max_iterations,
        default_variant_count=config.experiment_defaults.variant_count,
    )

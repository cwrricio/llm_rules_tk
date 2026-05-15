from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Callable

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator


logger = logging.getLogger(__name__)


class ExperimentRequest(BaseModel):
    intent: str = Field(min_length=1)
    max_iterations: int | None = None
    variant_count: int | None = None
    convergence_threshold: int | None = None

    @field_validator("intent")
    @classmethod
    def intent_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("intent must not be blank")
        return value


def create_app(
    orchestrator,
    default_max_iterations: int = 5,
    default_variant_count: int = 3,
    experiment_id_factory: Callable[[], str] | None = None,
) -> FastAPI:
    app = FastAPI(title="Rules Farmer")
    make_experiment_id = experiment_id_factory or (lambda: str(uuid.uuid4()))
    experiments: dict[str, dict[str, object]] = {}

    @app.post("/experiments")
    def create_experiment(
        request: ExperimentRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, str]:
        experiment_id = make_experiment_id()
        logger.info(
            "API experiment accepted experiment_id=%s max_iterations=%s variant_count=%s",
            experiment_id,
            request.max_iterations or default_max_iterations,
            request.variant_count or default_variant_count,
        )
        experiments[experiment_id] = {"status": "running"}
        background_tasks.add_task(
            _run_experiment,
            orchestrator,
            experiments,
            experiment_id,
            request.intent,
            request.max_iterations or default_max_iterations,
            request.variant_count or default_variant_count,
            request.convergence_threshold,
        )
        return {"experiment_id": experiment_id}

    @app.get("/experiments/{experiment_id}")
    def get_experiment(experiment_id: str) -> dict[str, object]:
        logger.info("API experiment status requested experiment_id=%s", experiment_id)
        experiment = experiments.get(experiment_id)
        if experiment is None:
            raise HTTPException(status_code=404, detail="experiment not found")
        if experiment["status"] == "running":
            return {"status": "running"}
        return experiment

    return app


def _run_experiment(
    orchestrator,
    experiments: dict[str, dict[str, object]],
    experiment_id: str,
    intent: str,
    max_iterations: int,
    variant_count: int,
    convergence_threshold: int | None = None,
) -> None:
    try:
        logger.info("API background experiment started experiment_id=%s", experiment_id)
        result = orchestrator.run_experiment(
            intent=intent,
            max_iterations=max_iterations,
            variant_count=variant_count,
            experiment_id=experiment_id,
            convergence_threshold=convergence_threshold,
        )
        experiments[experiment_id] = {
            "status": result.status,
            "result": {
                "json_path": _path_to_api_string(result.json_path),
                "csv_path": _path_to_api_string(result.csv_path),
            },
        }
        logger.info(
            "API background experiment finished experiment_id=%s status=%s",
            experiment_id,
            result.status,
        )
    except Exception as exc:
        logger.exception("API background experiment stopped due to error experiment_id=%s", experiment_id)
        experiments[experiment_id] = {
            "status": "error",
            "error": str(exc),
        }


def _path_to_api_string(path: str | Path) -> str:
    return str(path)

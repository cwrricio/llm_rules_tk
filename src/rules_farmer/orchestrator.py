from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from rules_farmer.agents import RulesAgent
from rules_farmer.config import AttackDestinationsConfig
from rules_farmer.experiment_recorder import ExperimentRecorder
from rules_farmer.execution_logging import log_stage
from rules_farmer.intent_preprocessor import FixedDestination, resolve_fixed_destination
from rules_farmer.schemas import IterationResult


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExperimentRunResult:
    status: str
    experiment_id: str
    json_path: Path
    csv_path: Path


class Orchestrator:
    def __init__(
        self,
        rules_agent: RulesAgent,
        recorder: ExperimentRecorder,
        attack_destinations: AttackDestinationsConfig,
        experiment_id_factory: Callable[[], str] | None = None,
        continue_on_failure: bool = False,
    ):
        self.rules_agent = rules_agent
        self.recorder = recorder
        self.attack_destinations = attack_destinations
        self.experiment_id_factory = experiment_id_factory or (lambda: str(uuid.uuid4()))
        self.continue_on_failure = continue_on_failure

    def run_experiment(
        self,
        intent: str,
        max_iterations: int,
        variant_count: int,
        experiment_id: str | None = None,
    ) -> ExperimentRunResult:
        experiment_id = experiment_id or self.experiment_id_factory()
        fixed = resolve_fixed_destination(intent, self.attack_destinations)
        log_stage("EXPERIMENTO INICIADO")
        logger.info(
            "Experiment started experiment_id=%s max_iterations=%s variant_count=%s intent=%r fixed_destination=%s",
            experiment_id,
            max_iterations,
            variant_count,
            intent,
            _fmt_destination(fixed),
        )
        self.recorder.initialize_experiment(experiment_id, intent)

        previous_iterations: list[IterationResult] = []
        any_failed = False
        try:
            for variant_index in range(variant_count + 1):
                label = "base" if variant_index == 0 else f"variant_{variant_index}"
                log_stage(f"AGORA ESTA RODANDO {label.upper()}")
                logger.info(
                    "Variant cycle started experiment_id=%s variant_index=%s label=%s",
                    experiment_id,
                    variant_index,
                    label,
                )
                result = self.rules_agent.run_iteration(
                    intent=intent,
                    variant_label=label,
                    previous_iterations=previous_iterations,
                    max_internal_attempts=max_iterations,
                    experiment_id=experiment_id,
                    fixed_destination_ip=fixed.ip if fixed else None,
                    fixed_destination_port=fixed.port if fixed else None,
                )
                previous_iterations.append(result)
                if not result.fired:
                    any_failed = True
                    log_stage(f"VARIANTE {label.upper()} NAO DETECTADA")
                    if not self.continue_on_failure:
                        log_stage("EXPERIMENTO FALHOU - PARANDO")
                        return self._finalize(experiment_id, converged=False, status="failed")
                    logger.info(
                        "continue_on_failure=True - prosseguindo para proximo ciclo apesar da falha"
                    )

            if any_failed:
                log_stage("EXPERIMENTO FINALIZOU COM FALHAS PARCIAIS")
                return self._finalize(experiment_id, converged=False, status="partial")
            log_stage("EXPERIMENTO CONVERGIU")
            return self._finalize(experiment_id, converged=True, status="converged")
        except Exception as exc:
            log_stage("EXPERIMENTO PAROU COM ERRO")
            logger.exception("Experiment stopped due to error experiment_id=%s", experiment_id)
            self.recorder.finalize_error(experiment_id, exc)
            raise

    def _finalize(self, experiment_id: str, converged: bool, status: str) -> ExperimentRunResult:
        artifacts = self.recorder.finalize(experiment_id, converged=converged)
        logger.info(
            "Experiment finalized experiment_id=%s status=%s json_path=%s csv_path=%s",
            experiment_id,
            status,
            artifacts.json_path,
            artifacts.csv_path,
        )
        return ExperimentRunResult(
            status=status,
            experiment_id=experiment_id,
            json_path=artifacts.json_path,
            csv_path=artifacts.csv_path,
        )


def _fmt_destination(fixed: FixedDestination | None) -> str:
    if fixed is None:
        return "unresolved"
    return f"{fixed.family}://{fixed.ip}:{fixed.port}"

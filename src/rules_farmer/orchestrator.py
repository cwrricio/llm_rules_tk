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
from rules_farmer.validated_rules import ValidatedRulesStore


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
        validated_rules_store: ValidatedRulesStore | None = None,
    ):
        self.rules_agent = rules_agent
        self.recorder = recorder
        self.attack_destinations = attack_destinations
        self.experiment_id_factory = experiment_id_factory or (lambda: str(uuid.uuid4()))
        self.continue_on_failure = continue_on_failure
        self.validated_rules_store = validated_rules_store

    def run_experiment(
        self,
        intent: str,
        max_iterations: int,
        variant_count: int,
        experiment_id: str | None = None,
        convergence_threshold: int | None = None,
    ) -> ExperimentRunResult:
        experiment_id = experiment_id or self.experiment_id_factory()
        fixed = resolve_fixed_destination(intent, self.attack_destinations)
        log_stage("EXPERIMENTO INICIADO")
        logger.info(
            "Experiment started experiment_id=%s max_iterations=%s variant_count=%s "
            "convergence_threshold=%s intent=%r fixed_destination=%s",
            experiment_id,
            max_iterations,
            variant_count,
            convergence_threshold,
            intent,
            _fmt_destination(fixed),
        )
        self.recorder.initialize_experiment(experiment_id, intent)

        previous_iterations: list[IterationResult] = []
        any_failed = False
        consecutive_detections = 0
        active_rule: str | None = None
        active_sid: int | None = None
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

                previous_attacks = [
                    {"attack_id": p.attack_id, "arguments": p.arguments, "fired": p.fired}
                    for p in previous_iterations
                    if p.attack_id
                ]

                if variant_index > 0 and active_rule is not None and active_sid is not None:
                    # Rule already deployed and fired — vary the attack without LLM rule generation.
                    # This is what variant_count controls: how many times the attack varies
                    # when the rule detects it.
                    result = self.rules_agent.run_variant_attack(
                        intent=intent,
                        variant_label=label,
                        active_sid=active_sid,
                        active_rule=active_rule,
                        previous_attacks=previous_attacks,
                        experiment_id=experiment_id,
                        fixed_destination_ip=fixed.ip if fixed else None,
                        fixed_destination_port=fixed.port if fixed else None,
                    )
                else:
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
                if result.fired:
                    if result.final_rule and result.final_sid is not None:
                        active_rule = result.final_rule
                        active_sid = result.final_sid
                    if variant_index > 0:
                        consecutive_detections += 1
                        logger.info(
                            "Variant detected experiment_id=%s label=%s consecutive=%s threshold=%s",
                            experiment_id,
                            label,
                            consecutive_detections,
                            convergence_threshold,
                        )
                        if (
                            convergence_threshold is not None
                            and consecutive_detections >= convergence_threshold
                        ):
                            log_stage("EXPERIMENTO CONVERGIU ANTECIPADAMENTE")
                            logger.info(
                                "Early convergence reached experiment_id=%s after %s consecutive detections",
                                experiment_id,
                                consecutive_detections,
                            )
                            return self._finalize(experiment_id, converged=True, status="converged")
                else:
                    consecutive_detections = 0
                    active_rule = None
                    active_sid = None
                    any_failed = True
                    log_stage(f"VARIANTE {label.upper()} NAO DETECTADA")
                    logger.info(
                        "Rule evaded — resetting consecutive_detections and forcing rule regeneration "
                        "on next cycle experiment_id=%s label=%s",
                        experiment_id,
                        label,
                    )
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
        if self.validated_rules_store is not None:
            try:
                out_dir = artifacts.json_path.parent / "validated_rules"
                written = self.validated_rules_store.export_per_attack(out_dir)
                logger.info(
                    "Per-attack rules exported experiment_id=%s families=%s",
                    experiment_id,
                    list(written),
                )
            except Exception:
                logger.exception(
                    "Failed to export per-attack validated rules experiment_id=%s", experiment_id
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

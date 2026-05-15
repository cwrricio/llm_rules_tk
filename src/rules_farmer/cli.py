from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from rules_farmer.app_factory import build_runtime
from rules_farmer.config import load_config
from rules_farmer.execution_logging import configure_execution_logging, log_stage
from rules_farmer.orchestrator import ExperimentRunResult


logger = logging.getLogger(__name__)


def run_terminal_prompt(
    orchestrator,
    default_max_iterations: int,
    default_variant_count: int,
    input_func: Callable[[str], str] = input,
    output_func: Callable[[str], None] = print,
) -> ExperimentRunResult:
    intent = input_func("Intent: ").strip()
    if not intent:
        raise ValueError("Intent cannot be empty.")

    output_func(f"Running experiment for: {intent}")
    result = orchestrator.run_experiment(
        intent=intent,
        max_iterations=default_max_iterations,
        variant_count=default_variant_count,
    )
    output_func(f"Status: {result.status}")
    output_func(f"JSON: {result.json_path}")
    output_func(f"CSV: {result.csv_path}")
    return result


def main(
    config_path: str = "config.yaml",
    input_func: Callable[[str], str] = input,
    output_func: Callable[[str], None] | None = None,
    config_loader=load_config,
    runtime_builder=build_runtime,
    log_path: str | Path = "output.log",
) -> None:
    configure_execution_logging(log_path)
    try:
        log_stage("CARREGANDO CONFIGURACAO")
        logger.debug("Loading configuration config_path=%s", config_path)
        config = config_loader(config_path)
        intent = input_func("Intent: ").strip()
        if not intent:
            raise ValueError("Intent cannot be empty.")

        log_stage("INTENCAO RECEBIDA")
        if output_func is not None:
            _progress(output_func, "Intent received")
        logger.debug("CLI intent received intent=%r", intent)
        log_stage("MONTANDO RUNTIME")
        logger.debug("Building runtime after intent input")
        runtime = runtime_builder(config_path)
        log_stage("INICIANDO EXPERIMENTO")
        _progress(output_func, f"Running experiment for: {intent}")
        result = runtime.orchestrator.run_experiment(
            intent=intent,
            max_iterations=config.experiment_defaults.max_iterations,
            variant_count=config.experiment_defaults.variant_count,
            convergence_threshold=config.experiment_defaults.convergence_threshold,
        )
        _progress(output_func, f"Status: {result.status}")
        _progress(output_func, f"JSON: {result.json_path}")
        _progress(output_func, f"CSV: {result.csv_path}")
        log_stage("EXECUCAO FINALIZADA")
        logger.info(
            "Experiment finished status=%s experiment_id=%s json_path=%s csv_path=%s",
            result.status,
            result.experiment_id,
            result.json_path,
            result.csv_path,
        )
    except Exception:
        log_stage("EXECUCAO PAROU COM ERRO")
        logger.exception("Execution stopped due to error")
        raise


def _progress(output_func: Callable[[str], None] | None, message: str) -> None:
    if output_func is None:
        logger.info(message)
    else:
        output_func(message)

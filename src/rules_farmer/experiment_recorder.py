from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


ExecutionType = Literal["base", "variant"]


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExperimentArtifacts:
    json_path: Path
    csv_path: Path


class ExperimentRecorder:
    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)

    def initialize_experiment(self, experiment_id: str, intent: str) -> None:
        experiment_dir = self._experiment_dir(experiment_id)
        logger.info("Experiment record initialized experiment_id=%s dir=%s", experiment_id, experiment_dir)
        (experiment_dir / "pcaps").mkdir(parents=True, exist_ok=True)
        self._write_experiment(
            experiment_id,
            {
                "experiment_id": experiment_id,
                "intent": intent,
                "status": "running",
                "executions": [],
            },
        )

    def record_execution(
        self,
        experiment_id: str,
        iteration: int,
        execution_type: ExecutionType,
        attack_id: str,
        arguments: list[str],
        fired: bool,
        evasion_rationale: str,
        pcap_filename: str | None = None,
        rule: str | None = None,
        container_exit_code: int | None = None,
        container_stderr: str | None = None,
    ) -> None:
        logger.debug(
            "Recording attack execution experiment_id=%s iteration=%s execution_type=%s attack_id=%s fired=%s container_exit_code=%s",
            experiment_id,
            iteration,
            execution_type,
            attack_id,
            fired,
            container_exit_code,
        )
        experiment = self._read_experiment(experiment_id)
        execution: dict[str, Any] = {
            "iteration": iteration,
            "execution_type": execution_type,
            "attacker": {
                "attack_id": attack_id,
                "arguments": arguments,
                "evasion_rationale": evasion_rationale,
                "container_exit_code": container_exit_code,
                "container_stderr": container_stderr or "",
            },
            "victim": {
                "rule": rule or "",
                "fired": fired,
            },
        }
        if pcap_filename is not None:
            execution["pcap_path"] = f"pcaps/{pcap_filename}"
        experiment["executions"].append(execution)
        self._write_experiment(experiment_id, experiment)

    def finalize(self, experiment_id: str, converged: bool) -> ExperimentArtifacts:
        logger.info("Finalizing experiment record experiment_id=%s converged=%s", experiment_id, converged)
        experiment = self._read_experiment(experiment_id)
        experiment["status"] = "converged" if converged else "failed"
        self._write_experiment(experiment_id, experiment)
        csv_path = self._write_metrics_csv(experiment_id, experiment)

        return ExperimentArtifacts(
            json_path=self._json_path(experiment_id),
            csv_path=csv_path,
        )

    def finalize_error(self, experiment_id: str, error: Exception) -> ExperimentArtifacts:
        logger.info(
            "Finalizing experiment record as error experiment_id=%s error_type=%s",
            experiment_id,
            type(error).__name__,
        )
        experiment = self._read_experiment(experiment_id)
        experiment["status"] = "error"
        experiment["error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        self._write_experiment(experiment_id, experiment)
        csv_path = self._write_metrics_csv(experiment_id, experiment)

        return ExperimentArtifacts(
            json_path=self._json_path(experiment_id),
            csv_path=csv_path,
        )

    def _write_metrics_csv(
        self, experiment_id: str, experiment: dict[str, Any]
    ) -> Path:
        csv_path = self._experiment_dir(experiment_id) / "metrics.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=[
                    "iteration",
                    "execution_type",
                    "attack_id",
                    "arguments",
                    "container_exit_code",
                    "fired",
                    "evasion_rationale",
                    "rule",
                ],
            )
            writer.writeheader()
            for execution in experiment["executions"]:
                attacker = execution.get("attacker", {})
                victim = execution.get("victim", {})
                # support old-format records that lack the nested structure
                writer.writerow(
                    {
                        "iteration": execution["iteration"],
                        "execution_type": execution["execution_type"],
                        "attack_id": attacker.get("attack_id", execution.get("attack_id", "")),
                        "arguments": json.dumps(
                            attacker.get("arguments", execution.get("arguments", [])),
                            separators=(",", ":"),
                        ),
                        "container_exit_code": attacker.get("container_exit_code", ""),
                        "fired": str(victim.get("fired", execution.get("fired", ""))).lower(),
                        "evasion_rationale": attacker.get(
                            "evasion_rationale", execution.get("evasion_rationale", "")
                        ),
                        "rule": victim.get("rule", ""),
                    }
                )
        return csv_path

    def _read_experiment(self, experiment_id: str) -> dict[str, Any]:
        return json.loads(self._json_path(experiment_id).read_text(encoding="utf-8"))

    def _write_experiment(self, experiment_id: str, data: dict[str, Any]) -> None:
        json_path = self._json_path(experiment_id)
        logger.debug("Writing experiment JSON path=%s", json_path)
        json_path.write_text(
            json.dumps(data, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _json_path(self, experiment_id: str) -> Path:
        return self._experiment_dir(experiment_id) / "experiment.json"

    def _experiment_dir(self, experiment_id: str) -> Path:
        return self.output_dir / experiment_id

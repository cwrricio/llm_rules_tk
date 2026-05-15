from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


ExecutionType = Literal["base", "variant"]


logger = logging.getLogger(__name__)

_CSV_FIELDS = [
    "iteration",
    "execution_type",
    "attack_id",
    "arguments",
    "container_exit_code",
    "fired",
    "evasion_rationale",
    "rule",
]


class ExperimentIDFactory:
    """Generates sequential zero-padded experiment IDs (0001, 0002, …) persisted in a counter file."""

    def __init__(self, counter_path: str | Path):
        self.counter_path = Path(counter_path)

    def __call__(self) -> str:
        counter = self._load()
        counter += 1
        self._save(counter)
        return f"{counter:04d}"

    def _load(self) -> int:
        try:
            data = json.loads(self.counter_path.read_text(encoding="utf-8"))
            return int(data["counter"])
        except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return 0

    def _save(self, counter: int) -> None:
        self.counter_path.parent.mkdir(parents=True, exist_ok=True)
        self.counter_path.write_text(
            json.dumps({"counter": counter}, indent=2, sort_keys=True),
            encoding="utf-8",
        )


@dataclass(frozen=True)
class ExperimentArtifacts:
    json_path: Path
    csv_path: Path


class ExperimentRecorder:
    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)

    def initialize_experiment(self, experiment_id: str, intent: str) -> None:
        experiment_dir = self._experiment_dir(experiment_id)
        experiment_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Experiment record initialized experiment_id=%s dir=%s", experiment_id, experiment_dir)
        self._write_experiment(
            experiment_id,
            {
                "experiment_id": experiment_id,
                "intent": intent,
                "status": "running",
                "executions": [],
            },
        )
        # Create the CSV immediately with the header so it exists from the first iteration.
        csv_path = self._csv_path(experiment_id)
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            csv.DictWriter(f, fieldnames=_CSV_FIELDS).writeheader()
        logger.debug("CSV initialized path=%s", csv_path)

    def record_execution(
        self,
        experiment_id: str,
        iteration: int,
        execution_type: ExecutionType,
        attack_id: str,
        arguments: list[str],
        fired: bool,
        evasion_rationale: str,
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

        # Persist to JSON first (source of truth).
        experiment = self._read_experiment(experiment_id)
        experiment["executions"].append(execution)
        self._write_experiment(experiment_id, experiment)

        # Append one row to the CSV immediately — no data loss if the process crashes later.
        self._append_csv_row(experiment_id, execution)

    def finalize(self, experiment_id: str, converged: bool) -> ExperimentArtifacts:
        logger.info("Finalizing experiment record experiment_id=%s converged=%s", experiment_id, converged)
        experiment = self._read_experiment(experiment_id)
        experiment["status"] = "converged" if converged else "failed"
        self._write_experiment(experiment_id, experiment)
        # CSV is already up-to-date (written row-by-row during record_execution).
        # Rebuild from JSON only as a safety net if the file is missing or empty.
        csv_path = self._csv_path(experiment_id)
        if not csv_path.exists() or csv_path.stat().st_size == 0:
            logger.warning("CSV missing at finalize — rebuilding from JSON experiment_id=%s", experiment_id)
            self._rebuild_csv_from_json(experiment_id, experiment)
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
        csv_path = self._csv_path(experiment_id)
        if not csv_path.exists() or csv_path.stat().st_size == 0:
            logger.warning("CSV missing at finalize_error — rebuilding from JSON experiment_id=%s", experiment_id)
            self._rebuild_csv_from_json(experiment_id, experiment)
        return ExperimentArtifacts(
            json_path=self._json_path(experiment_id),
            csv_path=csv_path,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _append_csv_row(self, experiment_id: str, execution: dict[str, Any]) -> None:
        """Append a single execution row to the CSV immediately after it is persisted to JSON."""
        csv_path = self._csv_path(experiment_id)
        # Write header if the file was somehow lost between initialize and this call.
        need_header = not csv_path.exists() or csv_path.stat().st_size == 0
        try:
            with csv_path.open("a", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
                if need_header:
                    writer.writeheader()
                writer.writerow(self._execution_to_row(execution))
                f.flush()
        except Exception:
            logger.exception(
                "Failed to append CSV row experiment_id=%s iteration=%s — data is safe in JSON",
                experiment_id,
                execution.get("iteration"),
            )

    def _rebuild_csv_from_json(self, experiment_id: str, experiment: dict[str, Any]) -> None:
        """Write the full CSV from the JSON executions list (fallback path only)."""
        csv_path = self._csv_path(experiment_id)
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
            writer.writeheader()
            for execution in experiment.get("executions", []):
                writer.writerow(self._execution_to_row(execution))
        logger.info("CSV rebuilt from JSON experiment_id=%s path=%s", experiment_id, csv_path)

    @staticmethod
    def _execution_to_row(execution: dict[str, Any]) -> dict[str, Any]:
        attacker = execution.get("attacker", {})
        victim = execution.get("victim", {})
        return {
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

    def _csv_path(self, experiment_id: str) -> Path:
        return self._experiment_dir(experiment_id) / "metrics.csv"

    def _experiment_dir(self, experiment_id: str) -> Path:
        return self.output_dir / experiment_id

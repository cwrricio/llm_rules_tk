from __future__ import annotations

import logging
from dataclasses import dataclass

from agno.tools import tool

from rules_farmer.experiment_recorder import ExperimentRecorder


logger = logging.getLogger(__name__)


@dataclass
class RunContext:
    """Mutable handle used to inject per-run state into tool closures.

    Why: tools are constructed once at startup but must operate against the current experiment
    and respect the fixed destination resolved by intent preprocessing. The orchestrator updates
    this object before each rules_agent.run_iteration() call; the persistence and inter-agent
    tools read from it.
    """

    experiment_id: str = ""
    variant_label: str = "base"
    fixed_destination_ip: str | None = None
    fixed_destination_port: int | None = None


def make_record_iteration(recorder: ExperimentRecorder, context: RunContext):
    @tool
    def record_iteration(
        iteration: int,
        attack_id: str,
        arguments: list[str],
        fired: bool,
        evasion_rationale: str,
        rule: str,
        container_exit_code: int | None = None,
        container_stderr: str = "",
    ) -> str:
        """Persist one rule-attempt outcome to experiment.json and metrics.csv.

        Call this once after every attack execution within the current variant cycle.

        Args:
            iteration: Sequential attempt number within the current variant (1, 2, ...).
            attack_id: The attack that was executed.
            arguments: The positional arguments passed to the attack.
            fired: Whether the rule with the assigned SID generated an IDS alert.
            evasion_rationale: Rationale produced by the attack agent.
            rule: The Snort rule that was deployed.
            container_exit_code: Docker exit code reported by execute_attack.
            container_stderr: Docker stderr returned by execute_attack.

        Returns:
            "recorded".
        """
        execution_type = "base" if context.variant_label == "base" else "variant"
        logger.debug(
            "Skill record_iteration called experiment_id=%s iteration=%s execution_type=%s",
            context.experiment_id,
            iteration,
            execution_type,
        )
        recorder.record_execution(
            experiment_id=context.experiment_id,
            iteration=iteration,
            execution_type=execution_type,
            attack_id=attack_id,
            arguments=arguments,
            fired=fired,
            evasion_rationale=evasion_rationale,
            rule=rule,
            container_exit_code=container_exit_code,
            container_stderr=container_stderr,
        )
        return "recorded"

    return record_iteration

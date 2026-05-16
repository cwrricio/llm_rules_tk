from __future__ import annotations

import logging
from dataclasses import dataclass, field

from agno.tools import tool

from rules_farmer.experiment_recorder import ExperimentRecorder
from rules_farmer.validated_rules import ValidatedRulesStore


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

    # Fallback snapshot populated by record_iteration; used when Gemini returns plain text
    # instead of structured JSON (tools + output_schema conflict in the Gemini API).
    last_fired: bool | None = None
    last_attack_id: str = ""
    last_arguments: list[str] = field(default_factory=list)
    last_evasion_rationale: str = ""
    last_rule: str | None = None


def make_record_iteration(
    recorder: ExperimentRecorder,
    context: RunContext,
    validated_rules_store: ValidatedRulesStore | None = None,
):
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
        rule_version = f"{context.variant_label}_{iteration}"
        logger.debug(
            "Skill record_iteration called experiment_id=%s iteration=%s execution_type=%s rule_version=%s fired=%s",
            context.experiment_id,
            iteration,
            execution_type,
            rule_version,
            fired,
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
            rule_version=rule_version,
        )
        context.last_fired = fired
        context.last_attack_id = attack_id
        context.last_arguments = list(arguments)
        context.last_evasion_rationale = evasion_rationale
        context.last_rule = rule
        if fired and validated_rules_store is not None and rule:
            try:
                added = validated_rules_store.save(attack_id=attack_id, rule=rule)
                if added:
                    logger.info(
                        "Validated rule saved to library attack_id=%s experiment_id=%s",
                        attack_id,
                        context.experiment_id,
                    )
            except Exception:
                logger.exception(
                    "Failed to persist validated rule attack_id=%s", attack_id
                )
        return "recorded"

    return record_iteration


def make_get_validated_rules(validated_rules_store: ValidatedRulesStore):
    @tool
    def get_validated_rules(attack_id: str) -> list[str]:
        """Return previously-validated Snort rules for the given attack_id.

        These are rules that have already fired against the IDS in past experiments. Try them
        FIRST (with a fresh sid:0 placeholder) before generating a new rule for the same
        attack family — they are known-good detection patterns.

        Args:
            attack_id: The attack identifier (e.g. "xrce-dds-udp-dos", "mqtt-bruteforce").

        Returns:
            A list of canonicalized rule strings (sid:0; rev:1;). Empty list if none yet.
        """
        rules = validated_rules_store.load(attack_id)
        logger.info(
            "get_validated_rules called attack_id=%s count=%s",
            attack_id,
            len(rules),
        )
        return rules

    return get_validated_rules

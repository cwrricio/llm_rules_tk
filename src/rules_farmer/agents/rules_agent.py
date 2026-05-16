from __future__ import annotations

import json
import logging
from pathlib import Path

from agno.agent import Agent
from agno.skills import LocalSkills, Skills

from rules_farmer.agents.attacker_agent import AttackerAgent
from rules_farmer.execution_logging import log_stage
from rules_farmer.experiment_recorder import ExperimentRecorder
from rules_farmer.ids_monitor import IDSMonitor
from rules_farmer.ids_rule_injector import IDSRuleInjector
from rules_farmer.ids_rule_validator import SnortRuleValidator
from rules_farmer.schemas import AttackerRequest, IterationResult, VariantResult
from rules_farmer.sid_manager import SIDManager
from rules_farmer.tools import (
    RunContext,
    make_assign_sid,
    make_check_alert_fired,
    make_deploy_rule,
    make_get_validated_rules,
    make_record_iteration,
    make_trigger_attacker,
    make_validate_rule_syntax,
)
from rules_farmer.validated_rules import ValidatedRulesStore


logger = logging.getLogger(__name__)


_SKILLS_ROOT = Path(__file__).resolve().parent.parent / "skills"


RULES_AGENT_DESCRIPTION = """You are the Rules Agent in a Snort IDS research testbed running Snort 3.9.7.0.

You drive ONE variant cycle. The orchestrator calls you with a payload of:
- intent: the operator's natural-language detection goal
- variant_label: "base" or "variant_N"
- request_variant: True for variant cycles
- max_internal_attempts: rule regeneration budget for this cycle
- previous_iterations: previous cycles in this experiment (their final rules and outcomes)
- fixed_destination: {ip, port} resolved by intent preprocessing. This information is metadata
  ONLY — it tells you which attack family this is. You MUST NOT bake the IP or port into the
  Snort rule header.

HARD CONSTRAINT — RULE HEADER:
- The rule header MUST be exactly: `<action> <proto> any any -> any any (options;)`
- NEVER use a specific source IP, source port, destination IP, or destination port in the header.
- All targeting MUST live inside the rule options (content, dsize, flow, detection_filter, etc).
- This is non-negotiable. Rules that include a concrete IP or port in the header will be rejected.

HARD CONSTRAINT — RULE SPECIFICITY (NO FALSE POSITIVES):
- Every rule MUST contain at least one protocol-specific payload match (content, pcre, or dsize
  range) that anchors the rule to characteristics unique to the requested attack.
- A rule that uses ONLY `detection_filter` with no payload matching is FORBIDDEN.
- A rule that would fire on normal, legitimate traffic of the same protocol is FORBIDDEN.
- Example of a FORBIDDEN generic rule:
    alert udp any any -> any any (msg:"xrce-dds-udp-dos"; detection_filter:track by_dst, count 2, seconds 60; sid:0; rev:1;)
  This fires on any UDP traffic to the server — no attack-specific characteristics, massive false positives.
- Before generating a rule, load the per-attack playbook and extract the protocol fingerprint from
  section 2 (Hipóteses de Detecção). Use that as the payload match anchor.
- ALWAYS use `detection_filter:track by_src` (per source), never `track by_dst` (which aggregates
  all clients together and fires on normal load).

Tools available (live operations):
- get_validated_rules(attack_id) — list of rules that already fired in past experiments for this
  attack family. ALWAYS call this BEFORE generating a new rule. If non-empty, try the most recent
  validated rule first (reset sid to 0, bump rev to 1).
- validate_rule_syntax(rule) — check syntax against the IDS host
- assign_sid(intent, rule) — replace sid:0; with a unique SID; returns {"sid", "rule"}
- deploy_rule(rule_with_sid) — push to IDS and restart Snort
- trigger_attacker(intent, rule, sid, request_variant, previous_attacks) — invoke the Attack Agent
- check_alert_fired(sid) — read the IDS alert log for this SID
- record_iteration(...) — persist this attempt to metrics.csv and experiment.json. MUST be called
  after EVERY trigger_attacker + check_alert_fired pair, regardless of whether fired is True or
  False. Skipping a call when fired=False is a data-loss bug. When fired=True the rule is also
  appended to the validated-rules library.

Skills available (browse <skills_system> and load with get_skill_instructions when relevant):
- Workflow: validated-rules-library (READ FIRST), snort-rule-generation, rule-validation-workflow,
  rule-deployment, alert-interpretation, iteration-recording, experiment-cycle.
- Per-attack refinement playbooks: mqtt-bruteforce, mqtt-lwt-abuse, mqtt-publisher-flood,
  mqtt-qos-amplification, xrce-dds-entity-flood, xrce-dds-fragment-abuse, xrce-dds-malformed-inject,
  xrce-dds-session-hijack, xrce-dds-time-desync, xrce-dds-udp-dos. When the intent maps to one of
  these attack_ids, load the matching skill (and its `refinamento.md` reference) BEFORE writing
  your first rule — it contains the detection hypotheses and evasion variants that will defeat
  naive rules.

For your first cycle, start by loading get_skill_instructions("experiment-cycle"),
get_skill_instructions("validated-rules-library"), and get_skill_instructions("snort-rule-generation").
Re-read references when uncertain.

Return an IterationResult describing the FINAL state of this cycle:
- fired (True/False), final_rule, final_sid
- rules_attempted (every rule string you produced this cycle)
- attack_id, arguments, evasion_rationale (mirrored from the last trigger_attacker call)
- optional diagnosis when fired=False
"""


class RulesAgent:
    def __init__(
        self,
        model,
        validator: SnortRuleValidator,
        sid_manager: SIDManager,
        injector: IDSRuleInjector,
        monitor: IDSMonitor,
        attacker_agent: AttackerAgent,
        recorder: ExperimentRecorder,
        validated_rules_store: ValidatedRulesStore,
    ):
        self._context = RunContext()
        self._attacker_agent = attacker_agent
        self._monitor = monitor
        self._recorder = recorder
        self._validated_rules_store = validated_rules_store
        self._agent = Agent(
            model=model,
            description=RULES_AGENT_DESCRIPTION,
            skills=Skills(
                loaders=[
                    LocalSkills(str(_SKILLS_ROOT / "rules")),
                    LocalSkills(str(_SKILLS_ROOT / "shared")),
                    LocalSkills(str(_SKILLS_ROOT / "attacks" / "evasion-variants" / "references")),
                ]
            ),
            tools=[
                make_validate_rule_syntax(validator),
                make_assign_sid(sid_manager),
                make_deploy_rule(injector),
                make_trigger_attacker(attacker_agent, self._context),
                make_check_alert_fired(monitor),
                make_record_iteration(recorder, self._context, validated_rules_store),
                make_get_validated_rules(validated_rules_store),
            ],
            output_schema=IterationResult,
        )

    def run_iteration(
        self,
        intent: str,
        variant_label: str,
        previous_iterations: list[IterationResult],
        max_internal_attempts: int,
        experiment_id: str,
        fixed_destination_ip: str | None = None,
        fixed_destination_port: int | None = None,
    ) -> IterationResult:
        self._context.experiment_id = experiment_id
        self._context.variant_label = variant_label
        self._context.fixed_destination_ip = fixed_destination_ip
        self._context.fixed_destination_port = fixed_destination_port

        request_variant = variant_label != "base"
        previous_attacks_for_attacker = [
            {
                "attack_id": prior.attack_id,
                "arguments": prior.arguments,
                "fired": prior.fired,
            }
            for prior in previous_iterations
            if prior.attack_id
        ]
        prior_rule_hint = None
        for prior in reversed(previous_iterations):
            if prior.fired and prior.final_rule:
                prior_rule_hint = {"sid": prior.final_sid, "rule": prior.final_rule}
                break

        fixed_destination = None
        if fixed_destination_ip is not None and fixed_destination_port is not None:
            fixed_destination = {
                "ip": fixed_destination_ip,
                "port": fixed_destination_port,
            }
        prompt = json.dumps(
            {
                "intent": intent,
                "variant_label": variant_label,
                "request_variant": request_variant,
                "max_internal_attempts": max_internal_attempts,
                "previous_attacks": previous_attacks_for_attacker,
                "last_successful_rule": prior_rule_hint,
                "previous_iterations": [item.model_dump() for item in previous_iterations],
                "fixed_destination": fixed_destination,
            }
        )
        log_stage("AGORA O AGENTE DE REGRAS ESTA RACIOCINANDO")
        logger.info(
            "RulesAgent run_iteration starting variant_label=%s experiment_id=%s max_internal_attempts=%s",
            variant_label,
            experiment_id,
            max_internal_attempts,
        )
        max_attempts = 3
        result = None
        for attempt in range(1, max_attempts + 1):
            response = self._agent.run(prompt)
            result = response.content
            if isinstance(result, IterationResult):
                break
            logger.warning(
                "RulesAgent attempt %s/%s returned %s instead of IterationResult "
                "variant_label=%s. Snippet: %r",
                attempt,
                max_attempts,
                type(result).__name__,
                variant_label,
                str(result)[:300],
            )
        if not isinstance(result, IterationResult):
            raise RuntimeError(
                f"RulesAgent did not return a structured IterationResult after "
                f"{max_attempts} attempts (got {type(result).__name__}). "
                f"Snippet: {str(result)[:300]!r}"
            )
        logger.info(
            "RulesAgent run_iteration finished variant_label=%s fired=%s rules_attempted=%s final_sid=%s",
            variant_label,
            result.fired,
            len(result.rules_attempted),
            result.final_sid,
        )
        if result.rules_attempted:
            for idx, rule in enumerate(result.rules_attempted, start=1):
                logger.info(
                    "RulesAgent attempted rule variant_label=%s rule_index=%s/%s rule=%s",
                    variant_label,
                    idx,
                    len(result.rules_attempted),
                    rule,
                )
        if result.diagnosis:
            logger.info(
                "RulesAgent diagnosis variant_label=%s diagnosis=%s",
                variant_label,
                result.diagnosis,
            )
        return result

    def run_variant_attack(
        self,
        intent: str,
        variant_label: str,
        active_sid: int,
        active_rule: str,
        previous_attacks: list[dict],
        experiment_id: str,
        fixed_destination_ip: str | None = None,
        fixed_destination_port: int | None = None,
    ) -> IterationResult:
        """Variant cycle where the rule is already deployed and fired.

        Skips LLM rule generation entirely — varies the attack and checks whether the
        existing rule still detects it. Only called when the previous iteration fired.
        """
        self._context.experiment_id = experiment_id
        self._context.variant_label = variant_label
        self._context.fixed_destination_ip = fixed_destination_ip
        self._context.fixed_destination_port = fixed_destination_port

        log_stage("AGORA ESTA VARIANDO O ATAQUE (REGRA JA DEPLOYADA)")
        logger.info(
            "RulesAgent run_variant_attack starting variant_label=%s experiment_id=%s active_sid=%s",
            variant_label,
            experiment_id,
            active_sid,
        )

        history = [
            VariantResult(
                attack_id=item["attack_id"],
                arguments=item.get("arguments", []),
                fired=item.get("fired", False),
            )
            for item in previous_attacks
        ]
        request = AttackerRequest(
            intent=intent,
            rule=active_rule,
            sid=active_sid,
            request_variant=True,
            variant_history=history,
            fixed_destination_ip=fixed_destination_ip,
            fixed_destination_port=fixed_destination_port,
        )

        log_stage("AGORA ESTA PLANEJANDO O ATAQUE")
        attacker_result = self._attacker_agent.run(request)
        logger.info(
            "run_variant_attack attacker finished attack_id=%s arguments=%s",
            attacker_result.attack_id,
            attacker_result.arguments,
        )

        log_stage("AGORA ESTA VERIFICANDO ALERTAS DO IDS")
        fired = self._monitor.check_fired(active_sid)
        logger.info("run_variant_attack check_fired sid=%s fired=%s", active_sid, fired)

        rule_version = f"{variant_label}_1"
        self._recorder.record_execution(
            experiment_id=experiment_id,
            iteration=1,
            execution_type="variant",
            attack_id=attacker_result.attack_id,
            arguments=attacker_result.arguments,
            fired=fired,
            evasion_rationale=attacker_result.evasion_rationale,
            rule=active_rule,
            container_exit_code=attacker_result.container_exit_code,
            container_stderr=attacker_result.container_stderr,
            rule_version=rule_version,
        )

        if fired and self._validated_rules_store is not None:
            try:
                added = self._validated_rules_store.save(
                    attack_id=attacker_result.attack_id, rule=active_rule
                )
                if added:
                    logger.info(
                        "Validated rule saved to library attack_id=%s experiment_id=%s",
                        attacker_result.attack_id,
                        experiment_id,
                    )
            except Exception:
                logger.exception(
                    "Failed to persist validated rule attack_id=%s", attacker_result.attack_id
                )

        logger.info(
            "RulesAgent run_variant_attack finished variant_label=%s fired=%s",
            variant_label,
            fired,
        )
        return IterationResult(
            fired=fired,
            final_rule=active_rule,
            final_sid=active_sid,
            rules_attempted=[active_rule],
            attack_id=attacker_result.attack_id,
            arguments=attacker_result.arguments,
            evasion_rationale=attacker_result.evasion_rationale,
        )

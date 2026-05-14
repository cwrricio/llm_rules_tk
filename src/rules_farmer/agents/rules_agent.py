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
from rules_farmer.schemas import IterationResult
from rules_farmer.sid_manager import SIDManager
from rules_farmer.tools import (
    RunContext,
    make_assign_sid,
    make_check_alert_fired,
    make_deploy_rule,
    make_record_iteration,
    make_trigger_attacker,
    make_validate_rule_syntax,
)


logger = logging.getLogger(__name__)


_SKILLS_ROOT = Path(__file__).resolve().parent.parent / "skills"


RULES_AGENT_DESCRIPTION = """You are the Rules Agent in a Snort IDS research testbed running Snort 3.9.7.0.

You drive ONE variant cycle. The orchestrator calls you with a payload of:
- intent: the operator's natural-language detection goal
- variant_label: "base" or "variant_N"
- request_variant: True for variant cycles
- max_internal_attempts: rule regeneration budget for this cycle
- previous_iterations: previous cycles in this experiment (their final rules and outcomes)
- fixed_destination: {ip, port} resolved by intent preprocessing — the testbed's target service
  address for this attack family (MQTT → port 1883, XRCE → port 8888). This is the destination
  IP/port your Snort rule MUST match against. NEVER invent a different IP or port.

Tools available (live operations):
- validate_rule_syntax(rule) — check syntax against the IDS host
- assign_sid(intent, rule) — replace sid:0; with a unique SID; returns {"sid", "rule"}
- deploy_rule(rule_with_sid) — push to IDS and restart Snort
- trigger_attacker(intent, rule, sid, request_variant, previous_attacks) — invoke the Attack Agent
- check_alert_fired(sid) — read the IDS alert log for this SID
- record_iteration(...) — persist this attempt to metrics.csv and experiment.json

Skills available (browse <skills_system> and load with get_skill_instructions when relevant):
- Workflow: snort-rule-generation, rule-validation-workflow, rule-deployment, alert-interpretation,
  iteration-recording, experiment-cycle.
- Per-attack refinement playbooks: mqtt-bruteforce, mqtt-lwt-abuse, mqtt-publisher-flood,
  mqtt-qos-amplification, xrce-dds-entity-flood, xrce-dds-fragment-abuse, xrce-dds-malformed-inject,
  xrce-dds-session-hijack, xrce-dds-time-desync, xrce-dds-udp-dos. When the intent maps to one of
  these attack_ids, load the matching skill (and its `refinamento.md` reference) BEFORE writing
  your first rule — it contains the detection hypotheses and evasion variants that will defeat
  naive rules.

For your first cycle, start by loading get_skill_instructions("experiment-cycle") and
get_skill_instructions("snort-rule-generation"). Re-read references when uncertain.

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
    ):
        self._context = RunContext()
        self._agent = Agent(
            model=model,
            description=RULES_AGENT_DESCRIPTION,
            skills=Skills(
                loaders=[
                    LocalSkills(str(_SKILLS_ROOT / "rules")),
                    LocalSkills(str(_SKILLS_ROOT / "shared")),
                    LocalSkills(str(_SKILLS_ROOT / "references")),
                ]
            ),
            tools=[
                make_validate_rule_syntax(validator),
                make_assign_sid(sid_manager),
                make_deploy_rule(injector),
                make_trigger_attacker(attacker_agent, self._context),
                make_check_alert_fired(monitor),
                make_record_iteration(recorder, self._context),
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
        response = self._agent.run(prompt)
        result: IterationResult = response.content
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

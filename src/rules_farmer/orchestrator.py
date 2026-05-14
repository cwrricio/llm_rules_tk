from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
import shutil
from typing import Callable

from rules_farmer.experiment_recorder import ExperimentRecorder
from rules_farmer.execution_logging import log_stage
from rules_farmer.schemas import AttackerRequest, FeedbackPayload, VariantResult


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
        rule_agent,
        validator,
        sid_manager,
        injector,
        attacker_agent,
        attack_executor,
        monitor,
        recorder: ExperimentRecorder,
        experiment_id_factory: Callable[[], str] | None = None,
    ):
        self.rule_agent = rule_agent
        self.validator = validator
        self.sid_manager = sid_manager
        self.injector = injector
        self.attacker_agent = attacker_agent
        self.attack_executor = attack_executor
        self.monitor = monitor
        self.recorder = recorder
        self.experiment_id_factory = experiment_id_factory or (lambda: str(uuid.uuid4()))

    def run_experiment(
        self,
        intent: str,
        max_iterations: int,
        variant_count: int,
        experiment_id: str | None = None,
    ) -> ExperimentRunResult:
        experiment_id = experiment_id or self.experiment_id_factory()
        log_stage("EXPERIMENTO INICIADO")
        logger.info(
            "Experiment started experiment_id=%s max_iterations=%s variant_count=%s intent=%r",
            experiment_id,
            max_iterations,
            variant_count,
            intent,
        )
        self.recorder.initialize_experiment(experiment_id, intent)
        feedback = None
        previous_rules = None
        variant_history: list[VariantResult] = []

        try:
            return self._run_feedback_loop(
                experiment_id=experiment_id,
                intent=intent,
                max_iterations=max_iterations,
                variant_count=variant_count,
                feedback=feedback,
                previous_rules=previous_rules,
                variant_history=variant_history,
            )
        except Exception as exc:
            log_stage("EXPERIMENTO PAROU COM ERRO")
            logger.exception("Experiment stopped due to error experiment_id=%s", experiment_id)
            self.recorder.finalize_error(experiment_id, exc)
            raise

    def _run_feedback_loop(
        self,
        experiment_id: str,
        intent: str,
        max_iterations: int,
        variant_count: int,
        feedback: FeedbackPayload | None,
        previous_rules: list[str] | None,
        variant_history: list[VariantResult],
    ) -> ExperimentRunResult:
        for iteration in range(1, max_iterations + 1):
            log_stage(f"ITERACAO {iteration} DE {max_iterations}")
            logger.debug("Iteration started experiment_id=%s iteration=%s", experiment_id, iteration)
            log_stage("AGORA ESTA GERANDO A REGRA")
            logger.debug("Generating IDS rule experiment_id=%s iteration=%s", experiment_id, iteration)
            rule_output = self.rule_agent.run(
                intent=intent,
                previous_rules=previous_rules,
                feedback=feedback,
            )
            previous_rules = rule_output.rules
            logger.info(
                "Rule generation finished experiment_id=%s iteration=%s rule_count=%s diagnosis_present=%s",
                experiment_id,
                iteration,
                len(rule_output.rules),
                rule_output.diagnosis is not None,
            )

            if not self._rules_are_valid(rule_output.rules):
                logger.warning(
                    "Rule validation failed experiment_id=%s iteration=%s",
                    experiment_id,
                    iteration,
                )
                feedback = FeedbackPayload(
                    pcap_summary="",
                    ids_logs="",
                    evasion_rationale="Rule validation failed",
                )
                continue

            assigned_rules = self.sid_manager.assign_sids(intent, rule_output.rules)
            logger.info(
                "SID assignment completed experiment_id=%s iteration=%s sids=%s",
                experiment_id,
                iteration,
                [item.sid for item in assigned_rules],
            )
            log_stage("AGORA ESTA INJETANDO A REGRA NO IDS")
            logger.debug("Injecting IDS rule experiment_id=%s iteration=%s", experiment_id, iteration)
            self.injector.inject([item.rule for item in assigned_rules])
            logger.info("Rule injection finished experiment_id=%s iteration=%s", experiment_id, iteration)
            active_rule = assigned_rules[0]

            base_fired = self._run_attack_execution(
                experiment_id=experiment_id,
                iteration=iteration,
                execution_type="base",
                intent=intent,
                rule=active_rule.rule,
                sid=active_rule.sid,
                variant_history=variant_history,
            )
            if not base_fired.fired:
                logger.info(
                    "Base attack did not fire experiment_id=%s iteration=%s",
                    experiment_id,
                    iteration,
                )
                feedback = base_fired.feedback
                continue

            converged = True
            for variant_index in range(1, variant_count + 1):
                log_stage(f"AGORA ESTA RODANDO VARIANTE {variant_index} DE {variant_count}")
                logger.debug(
                    "Variant attack started experiment_id=%s iteration=%s variant_index=%s/%s",
                    experiment_id,
                    iteration,
                    variant_index,
                    variant_count,
                )
                variant_fired = self._run_attack_execution(
                    experiment_id=experiment_id,
                    iteration=iteration,
                    execution_type="variant",
                    intent=intent,
                    rule=active_rule.rule,
                    sid=active_rule.sid,
                    variant_history=variant_history,
                )
                if not variant_fired.fired:
                    logger.info(
                        "Variant evaded rule experiment_id=%s iteration=%s variant_index=%s",
                        experiment_id,
                        iteration,
                        variant_index,
                    )
                    feedback = variant_fired.feedback
                    converged = False
                    break

            if converged:
                log_stage("EXPERIMENTO CONVERGIU")
                artifacts = self.recorder.finalize(experiment_id, converged=True)
                logger.info(
                    "Experiment converged experiment_id=%s json_path=%s csv_path=%s",
                    experiment_id,
                    artifacts.json_path,
                    artifacts.csv_path,
                )
                return ExperimentRunResult(
                    status="converged",
                    experiment_id=experiment_id,
                    json_path=artifacts.json_path,
                    csv_path=artifacts.csv_path,
                )

        log_stage("EXPERIMENTO FALHOU")
        artifacts = self.recorder.finalize(experiment_id, converged=False)
        logger.info(
            "Experiment failed experiment_id=%s json_path=%s csv_path=%s",
            experiment_id,
            artifacts.json_path,
            artifacts.csv_path,
        )
        return ExperimentRunResult(
            status="failed",
            experiment_id=experiment_id,
            json_path=artifacts.json_path,
            csv_path=artifacts.csv_path,
        )

    def _rules_are_valid(self, rules: list[str]) -> bool:
        log_stage("AGORA ESTA VALIDANDO A REGRA")
        for index, rule in enumerate(rules, start=1):
            logger.debug("Validating rule %s/%s", index, len(rules))
            result = self.validator.validate(rule)
            if not result.valid:
                logger.warning(
                    "Rule validation rejected rule_index=%s/%s error=%s",
                    index,
                    len(rules),
                    result.error,
                )
                return False
            logger.debug("Rule validation accepted rule_index=%s/%s", index, len(rules))
        logger.info("Rule validation accepted rule_count=%s", len(rules))
        return True

    def _run_attack_execution(
        self,
        experiment_id: str,
        iteration: int,
        execution_type: str,
        intent: str,
        rule: str,
        sid: int,
        variant_history: list[VariantResult],
    ) -> "_AttackOutcome":
        log_stage("AGORA ESTA PLANEJANDO O ATAQUE")
        logger.debug(
            "Attack planning started experiment_id=%s iteration=%s execution_type=%s history_count=%s",
            experiment_id,
            iteration,
            execution_type,
            len(variant_history),
        )
        plan = self.attacker_agent.run(
            AttackerRequest(
                intent=intent,
                rule=rule,
                sid=sid,
                variant_history=variant_history,
            )
        )
        logger.info(
            "Attack planning finished experiment_id=%s iteration=%s execution_type=%s attack_id=%s arguments=%s",
            experiment_id,
            iteration,
            execution_type,
            plan.attack_id,
            plan.arguments,
        )
        log_stage("AGORA ESTA RODANDO O ATACANTE")
        logger.debug(
            "Running attacker experiment_id=%s iteration=%s execution_type=%s attack_id=%s",
            experiment_id,
            iteration,
            execution_type,
            plan.attack_id,
        )
        execution = self.attack_executor.execute(plan.attack_id, plan.arguments)
        logger.info(
            "Attack execution finished experiment_id=%s iteration=%s execution_type=%s attack_id=%s exit_code=%s pcap=%s",
            experiment_id,
            iteration,
            execution_type,
            plan.attack_id,
            execution.exit_code,
            execution.pcap_local_path,
        )
        pcap_dest_dir = Path(self.recorder.output_dir) / experiment_id / "pcaps"
        pcap_dest_dir.mkdir(parents=True, exist_ok=True)
        pcap_dest_path = pcap_dest_dir / execution.pcap_local_path.name
        try:
            shutil.copy2(execution.pcap_local_path, pcap_dest_path)
            logger.debug("PCAP copied to experiment directory path=%s", pcap_dest_path)
        except FileNotFoundError:
            # Best-effort: if the executor didn't produce a local PCAP, still record execution.
            logger.warning(
                "PCAP copy skipped because source was missing source=%s destination=%s",
                execution.pcap_local_path,
                pcap_dest_path,
            )
            pass
        log_stage("AGORA ESTA VERIFICANDO ALERTAS DO IDS")
        logger.debug("Checking IDS alerts sid=%s", sid)
        fired = self.monitor.check_fired(sid)
        logger.info(
            "IDS monitor check finished sid=%s fired=%s",
            sid,
            fired,
        )
        variant_history.append(
            VariantResult(attack_id=plan.attack_id, arguments=plan.arguments, fired=fired)
        )
        self.recorder.record_execution(
            experiment_id=experiment_id,
            iteration=iteration,
            execution_type=execution_type,
            attack_id=plan.attack_id,
            arguments=plan.arguments,
            fired=fired,
            evasion_rationale=plan.evasion_rationale,
            pcap_filename=execution.pcap_local_path.name,
            rule=rule,
            container_exit_code=execution.container_exit_code,
            container_stderr=execution.container_stderr,
        )
        feedback = None
        if not fired:
            feedback = FeedbackPayload(
                pcap_summary=execution.pcap_summary,
                ids_logs="",
                evasion_rationale=plan.evasion_rationale,
            )
        return _AttackOutcome(fired=fired, feedback=feedback)


@dataclass(frozen=True)
class _AttackOutcome:
    fired: bool
    feedback: FeedbackPayload | None

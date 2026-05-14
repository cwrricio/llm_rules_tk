from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RuleAgentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[str]
    diagnosis: str | None


class VariantResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    arguments: list[str]
    fired: bool


class FeedbackPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pcap_summary: str
    ids_logs: str
    evasion_rationale: str


class AttackPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    arguments: list[str]
    evasion_rationale: str


class AttackerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: str
    rule: str
    sid: int
    variant_history: list[VariantResult]

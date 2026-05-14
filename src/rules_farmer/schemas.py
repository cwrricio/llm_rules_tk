from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class VariantResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    arguments: list[str]
    fired: bool


class FeedbackPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids_logs: str
    evasion_rationale: str
    validation_error: str | None = None


class AttackerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: str
    rule: str
    sid: int
    request_variant: bool
    variant_history: list[VariantResult] = []
    fixed_destination_ip: str | None = None
    fixed_destination_port: int | None = None


class AttackerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    arguments: list[str]
    evasion_rationale: str
    container_exit_code: int | None = None
    container_stderr: str = ""
    fired: bool | None = None


class IterationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fired: bool
    final_rule: str | None = None
    final_sid: int | None = None
    rules_attempted: list[str] = []
    attack_id: str = ""
    arguments: list[str] = []
    evasion_rationale: str = ""
    diagnosis: str | None = None

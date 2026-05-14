from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from rules_farmer.errors import SIDCounterCorruptedError


logger = logging.getLogger(__name__)


SID_COUNTER_RECOVERY_MESSAGE = (
    'sid_counter.json missing or corrupted. To reset safely, delete '
    'rules_farmer_ai.rules and recreate sid_counter.json with {"counter": 9000000}.'
)


@dataclass(frozen=True)
class AssignedRule:
    sid: int
    rule: str


class SIDManager:
    def __init__(self, counter_path: str | Path, mapping_path: str | Path):
        self.counter_path = Path(counter_path)
        self.mapping_path = Path(mapping_path)
        self._counter = self._load_counter()

    def assign_sid(self, intent: str) -> int:
        self._counter += 1
        logger.debug("Assigning SID sid=%s", self._counter)
        self._write_json(self.counter_path, {"counter": self._counter})

        mappings = self._load_mappings()
        mappings[str(self._counter)] = intent
        self._write_json(self.mapping_path, mappings)
        return self._counter

    def assign_sids(self, intent: str, rules: list[str]) -> list[AssignedRule]:
        logger.debug("Assigning SIDs to generated rules rule_count=%s", len(rules))
        assigned_rules = []
        for rule in rules:
            sid = self.assign_sid(intent)
            assigned_rules.append(
                AssignedRule(
                    sid=sid,
                    rule=re.sub(r"sid\s*:\s*\d+\s*;", f"sid:{sid};", rule),
                )
            )
        return assigned_rules

    def _load_counter(self) -> int:
        try:
            data = json.loads(self.counter_path.read_text(encoding="utf-8"))
            logger.debug("Loaded SID counter path=%s counter=%s", self.counter_path, data["counter"])
            return int(data["counter"])
        except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            logger.exception("SID counter missing or corrupted path=%s", self.counter_path)
            raise SIDCounterCorruptedError(SID_COUNTER_RECOVERY_MESSAGE) from exc

    def _load_mappings(self) -> dict[str, str]:
        if not self.mapping_path.exists():
            return {}
        return json.loads(self.mapping_path.read_text(encoding="utf-8"))

    def _write_json(self, path: Path, data: dict[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        logger.debug("Writing SID JSON path=%s", path)
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

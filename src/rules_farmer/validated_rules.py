"""Persistent library of Snort rules that successfully fired (fired=True).

All validated rules from every attack family are stored in a single combined file
(all_validated_rules.rules) under the configured validated_rules_dir. Each entry is
preceded by a metadata comment that identifies the attack family, allowing load() to
filter by attack_id while keeping everything in one place for easy inspection.

Storage format per rule:
    # attack_id=<id> fired_at=<ISO8601>
    <canonical rule (sid:0; rev:1;)>

Duplicates are filtered using the canonical form (sid/rev stripped).
"""

from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path


logger = logging.getLogger(__name__)


_SID_PATTERN = re.compile(r"\bsid\s*:\s*\d+\s*;")
_REV_PATTERN = re.compile(r"\brev\s*:\s*\d+\s*;")
_SLUG_PATTERN = re.compile(r"[^a-zA-Z0-9_\-]")
_META_PATTERN = re.compile(r"^#\s*attack_id=(\S+)")

_COMBINED_FILENAME = "all_validated_rules.rules"


def _slugify(attack_id: str) -> str:
    cleaned = _SLUG_PATTERN.sub("-", attack_id.strip()).strip("-")
    return cleaned or "unknown"


def canonicalize(rule: str) -> str:
    """Strip sid/rev so different SID assignments of the same logical rule dedupe to one entry."""
    without_sid = _SID_PATTERN.sub("sid:0;", rule)
    without_rev = _REV_PATTERN.sub("rev:1;", without_sid)
    return " ".join(without_rev.split())


class ValidatedRulesStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self._lock = threading.Lock()

    @property
    def _combined_path(self) -> Path:
        return self.root / _COMBINED_FILENAME

    def save(self, attack_id: str, rule: str) -> bool:
        """Append the canonical form of `rule` to the combined library if not already present.

        Returns True if the rule was new and got written, False if it was already known.
        """
        if not attack_id or not rule or not rule.strip():
            return False
        slug = _slugify(attack_id)
        canonical = canonicalize(rule)
        with self._lock:
            existing = self._load_canonical_for(slug)
            if canonical in existing:
                logger.debug(
                    "Validated rule already known attack_id=%s canonical=%s",
                    attack_id,
                    canonical[:80],
                )
                return False
            self._combined_path.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            with self._combined_path.open("a", encoding="utf-8") as fh:
                fh.write(f"# attack_id={slug} fired_at={timestamp}\n")
                fh.write(f"{canonical}\n")
        logger.info(
            "Validated rule appended attack_id=%s path=%s canonical=%s",
            attack_id,
            self._combined_path,
            canonical[:120],
        )
        return True

    def load(self, attack_id: str) -> list[str]:
        """Return the canonical validated rules for the given attack_id (most recent last)."""
        return list(self._load_canonical_for(_slugify(attack_id)))

    def _load_canonical_for(self, slug: str) -> list[str]:
        path = self._combined_path
        if not path.exists():
            return []
        rules: list[str] = []
        seen: set[str] = set()
        current_attack: str | None = None
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line:
                continue
            meta = _META_PATTERN.match(line)
            if meta:
                current_attack = meta.group(1)
                continue
            if line.startswith("#"):
                continue
            if current_attack != slug:
                continue
            canonical = canonicalize(line)
            if canonical in seen:
                continue
            seen.add(canonical)
            rules.append(canonical)
        return rules

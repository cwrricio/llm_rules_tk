"""Persistent library of Snort rules that successfully fired (fired=True).

Why: across many experiments we accumulate rules that have been validated by the IDS for each
attack family. Future iterations should try these proven rules FIRST before generating new ones,
saving time and converging faster. Stored per attack_id under data/validated_rules/<id>.rules.

Storage format: one canonical (sid/rev stripped) rule per line, with a leading "# fired_at=..."
comment for traceability. Duplicates are filtered out using the canonical form.
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

    def _path(self, attack_id: str) -> Path:
        return self.root / f"{_slugify(attack_id)}.rules"

    def save(self, attack_id: str, rule: str) -> bool:
        """Append the canonical form of `rule` to the attack's library if not already present.

        Returns True if the rule was new and got written, False if it was already known.
        """
        if not attack_id or not rule or not rule.strip():
            return False
        canonical = canonicalize(rule)
        path = self._path(attack_id)
        with self._lock:
            existing = self._load_canonical(path)
            if canonical in existing:
                logger.debug(
                    "Validated rule already known attack_id=%s canonical=%s",
                    attack_id,
                    canonical[:80],
                )
                return False
            path.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            with path.open("a", encoding="utf-8") as fh:
                fh.write(f"# fired_at={timestamp}\n")
                fh.write(f"{canonical}\n")
        logger.info(
            "Validated rule appended attack_id=%s path=%s canonical=%s",
            attack_id,
            path,
            canonical[:120],
        )
        return True

    def load(self, attack_id: str) -> list[str]:
        """Return the canonical validated rules for the given attack_id (most recent last)."""
        return list(self._load_canonical(self._path(attack_id)))

    def _load_canonical(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        rules: list[str] = []
        seen: set[str] = set()
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            canonical = canonicalize(line)
            if canonical in seen:
                continue
            seen.add(canonical)
            rules.append(canonical)
        return rules

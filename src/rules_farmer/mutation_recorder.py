"""Persistent capture of exact file mutations produced by the Attack Agent.

Every call to modify_attack_file() writes the new file content to
results/{experiment_id}/mutations/{variant_label}__{attack_id}__{filename}
so the exact state of each attack variant is preserved independently of the
Docker build process.

MutationContext is a mutable shared object.  RulesAgent updates it before
each attacker invocation; make_modify_attack_file() reads it on every write.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass
class MutationContext:
    output_dir: Path
    experiment_id: str = ""
    variant_label: str = "base"

    def record(self, attack_id: str, filename: str, content: str) -> None:
        if not self.experiment_id:
            return
        mutations_dir = self.output_dir / self.experiment_id / "mutations"
        mutations_dir.mkdir(parents=True, exist_ok=True)
        safe_filename = filename.replace("/", "_").replace("\\", "_")
        path = mutations_dir / f"{self.variant_label}__{attack_id}__{safe_filename}"
        path.write_text(content, encoding="utf-8")
        logger.info(
            "Mutation recorded experiment_id=%s variant=%s attack_id=%s file=%s path=%s bytes=%s",
            self.experiment_id,
            self.variant_label,
            attack_id,
            filename,
            path,
            len(content.encode()),
        )

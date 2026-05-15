from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass

from rules_farmer.ssh import SSHClient


logger = logging.getLogger(__name__)

# Keywords that exist in Snort 2 but are invalid in Snort 3.
_SNORT2_FORBIDDEN: list[tuple[str, str]] = [
    ("threshold:", "use detection_filter instead of threshold in Snort 3"),
    ("uricontent:", "use content + http_uri instead of uricontent in Snort 3"),
    ("resp:", "resp is not supported in Snort 3"),
    ("react:", "react is not supported in Snort 3"),
    ("tag:", "tag is not supported in Snort 3"),
]

# Minimum structure: action proto src_ip src_port dir dst_ip dst_port (...)
_RULE_STRUCTURE_RE = re.compile(
    r"^\s*\w+\s+\w+\s+\S+\s+\S+\s+[-<>]+\s+\S+\s+\S+\s*\(.*\)\s*$",
    re.DOTALL,
)

# Hard constraint: rule header must be `<action> <proto> any any -> any any (`.
# Anything else (concrete IPs, ports, CIDR ranges, variables) is rejected.
_RULE_HEADER_ANY_RE = re.compile(
    r"^\s*\w+\s+\w+\s+any\s+any\s+->\s+any\s+any\s*\(",
)


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    error: str | None


class SnortRuleValidator:
    def __init__(
        self,
        ssh_client: SSHClient,
        temp_rule_path: str = "/tmp/rules_farmer_candidate.rules",
        container_name: str = "snort_ids",
        container_temp_rule_path: str = "/tmp/rules_farmer_candidate.rules",
        snort_config_path: str = "/opt/snort3/etc/snort/snort.lua",
    ):
        self.ssh_client = ssh_client
        self.temp_rule_path = temp_rule_path
        self.container_name = container_name
        self.container_temp_rule_path = container_temp_rule_path
        self.snort_config_path = snort_config_path

    def validate(self, rule: str) -> ValidationResult:
        logger.debug(
            "Snort rule validation started temp_rule_path=%s container=%s",
            self.temp_rule_path,
            self.container_name,
        )
        pre = self._prevalidate(rule)
        if pre is not None:
            logger.warning("Snort rule pre-validation rejected error=%s", pre.error)
            return pre

        # Snort rejects sid:0; — substitute a temporary SID for the syntax check only.
        # SID assignment happens after validation passes (orchestrator.assign_sids).
        validation_rule = re.sub(r"sid\s*:\s*0\s*;", "sid:999999999;", rule)
        temp_path = shlex.quote(self.temp_rule_path)
        self.ssh_client.run_command(f"cat > {temp_path} <<'EOF'\n{validation_rule}\nEOF")
        self.ssh_client.run_command(
            "docker cp "
            f"{temp_path} "
            f"{shlex.quote(self.container_name)}:{shlex.quote(self.container_temp_rule_path)}"
        )
        result = self.ssh_client.run_command(
            "docker exec "
            f"{shlex.quote(self.container_name)} "
            "snort "
            f"-c {shlex.quote(self.snort_config_path)} "
            f"-R {shlex.quote(self.container_temp_rule_path)} "
            "-T"
        )
        if result.exit_code == 0:
            logger.debug("Snort rule validation accepted")
            return ValidationResult(valid=True, error=None)

        error_detail = self._extract_snort_error(result.stdout, result.stderr)
        logger.warning("Snort rule validation rejected error=%s", error_detail)
        return ValidationResult(valid=False, error=error_detail)

    def _prevalidate(self, rule: str) -> ValidationResult | None:
        rule_stripped = rule.strip()
        if not rule_stripped:
            return ValidationResult(valid=False, error="Rule is empty")

        if not _RULE_STRUCTURE_RE.match(rule_stripped):
            return ValidationResult(
                valid=False,
                error=(
                    "Rule does not match expected Snort 3 structure: "
                    "action proto src_ip src_port direction dst_ip dst_port (options;)"
                ),
            )

        if not _RULE_HEADER_ANY_RE.match(rule_stripped):
            return ValidationResult(
                valid=False,
                error=(
                    "Rule header must be exactly `<action> <proto> any any -> any any (...)`. "
                    "Concrete source/destination IPs or ports are FORBIDDEN — move targeting "
                    "into rule options (content, dsize, flow, detection_filter, etc)."
                ),
            )

        rule_body_start = rule_stripped.index("(")
        rule_body = rule_stripped[rule_body_start:]

        for keyword, reason in _SNORT2_FORBIDDEN:
            if keyword in rule_body:
                return ValidationResult(
                    valid=False,
                    error=f"Forbidden Snort 2 keyword '{keyword.rstrip(':')}': {reason}",
                )

        flow_match = re.search(r"flow\s*:\s*([^;]+);", rule_body)
        if flow_match:
            flow_opts = [o.strip() for o in flow_match.group(1).split(",")]
            if "stateless" in flow_opts and len(flow_opts) > 1:
                return ValidationResult(
                    valid=False,
                    error="flow:stateless cannot be combined with other flow options in Snort 3",
                )

        _CONTENT_MODIFIERS = r"(nocase|rawbytes|offset|depth|within|distance)"
        if re.search(
            r'content\s*:\s*"[^"]*"\s*,' + r"\s*" + _CONTENT_MODIFIERS,
            rule_body,
        ):
            return ValidationResult(
                valid=False,
                error=(
                    "Content modifiers must be separate options: "
                    'use content:"X"; rawbytes; not content:"X", rawbytes; (Snort 2 syntax)'
                ),
            )

        return None

    @staticmethod
    def _extract_snort_error(stdout: str, stderr: str) -> str:
        combined = (stdout or "") + "\n" + (stderr or "")
        error_lines = [
            line for line in combined.splitlines()
            if re.search(r"ERROR|error:|FATAL|Warning:|parse error|unknown option", line, re.IGNORECASE)
        ]
        if error_lines:
            return "\n".join(error_lines[:20])
        return combined.strip()[:1000]

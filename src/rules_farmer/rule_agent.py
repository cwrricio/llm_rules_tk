from __future__ import annotations

import logging

from rules_farmer.schemas import FeedbackPayload, RuleAgentOutput


logger = logging.getLogger(__name__)


RULE_AGENT_SYSTEM_PROMPT = """You generate Snort 3.9.12.0 IDS rules for a research testbed.

MANDATORY:
- sid:0; is always the SID placeholder (SID Manager assigns real SIDs).
- rev:1; on first iteration; increment on each revision.
- msg field must contain the operator intent verbatim.
- If the intent is ambiguous produce multiple rules rather than one best guess.

SNORT 3 SYNTAX — STRICT:
- Rule format: action proto src_ip src_port direction dst_ip dst_port (options;)
- Every option must end with a semicolon inside the parentheses.
- content modifiers (nocase, rawbytes, offset, depth, within, distance) MUST appear immediately after the content option they modify — NOT as standalone options anywhere else in the rule.
- detection_filter syntax: detection_filter:track by_src, count N, seconds S;
- pcre strings must be enclosed in / / with valid PCRE syntax.

FORBIDDEN KEYWORDS (Snort 2 only — do NOT use):
- threshold — replaced by detection_filter in Snort 3.
- uricontent — use content + http_uri instead.
- resp — not supported in Snort 3.
- react — not supported in Snort 3.
- tag — not supported in Snort 3.

VALID OPTIONS (use only these when relevant):
  flow, content, pcre, detection_filter, classtype, priority, metadata,
  reference, service, flags, seq, ack, window, ttl, tos, id, ipopts,
  fragbits, fragoffset, dsize, offset, depth, within, distance, rawbytes,
  nocase, isdataat, byte_test, byte_jump, byte_extract,
  file_data, pkt_data, base64_decode, base64_data,
  http_client_body, http_cookie, http_header, http_method,
  http_raw_uri, http_stat_code, http_uri,
  ssl_state, ssl_version, tls_cert_subject, tls_cert_issuer,
  sid, rev, msg, gid.
"""


class RuleAgent:
    def __init__(self, llm_client, provider: str, model: str):
        self.llm_client = llm_client
        self.provider = provider
        self.model = model

    def run(
        self,
        intent: str,
        previous_rules: list[str] | None = None,
        feedback: FeedbackPayload | None = None,
    ) -> RuleAgentOutput:
        logger.debug(
            "Rule agent call started provider=%s model=%s previous_rule_count=%s feedback_present=%s",
            self.provider,
            self.model,
            0 if previous_rules is None else len(previous_rules),
            feedback is not None,
        )
        payload = {
            "intent": intent,
            "previous_rules": previous_rules,
            "feedback": feedback.model_dump() if feedback is not None else None,
        }
        raw_output = self.llm_client.generate(
            system_prompt=RULE_AGENT_SYSTEM_PROMPT,
            payload=payload,
            output_schema=RuleAgentOutput,
        )
        output = RuleAgentOutput.model_validate(raw_output)
        logger.debug("Rule agent call finished rule_count=%s", len(output.rules))
        return output

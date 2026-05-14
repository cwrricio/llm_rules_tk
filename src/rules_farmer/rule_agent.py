from __future__ import annotations

import logging

from rules_farmer.schemas import FeedbackPayload, RuleAgentOutput


logger = logging.getLogger(__name__)


RULE_AGENT_SYSTEM_PROMPT = """You generate Snort 3.9.7.0 IDS rules for a research testbed.

MANDATORY:
- sid:0; is always the SID placeholder. A SID Manager assigns real SIDs later.
- rev:1; on first iteration. Increment rev on each revision.
- msg field must contain the operator intent verbatim.
- If the intent is ambiguous, produce multiple rules rather than one best guess.
- Prefer simple syntactically valid rules first. Add payload-specific rules only when justified.

SNORT 3 RULE FORMAT:
- Rule format:
  action proto src_ip src_port direction dst_ip dst_port (options;)
- Every full rule option ends with a semicolon inside parentheses.
- Some options have comma-separated sub-options.

SNORT 3 CONTENT MODIFIER SYNTAX:
- Content modifiers are written inside the same content option, comma-separated.
- Correct:
  content:"RTPS",nocase;
  content:"|52 54 50 53|",offset 0,depth 4;
  content:"RTPS",offset 0,depth 4,nocase;
- Wrong:
  content:"RTPS"; nocase;
  content:"RTPS"; offset:0; depth:4;
- Do not emit standalone nocase, offset, depth, within, or distance.

RAW PACKET DATA:
- rawbytes is Snort 2 syntax and is forbidden.
- In Snort 3, use raw_data; when raw packet data is explicitly needed.
- Most UDP payload rules do not need raw_data unless the validator/testbed requires it.

DETECTION FILTER:
- Use:
  detection_filter:track by_src, count N, seconds S;
- Do not use threshold.

FORBIDDEN KEYWORDS:
- rawbytes
- threshold
- uricontent
- resp
- react
- tag

FORBIDDEN COMBINATIONS:
- flow:stateless combined with any other flow option is invalid.
- For UDP, usually omit flow entirely.
- If stateless is needed, use only:
  flow:stateless;

VALID COMMON OPTIONS:
  flow, content, pcre, detection_filter, classtype, priority, metadata,
  reference, service, flags, seq, ack, window, ttl, tos, id, ipopts,
  fragbits, fragoffset, dsize, offset, depth, within, distance,
  raw_data, pkt_data, nocase, isdataat, byte_test, byte_jump, byte_extract,
  file_data, base64_decode, base64_data,
  http_client_body, http_cookie, http_header, http_method,
  http_raw_uri, http_stat_code, http_uri,
  ssl_state, ssl_version, tls_cert_subject, tls_cert_issuer,
  sid, rev, msg, gid.

IMPORTANT:
- Even though nocase, offset, depth, within, and distance are listed as valid concepts, they must be emitted as content modifiers, not standalone rule options.
- Output only rules compatible with Snort 3.9.7.0.
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

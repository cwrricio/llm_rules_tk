---
name: snort-rule-generation
description: Generate Snort 3.9.7.0 IDS rules from a natural-language operator intent. Use whenever you need to write a new rule, refine an existing one, or recover from a syntax error.
metadata:
  snort_version: "3.9.7.0"
---

# Snort Rule Generation

Use this skill to author Snort 3.9.7.0 rules that the Rules Farmer testbed will deploy against the live IDS.

## ⚠️ HARD CONSTRAINT — RULE HEADER

**THE RULE HEADER MUST BE EXACTLY `any any -> any any`.**

- **DO NOT** include a source IP, source port, destination IP, or destination port in the header.
- Use the form: `alert <proto> any any -> any any (options;)`
- All targeting (destination port, protocol-specific markers, payload shape) MUST live INSIDE the
  rule options — never in the header.
- Rules that bake an IP or port into the header will be REJECTED by the validator.
- Examples:
  - ✅ `alert udp any any -> any any (msg:"…"; dsize:>1000; sid:0; rev:1;)`
  - ❌ `alert udp any any -> 192.168.137.1 8888 (msg:"…"; sid:0; rev:1;)`
  - ❌ `alert tcp any any -> any 1883 (msg:"…"; sid:0; rev:1;)`
  - ❌ `alert udp 10.0.0.0/8 any -> any any (msg:"…"; sid:0; rev:1;)`

This rule applies to EVERY attack family (MQTT, XRCE-DDS, anything else).

## When to Use

- The operator has stated an intent and no rule has been generated yet.
- The current deployed rule failed to detect an attack and you need a refined version.
- A previous rule was rejected by `validate_rule_syntax` and you must regenerate.

## Mandatory Behavior

- The rule header MUST be `<action> <proto> any any -> any any` (see HARD CONSTRAINT above).
- Always emit `sid:0;` as a placeholder. The `assign_sid` tool replaces it with a real SID before deployment.
- Always set `rev:1;` on the first iteration. Increment `rev` on every regeneration of the same logical rule.
- The `msg` field MUST contain the operator intent verbatim — this is how downstream tooling correlates alerts with intents.
- Prefer simple, syntactically valid rules first. Add payload-specific matching only when the simple version fails.
- When the intent is ambiguous, produce multiple rules instead of one best guess.

## Process

1. Parse the operator intent to extract: target IP, target port, protocol, attack class, and any payload hints.
2. Choose the simplest Snort 3 rule that captures the intent.
3. Format it according to the Snort 3.9.7.0 grammar in `references/snort3-syntax-cheatsheet.md`.
4. If you have prior feedback (container_stderr, ids_logs, validation_error), incorporate it into your revision.
5. Return one or more candidate rules.

## References

- `references/snort3-syntax-cheatsheet.md` — Complete syntax reference for Snort 3.9.7.0 (mandatory read before writing your first rule).
- `references/common-rule-patterns.md` — Worked examples for common attack classes (DoS, scan, payload match).

## Output Format

Return rule strings ready for `validate_rule_syntax`. Each rule is a single line of the form:

```
action proto src_ip src_port direction dst_ip dst_port (options;)
```

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

## ⛔ ANTI-PATTERN: Generic Rate-Only Rules

**A rule that uses only `detection_filter` without protocol-specific payload matching is FORBIDDEN as a first attempt.**

Generic rate-based rules like the example below MUST NOT be generated:

```
# FORBIDDEN — fires on any UDP traffic, causes massive false positives:
alert udp any any -> any any (msg:"..."; detection_filter:track by_dst, count 2, seconds 60; sid:0; rev:1;)
```

Why this is wrong:
- `track by_dst` groups ALL UDP packets to the server, not just attack traffic — any legitimate client triggers it.
- `count 2` in 60 seconds fires on virtually any service interaction.
- No content matching means it fires on completely unrelated UDP traffic.
- It does not capture any characteristic of the actual attack being detected.

`detection_filter` is a supplementary mechanism. It MUST be combined with payload or protocol-specific matchers that anchor the rule to the attack being detected.

## ⚠️ FALSE POSITIVE PREVENTION

Before emitting any rule, ask: "Would this rule fire on legitimate traffic from a real client using this protocol?"

If yes, the rule is too generic. Add specificity through:
- **Protocol fingerprint** (`content:"|52 54 50 53|"` for RTPS, `content:"|10|"` for MQTT CONNECT, etc.)
- **Behavioral signature** (combination of message type, size range, and rate that is only plausible during the attack)
- **Rate by source** (`detection_filter:track by_src`) — a single client sending 500,000 packets is the attack, not the service receiving them

### Critical false-positive traps to AVOID

1. **Bidirectional rules** (`<>` direction): the rule `alert udp any any <> any any` catches BOTH outgoing attack packets AND incoming server responses. A server responding to 500,000 pings will also generate 500,000 response packets — the rule fires on both sides. **Always use `->` (unidirectional).**

2. **Overly broad dsize ranges**: `dsize:100<>400` matches ALL UDP packets between 100 and 400 bytes. Normal protocol handshakes, keepalives, and acknowledgments often fall in this range. Use dsize as a SECONDARY filter combined with a content/pcre anchor, never alone.

3. **Generic content matches**: `content:"xml"` fires on every XRCE-DDS packet that uses XML-mode encoding (normal operation). `content:"create"` fires on any DDS CREATE operation. Use binary submessage type bytes or protocol-specific multi-byte sequences instead.

4. **Low detection_filter thresholds**: `detection_filter:track by_src, count 1, seconds 10` fires on any single matching packet from a host. A legitimate client can easily send one packet per 10 seconds. Use counts that are genuinely anomalous (e.g., 50+ per second for DoS, 5+ entity creations in 30 seconds for flood attacks).

5. **Missing payload anchor**: A rule with only `detection_filter` and no content/dsize/pcre fires on literally any traffic of that protocol type. This is ALWAYS wrong.

## MANDATORY VALIDATION FLOW

After writing a rule, follow this exact sequence — no steps may be skipped:

```
1. validate_rule_syntax(rule)
2. assign_sid(intent, rule)           → get SID
3. deploy_rule(rule_with_sid)         → push to IDS
4. run_benign_traffic(protocol, sid)  → FALSE POSITIVE CHECK
   ├─ false_positive=True  → DISCARD rule. Generate a more specific rule. Go back to step 1.
   └─ false_positive=False → rule passed benign check. Proceed.
5. trigger_attacker(intent, rule, sid, ...)
6. check_alert_fired(sid)
7. record_iteration(...)
```

**Step 4 is NOT optional.** A rule that fires on legitimate traffic is scientifically invalid and must be discarded before being tested against an attack. The `run_benign_traffic` tool also clears the alert log automatically, so the subsequent `check_alert_fired` call will reflect only the real attack.

Protocol mapping for `run_benign_traffic`:
- XRCE-DDS attacks → `protocol="xrce"`
- MQTT attacks → `protocol="mqtt"`
- HTTP attacks → `protocol="http"`

## Mandatory Behavior

- The rule header MUST be `<action> <proto> any any -> any any` (see HARD CONSTRAINT above).
- Always emit `sid:0;` as a placeholder. The `assign_sid` tool replaces it with a real SID before deployment.
- Always set `rev:1;` on the first iteration. Increment `rev` on every regeneration of the same logical rule.
- The `msg` field MUST contain the operator intent verbatim — this is how downstream tooling correlates alerts with intents.
- The **first rule for any known attack family MUST contain at least one protocol-specific content or pcre match** derived from the attack's payload structure. Pure rate-based rules are only acceptable as a last resort after payload-matched rules have been exhausted.
- When the intent is ambiguous, produce multiple rules instead of one best guess.

## Process

1. Load the per-attack refinement playbook (`get_skill_instructions("<attack_id>")`) BEFORE writing any rule. Extract the protocol fingerprint and detection hypotheses from section 2 (Hipóteses de Detecção).
2. Parse the operator intent to extract: protocol, attack class, payload characteristics, and behavioral patterns.
3. Build a rule that combines:
   a. A **protocol-specific payload match** (content bytes, pcre, dsize range) that identifies this attack's traffic structure.
   b. A **rate or behavioral filter** (`detection_filter:track by_src`) calibrated so legitimate single clients do not trigger it.
4. Format it according to the Snort 3.9.7.0 grammar in `references/snort3-syntax-cheatsheet.md`.
5. If you have prior feedback (container_stderr, ids_logs, validation_error), incorporate it into your revision.
6. Follow the MANDATORY VALIDATION FLOW above before calling trigger_attacker.
7. Return one or more candidate rules.

## Output Format

Return rule strings ready for `validate_rule_syntax`. Each rule is a single line of the form:

```
action proto src_ip src_port direction dst_ip dst_port (options;)
```

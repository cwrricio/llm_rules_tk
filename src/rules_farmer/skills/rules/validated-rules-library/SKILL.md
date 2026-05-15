---
name: validated-rules-library
description: Reuse Snort rules that already fired in past experiments. ALWAYS consult this skill at the start of every cycle BEFORE writing a new rule. Validated rules are known-good detection patterns persisted per attack_id under data/validated_rules/.
metadata:
  load_order: first
---

# Validated Rules Library

The testbed maintains a persistent library of Snort rules that already produced an IDS alert
(`fired=True`) in earlier experiments. These rules are known-good for their attack family. Before
spending budget on a brand-new rule, ALWAYS try a validated one first.

## When to Use

- At the very beginning of EVERY variant cycle (base and variant_N).
- Immediately after the orchestrator hands you the cycle payload.
- Before invoking `validate_rule_syntax` for the first time in the cycle.

This applies to ALL attacks. There are no exceptions.

## Process

1. Identify the `attack_id` you will execute this cycle. For base cycles, infer it from the
   operator intent (e.g. intent `"quero gerar regras xrce-dds-udp-dos"` ⇒ attack_id
   `xrce-dds-udp-dos`). For variant cycles, reuse the previous iteration's `attack_id`.
2. Call `get_validated_rules(attack_id)`. The tool returns a list of canonicalized rules
   (`sid:0;`, `rev:1;`). The most recent additions are at the END of the list.
3. If the list is non-empty:
   - Pick the LAST rule first (most recently validated).
   - Run it through `validate_rule_syntax` → `assign_sid` → `deploy_rule` → `trigger_attacker` →
     `check_alert_fired` exactly like a freshly generated rule.
   - If it fires, record the iteration and you're done for this cycle.
   - If it does NOT fire (the variant evades it), move on to the next-most-recent validated rule.
4. If you exhaust the validated rules without firing, THEN fall back to generating a new rule
   using the `snort-rule-generation` skill and the matching per-attack refinement playbook.
5. When a NEW rule fires, `record_iteration(fired=True, rule=...)` automatically appends it to
   the validated library. You do not need to call any extra tool.

## Hard Constraints (carried from snort-rule-generation)

- Every rule MUST use the header `<action> <proto> any any -> any any` — no IPs, no ports.
- Validated rules in the library are already stored in this form. Do NOT add a destination IP
  or port when re-deploying a validated rule.
- Always reset `sid:` to `0` and `rev:` to `1` before validating. `assign_sid` will replace the
  zero with a fresh unique SID.

## Why This Skill Exists

- **Convergence speed**: re-using a working rule short-circuits the regeneration loop.
- **Cross-experiment learning**: the agent that runs tomorrow benefits from rules validated today.
- **Variant evaluation**: testing an already-validated rule against a new variant is the cleanest
  signal that the variant truly evades detection.

---
name: evasion-variants
description: How to produce an evasion variant of a previously successful attack. Use this when request_variant=True on the attacker request.
---

# Evasion Variants

When the Rules Agent has already deployed a rule that detected the previous attack, it asks the Attack Agent for a VARIANT — an attempt to bypass that rule without leaving the operator intent.

## When to Use

- `request_variant=True` on the AttackerRequest.
- `variant_history` contains at least one attack with `fired=True`.

## Goal

Stay within the operator intent (same protocol, same target, same attack class), but mutate one or more arguments so the deployed rule fails to match.

## Mutation Strategies

See `references/evasion-patterns.md` for a catalogued list. Common levers:

- **Rate**: drop below `detection_filter` thresholds; or burst above them.
- **Source port**: rotate ephemeral ports.
- **Payload size**: vary `dsize`-relevant lengths.
- **Encoding**: change between binary/text/base64 if the attack accepts the choice.
- **Timing**: introduce delays that defeat time-bucket detection_filters.

## Process

1. Read the previously fired rule (provided in the AttackerRequest) to identify what the rule matches on.
2. Pick the mutation strategy that defeats the matcher without violating the intent.
3. Set `evasion_rationale` to a one-line explanation of WHY this mutation should evade the rule.
4. Call `execute_attack` with the new arguments.
5. The Rules Agent will check whether the rule fires. If it does, the variant failed (the attacker is supposed to evade). If it does not fire, the variant succeeded and the Rules Agent will refine its rule.

## Do NOT

- Switch `attack_id` between variants of the same intent — same intent must use the same attack class.
- Violate the `required_arguments` schema — mutate VALUES, not the argument list shape.

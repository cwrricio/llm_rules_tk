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

Stay within the operator intent (same protocol, same target, same attack class), but mutate the attack so the deployed rule fails to match.

## Step 1 — Load the Attack-Specific Playbook

Before attempting any mutation, call:

```
get_skill_reference("<attack_id>", "refinamento.md")
```

This loads three things for the specific attack family:
- **Detection hypotheses** — what each rule variant is likely detecting.
- **Evasion catalogue** — three concrete mutation strategies per hypothesis (obfuscação / fragmentação-timing / context shifting).
- **Adaptation algorithm** — maps the fired rule's detection mechanism to the correct mutation strategy.

Use the adaptation algorithm to decide WHICH mutation to apply before choosing a level.

## Step 2 — Choose a Mutation Level

### Level 1: Argument Mutation (preferred)

If the attack exposes non-destination parameters (rate, count, payload size, timing, source port, etc.), mutate those values.

Common levers:
- **Rate**: drop below `detection_filter` thresholds or burst above them.
- **Source port**: rotate ephemeral ports.
- **Payload size**: vary `dsize`-relevant lengths.
- **Encoding**: change between binary/text/base64 if the attack accepts the choice.
- **Timing**: introduce delays that defeat time-bucket detection_filters.

Set `evasion_rationale` to a one-line explanation of WHY this mutation should evade the rule, then call `execute_attack` with the new arguments.

### Level 2: File + Rebuild Mutation (when Level 1 is structurally impossible)

When the attack exposes **only destination-fixed arguments** (target + port) and no other parameters exist, argument mutation cannot produce a variant. You MUST modify the attack source files on the attacker host and rebuild the Docker image.

**Steps:**

1. Call `list_attack_files(attack_id)` to discover the actual filenames in the attack directory — NEVER guess. Then call `read_attack_source_file(attack_id, filename)` to inspect the relevant source file (typically the `.c` or `.py` file, not the Dockerfile or entrypoint).
2. Pick the mutation strategy from the playbook loaded in Step 1 (obfuscação / fragmentação-timing / context shifting) that defeats the fired rule's detection mechanism.
3. Produce the mutated file content implementing that strategy.
4. Call `modify_attack_file(attack_id, filename, new_content)` to write it to the attacker host.
5. Call `rebuild_attack_image(attack_id)` to rebuild the Docker image. Verify `exit_code == 0` before proceeding.
6. Call `execute_attack(attack_id, arguments)` as usual — the container now runs the mutated code.

Set `evasion_rationale` to a one-line explanation of the strategy applied and the rule mechanism it targets.

## Do NOT

- Switch `attack_id` between variants of the same intent — same intent must use the same attack class.
- Violate the `required_arguments` schema — mutate VALUES (Level 1) or internal source logic (Level 2), not the argument list shape.
- Mutate `fixed_destination_ip` or `fixed_destination_port` across variants.
- Call `execute_attack` without rebuilding first if you modified source files.
- Skip loading `refinamento.md` — without the adaptation algorithm you will repeat defeated strategies.

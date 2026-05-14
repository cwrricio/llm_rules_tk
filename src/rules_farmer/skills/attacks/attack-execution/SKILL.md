---
name: attack-execution
description: How to execute the selected attack container on the attacker host and interpret the result.
---

# Attack Execution

Use this skill after `attack-selection` has produced a concrete `attack_id` and ordered `arguments` list. Execution runs the attack Docker container on the attacker host.

## Tool

```
execute_attack(attack_id: str, arguments: list[str]) -> {
    "attack_id", "arguments",
    "container_exit_code", "container_stderr"
} | {"error": "..."}
```

## Pre-Execution Checks

- `arguments` must have the same length as the `required_arguments` list from `read_attack_definition`.
- `attack_id` must be one of those returned by `list_available_attacks`.

If either check fails, `execute_attack` returns `{"error": "..."}` — fix the input and call again, do not return the error to the parent.

## Interpreting the Result

| Field | Meaning |
|---|---|
| `container_exit_code` | 0 = attack ran cleanly; non-zero = attack errored |
| `container_stderr` | Container stderr output — useful for diagnosing setup errors and as feedback for rule refinement |

## Variant Calls

When `request_variant=True` was set by the caller, you MUST vary the arguments from previous attempts in `variant_history`. Use the `evasion-variants` skill to choose how to mutate.

The destination IP and port for the attack are FIXED by config and provided in the AttackerRequest as `fixed_destination_ip` and `fixed_destination_port`. NEVER mutate these values when producing variants — only mutate other parameters (rate, payload size, source port, timing).

## Failure Modes

- `error: argument count mismatch` — recompute arguments using `read_attack_definition.required_arguments`.
- `error: unknown attack_id` — your selection in `attack-selection` was wrong; pick a real `attack_id`.
- `container_exit_code != 0` — the attack container errored. Mention this clearly in `evasion_rationale` so the Rules Agent does not loop on rule changes for a broken attack.

---
name: attack-selection
description: How to map an operator intent to one of the attacks discovered on the attacker host. Use this before calling execute_attack.
---

# Attack Selection

The attacker host exposes a catalog of attacks discovered at startup (each one is a directory under `attacker_attacks_root` with a `README.md`, `Dockerfile`, and `entrypoint.sh`). Your job is to pick the right one for the intent.

## Tools

- `list_available_attacks() -> list[{attack_id, description, required_arguments}]` — quick browse of every available attack.
- `read_attack_definition(attack_id) -> {attack_id, description, docker_image, required_arguments, readme_excerpt}` — full definition of a single attack including the README excerpt.

## Process

1. Always call `list_available_attacks` first to confirm the catalog.
2. Match the operator intent to the closest `attack_id` based on description and required arguments. Mention IPs, ports, protocols, and attack class in your reasoning.
3. Call `read_attack_definition(attack_id)` for the candidate to inspect the README and required argument names.
4. If no candidate is a defensible match, choose the closest one anyway and explain the mismatch in `evasion_rationale`. The deterministic guardrail in the agent will raise if the `attack_id` is unknown — never invent an attack_id.

## Argument Ordering

The `required_arguments` field returns a list of NAMES (e.g. `["target_ip", "target_port", "rate"]`). You must produce a list of VALUES in the same order. Wrong order silently breaks the attack.

## Multiple Reasonable Candidates

If two attacks could match the intent (e.g. both target the same protocol but differ in payload), choose the one whose `required_arguments` are best determined by the intent. Explain the choice in `evasion_rationale`.

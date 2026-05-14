---
name: mqtt-lwt-abuse
description: "Rule-generation refinement playbook for MQTT LWT Abuse — abuse of MQTT Last Will and Testament to publish malicious payloads under the broker's trusted identity. Load when the operator intent maps to attack_id mqtt-lwt-abuse."
---

# MQTT LWT Abuse — Rule Refinement Playbook

Load this skill whenever the operator intent maps to the `mqtt-lwt-abuse` attack. It contains:

- **Detection hypotheses** ranked by severity, each describing what an IDS should look for.
- **Evasion variants catalogue** — for each hypothesis, three transformation strategies (obfuscation / fragmentation-timing / context-shifting) an attacker can use to bypass naive rules.
- **Adaptation algorithm** mapping observed IDS feedback to the specific evasion strategy to try next.

The full playbook is in `references/refinamento.md` (Portuguese). Use
`get_skill_reference("mqtt-lwt-abuse", "refinamento.md")` to load it before producing your first rule for this attack family.

## Why It Matters

A first-pass Snort rule for `mqtt-lwt-abuse` (e.g. a rate-based detection_filter on the destination port)
typically catches only the most naive variant. The playbook describes the specific mutations an
attacker would apply against each detection hypothesis, letting you write rules that anticipate
evasion variants instead of being defeated by the second one.

## How to Use During Rule Generation

1. Identify the operator intent's `attack_id`.
2. If it matches one of the slugs in the references skill set, call
   `get_skill_instructions("mqtt-lwt-abuse")` to load this overview.
3. Call `get_skill_reference("mqtt-lwt-abuse", "refinamento.md")` to load the full hypothesis catalogue.
4. Select two or three detection hypotheses with the highest severity and write rules that defeat
   the corresponding evasion strategies.
5. After the first attack, if `fired=False`, re-read the adaptation algorithm section to choose a
   refined rule that closes the gap revealed by the evasion variant.

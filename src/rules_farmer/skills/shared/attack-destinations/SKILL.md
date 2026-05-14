---
name: attack-destinations
description: Hard rule about fixed attack destinations (IP and port). Read this before generating rules or planning attacks.
---

# Attack Destinations Are Fixed

The Rules Farmer testbed exposes target services at well-known addresses per protocol family.
These are configured in `config.yaml` under `attack_destinations` and resolved by intent
preprocessing before the agents are invoked.

| Family | IP | Port |
|---|---|---|
| MQTT  | (from config: attack_destinations.mqtt.ip)  | 1883 |
| XRCE-DDS | (from config: attack_destinations.xrce.ip) | 8888 |

The Orchestrator detects the family by scanning the intent for keywords (`mqtt`, `xrce`, `dds`,
`rtps`) and injects the resolved `{ip, port}` into the prompt as `fixed_destination` and into the
AttackerRequest as `fixed_destination_ip`/`fixed_destination_port`.

## What This Means for the Rules Agent

When you write the Snort rule, the destination part of the rule header MUST match the fixed
destination:

```
alert <proto> any any -> <fixed_destination_ip> <fixed_destination_port> (... msg ...; sid:0; rev:1;)
```

Never invent a different IP or port. Never use `any` when a concrete fixed value is available.

## What This Means for the Attack Agent

When you select an attack with `port` (or `target_ip`, `target`, `host`, `broker`) as a required
argument, you MUST set that argument to the fixed value from the request:

- `required_arguments` contains `target_ip` → use `fixed_destination_ip`.
- `required_arguments` contains `port`, `target_port`, or `broker_port` → use `fixed_destination_port`.

When `request_variant=True`, mutate ONLY the other parameters (rate, payload size, source port,
timing, count, encoding). The destination IP and port stay constant across the base attack and
every variant.

## Why

If the agent mutates the destination, the attack lands somewhere other than the testbed's target
service. The IDS sees nothing because no traffic reaches the protected port, and the experiment
silently looks like a successful detection failure when in reality the attack never happened.
This skill exists to prevent that whole class of silent bugs.

## When Family Cannot Be Determined

If `fixed_destination` is `null` in the prompt (the intent did not match a known family
keyword), fall back to the destination IP and port mentioned in the intent text itself. Log a
warning. Prefer asking the operator to clarify rather than guessing.

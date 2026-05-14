---
name: experiment-cycle
description: The shared protocol for one variant cycle in a Rules Farmer experiment. Read this before starting any cycle.
---

# Experiment Cycle Protocol

This skill documents the contract between the Rules Agent, the Attack Agent, and the Orchestrator.

## Roles

- **Operator** — provides the natural-language intent ("Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888").
- **Orchestrator** — owns the outer loop. Runs `variant_count + 1` cycles (one base + N variants). Initializes/finalizes the experiment record.
- **Rules Agent** — drives ONE cycle. Generates rule(s), validates, deploys, triggers the attacker, checks the alert, records, decides convergence for the cycle.
- **Attack Agent** — picks a discovered attack and executes it. On variant cycles, mutates arguments to evade the deployed rule.

## Cycle States

```
base cycle (variant_label="base"):
  - Rules Agent generates rule for intent
  - Validates -> deploys
  - Asks Attack Agent to execute (request_variant=False)
  - Checks alert -> if not fired, regenerates rule and retries (up to max_internal_attempts)
  - Returns IterationResult(fired=True) on success
  - Orchestrator advances to variant_1

variant_N cycle (variant_label="variant_N"):
  - Rules Agent receives previous_iterations with prior cycle's final_rule
  - It MAY keep the same rule and just ask for a variant attack, OR refine
  - Asks Attack Agent to execute (request_variant=True)
  - Same convergence check
  - Returns IterationResult(fired=True) on success
  - Orchestrator advances to variant_(N+1)
```

## Termination

- All `variant_count + 1` cycles return `fired=True` → experiment converged.
- Any cycle returns `fired=False` after exhausting `max_internal_attempts` → experiment failed.

## Recording

Both agents persist their work via the orchestrator's `ExperimentRecorder`:

- The Rules Agent calls `record_iteration` after each attack execution.
- The Orchestrator finalizes `experiment.json` and `metrics.csv` after the outer loop ends (success or failure).

## Skills Shared Between Agents

- `experiment-cycle` (this skill) — both agents must understand the protocol.
- Other skills are agent-specific (rules / attacks).

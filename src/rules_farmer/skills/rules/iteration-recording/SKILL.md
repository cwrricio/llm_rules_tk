---
name: iteration-recording
description: How and when to persist a rule attempt to the experiment record (metrics.csv and experiment.json).
---

# Iteration Recording

Use this skill after every attack execution within the current variant cycle. The orchestrator owns the experiment ID and the variant label; you only pass the per-attempt details.

## Tool

```
record_iteration(
    iteration: int,
    attack_id: str,
    arguments: list[str],
    fired: bool,
    evasion_rationale: str,
    rule: str,
    container_exit_code: int | None = None,
    container_stderr: str = "",
) -> "recorded"
```

## When to Call

**MANDATORY: call `record_iteration` after EVERY `trigger_attacker` + `check_alert_fired` pair,
regardless of whether `fired` is True or False.** Skipping a call because the rule did not fire
is a data-loss bug — failed attempts are the most valuable rows for analysis.

- Pass `iteration` as the attempt number within the current variant cycle (start at 1, increment for each rule regeneration attempt).
- `fired` must reflect the result of `check_alert_fired` — pass `False` when the rule did not fire.
- `rule` must be the rule that was deployed for this attempt (post-`assign_sid`).
- Copy `container_exit_code` and `container_stderr` from the `trigger_attacker` return value.

## Why It Matters

The orchestrator can crash, the SSH session can drop, the LLM can run out of budget. Every recorded iteration is a row in `metrics.csv` and an entry in `experiment.json` — partial records are still useful for analysis. Always record before returning.

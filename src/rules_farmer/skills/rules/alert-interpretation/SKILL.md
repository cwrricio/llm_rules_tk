---
name: alert-interpretation
description: How to check the IDS alert log after an attack and decide whether the rule converged or needs refinement.
---

# Alert Interpretation

Use this skill immediately after `trigger_attacker` returns. The alert log is read from `ids_alert_log_path` on the IDS host.

## Tool

`check_alert_fired(sid: int) -> bool`

Returns:

- `True` — at least one alert for the given SID is present in the log.
- `False` — no alert for this SID was found.

## Process

1. Pass the SID returned by `assign_sid` (NOT the placeholder `0`).
2. If `True`, the variant cycle has converged for this attack. Record the iteration with `fired=True`, populate `final_rule` and `final_sid` on your `IterationResult`, and return.
3. If `False`, the rule failed to detect the attack. You must regenerate:
   - Inspect the `container_exit_code` and `container_stderr` — if the attack container errored, the issue is the attack arguments, not the rule.
   - Apply `snort-rule-generation` again with the feedback embedded in your reasoning, bump `rev`, validate, and redeploy.

## Common Failure Modes

| Symptom | Likely Cause | Fix |
|---|---|---|
| `fired=False`, container_exit_code=0 | Rule matcher is too narrow | Broaden matching options, drop overly specific content matches, lower detection_filter threshold |
| `fired=False`, container_exit_code != 0 | Attack container failed | Look at container_stderr; record diagnosis but do not infinite-loop on rule changes |

## Budget Awareness

If `max_internal_attempts` is exhausted and `fired=False`, return `IterationResult(fired=False, diagnosis="attempts-exhausted")` so the orchestrator can fail the experiment.

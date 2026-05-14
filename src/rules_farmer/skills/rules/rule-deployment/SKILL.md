---
name: rule-deployment
description: How to assign a SID and deploy a validated Snort rule to the live IDS via the assign_sid and deploy_rule tools.
---

# Rule Deployment

Use this skill after `rule-validation-workflow` returns `VALID` for a candidate rule.

## When to Use

- A rule has passed syntax validation.
- You are about to trigger the attacker and need the rule active in the IDS.

## Tools

- `assign_sid(intent: str, rule: str) -> {"sid": int, "rule": "<rule with real SID>"}` — replaces the `sid:0;` placeholder with a real, unique SID. Returns the SID number (you MUST remember it for `check_alert_fired`) and the rewritten rule.
- `deploy_rule(rule_with_sid: str) -> "DEPLOYED"` — writes the rule to the IDS rules file, ensures the include statement is present, and restarts the Snort container.

## Process

1. Call `assign_sid(intent, rule)` with the validated rule.
2. Capture the returned `sid` — you will pass it to `check_alert_fired` later.
3. Call `deploy_rule(rule_with_sid)` with the rewritten rule.
4. On success, `deploy_rule` returns `"DEPLOYED"`. Move on to `trigger_attacker`.
5. On failure, `deploy_rule` raises `IDSReloadError`. This means the Snort container did not come back to healthy state — you cannot recover from this within the agent. Return `IterationResult(fired=False, diagnosis="ids-reload-failed: <message>")`.

## Single Rule per Cycle

Within one variant cycle you may regenerate rules multiple times, but only ONE rule is deployed at a time. Each `deploy_rule` call replaces the previous rule. Track each rule you tried in `IterationResult.rules_attempted` and the final one in `IterationResult.final_rule`.

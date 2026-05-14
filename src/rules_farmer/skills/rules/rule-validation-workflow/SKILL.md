---
name: rule-validation-workflow
description: How to validate a candidate Snort rule against the live IDS before deployment, interpret the result, and recover from syntax errors.
---

# Rule Validation Workflow

Use this skill every time you produce a candidate Snort rule. Validation runs `snort -T` inside the IDS container via SSH, so it catches real syntax errors before deployment reloads the engine.

## When to Use

- Immediately after emitting a candidate rule from `snort-rule-generation`.
- Before calling `assign_sid` and `deploy_rule`.

## Tool

`validate_rule_syntax(rule: str) -> str`

Returns one of:

- `"VALID"` — syntax accepted. You may proceed to `assign_sid`.
- `"INVALID: <error>"` — syntax rejected. You MUST regenerate before deployment.

## Process

1. Pass the rule string exactly as produced (with `sid:0;` placeholder).
2. If `VALID`, proceed.
3. If `INVALID`, read the error message carefully. The most common causes are:
   - Snort 2 keywords leaking in (`rawbytes`, `threshold`, `uricontent`, `resp`, `react`, `tag`)
   - Standalone content modifiers (`nocase`, `offset`, `depth`) that should be comma-separated inside the `content` option
   - `flow:stateless` combined with another flow option
   - Missing semicolons inside the option list
   - Unbalanced parentheses or quotes
4. Apply the fix indicated by the error, bump `rev`, and call `validate_rule_syntax` again on the corrected rule.
5. Track every rule you attempted in your final `IterationResult.rules_attempted`.

## Budget

You have at most `max_internal_attempts` regenerations per variant cycle. Spend them on real refinement, not on retries of identical syntax. If you exhaust the budget with only syntax errors, return `IterationResult(fired=False, diagnosis="syntax-budget-exhausted: <last error>")`.

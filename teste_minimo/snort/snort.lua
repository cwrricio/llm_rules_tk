-- Minimal Snort 3 configuration for the self-contained teste mínimo.
--
-- Mirrors the essentials of the real testbed's snort.lua (HOME_NET/EXTERNAL_NET
-- 'any', an ips block that includes the rules tree, and alert_fast to file), but
-- keeps only what the deterministic detection check needs. The generated rule is
-- deployed by the real IDSRuleInjector into rules/temp/rules_farmer_ai.rules,
-- which is pulled in via rules/all.rules below.
--
-- Includes use absolute in-container paths (/etc/snort/...) so that the exact
-- invocation used by SnortRuleValidator (`snort -c snort.lua -R <rule> -T`,
-- without --include-path) resolves them.

HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips =
{
    variables = { nets = { HOME_NET = HOME_NET, EXTERNAL_NET = EXTERNAL_NET } },
    rules = [[ include /etc/snort/rules/all.rules ]],
}

alert_fast = { file = true, packet = false }

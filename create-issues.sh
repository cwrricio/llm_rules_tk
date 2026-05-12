#!/bin/bash

# Create issues in dependency order (blockers first)

# 1. Project Setup (no blockers)
ISSUE_1=$(gh issue create --title "1. Project Setup" --body "## What to build

Initialize three separate FastAPI projects (Orchestrator, Attacker, IDS Management API) with proper package structure, dependency management, test infrastructure, and Agno agent framework integration.

## Acceptance Criteria

- [ ] Three FastAPI projects scaffold with basic health-check endpoints (\`GET /health\`)
- [ ] \`uv\` environment files (pyproject.toml) for each project with base dependencies
- [ ] Pytest configured with basic test template for each project
- [ ] Agno agent framework imports work without errors in test environment
- [ ] Git repo initialized with initial commit, proper .gitignore
- [ ] README documents the 4-entity topology and how to run each entity locally
- [ ] CI/CD pipeline (GitHub Actions) runs tests on PR

## Type

HITL — Requires review of initial project structure and setup decisions.

## Blocked by

None - can start immediately." --label "architecture,setup" -q)
echo "Created issue #$ISSUE_1: Project Setup"

# 2. Define Attack Skill Taxonomy (no blockers)
ISSUE_2=$(gh issue create --title "2. Define Attack Skill Taxonomy" --body "## What to build

Collaborate with domain experts to define the complete taxonomy of attack types the system should support. Document each attack category, its purpose, example attack names, and tools/techniques that fit.

## Acceptance Criteria

- [ ] Taxonomy document (attack-skill-taxonomy.md) created in docs/
- [ ] Each attack type has: name, description, use cases, example attacks, suggested tools
- [ ] Minimum 5 attack categories defined (e.g., Reconnaissance, DoS, Exploitation, Credential Attacks, Data Exfiltration)
- [ ] Cross-referenced with brainstorm.md decisions (skill structure, invocation model)
- [ ] Approved by user; used to guide future skill implementations
- [ ] Document notes any constraints (e.g., which tools require elevated privileges, which are safe for isolated testbed)

## Type

HITL — Requires domain expertise and user approval for future skill development.

## Blocked by

None - can start immediately." --label "architecture,planning" -q)
echo "Created issue #$ISSUE_2: Define Attack Skill Taxonomy"

# 3. SID Manager (no blockers)
ISSUE_3=$(gh issue create --title "3. SID Manager" --body "## What to build

Deterministic component that assigns unique SIDs to generated rules and persists the sid→intent mapping. Never trusts the LLM to generate unique SIDs; always overwrites.

## Acceptance Criteria

● Bash(gh issue list --limit 20)
  ⎿  Error: Exit code 127
     /usr/bin/bash: line 1: gh: command not found

- [ ] Counter-based assignment in range 9,000,000–9,999,999 (reserved local range per Snort docs)
- [ ] Reads/writes counter to persistent file (e.g., \`.data/sid_counter.json\`)
- [ ] \`assign_sid(intent: str) -> (sid: int, intent: str)\` — increments counter, returns SID + echoed intent
- [ ] \`persist_mapping(sid: int, intent: str)\` — appends to \`sid_mappings.json\` for later analysis
- [ ] Thread-safe (file locking or atomic writes) to prevent duplicate SIDs under concurrent calls
- [ ] SID range validation: raises \`SIDRangeExhausted\` if counter exceeds 9,999,999
- [ ] Tests: concurrent assignment (100 threads), persistence across process restarts, range validation, idempotency

## Type

AFK — Independently implementable, no external dependencies.

## Blocked by

None - can start immediately." --label "core,rule-agent" -q)
echo "Created issue #$ISSUE_3: SID Manager"

# 4. PCAP Capture (no blockers)
ISSUE_4=$(gh issue create --title "4. PCAP Capture" --body "## What to build

Utility module for capturing network packets during attack execution. Uses tcpdump to capture traffic before and after an attack window.

## Acceptance Criteria

- [ ] \`start_capture(interface: str, output_file: str) -> CaptureSession\`: Spawns \`tcpdump\` subprocess with \`-w {output_file}\` flag
- [ ] \`CaptureSession.stop() -> str\`: Terminates tcpdump, returns path to PCAP file
- [ ] \`assert_not_empty(pcap_path: str) -> bool\`: Verifies PCAP file exists and > 0 bytes
- [ ] Network interface name is configurable (default \`eth0\` on Linux, \`en0\` on macOS)
- [ ] Error handling: if tcpdump not installed, raises \`TCPDumpNotFound\`; if capture fails, raises \`CaptureFailed\`
- [ ] Tests: mock tcpdump process, verify file creation, verify cleanup on error

## Type

AFK — Independently implementable, no external dependencies.

## Blocked by

None - can start immediately." --label "core,attacker-agent" -q)
echo "Created issue #$ISSUE_4: PCAP Capture"

# 5. Experiment Recorder (no blockers)
ISSUE_5=$(gh issue create --title "5. Experiment Recorder" --body "## What to build

Persistence layer that records all experiment metadata, metrics, and artifacts (JSON + CSV).

## Acceptance Criteria

- [ ] \`record_experiment(experiment_id: str, metadata: {...}) -> ExperimentRecord\`: Creates directory, initializes experiment.json
- [ ] \`record_iteration(experiment_id: str, iteration: int, metrics: {...}, rule: str, feedback?: {...})\`: Appends to iterations.json, stores rule text and feedback
- [ ] \`finalize_experiment(experiment_id: str, converged: bool, final_rule: str) -> {json_path, csv_path}\`: Generates CSV with one row per iteration
- [ ] PCAP paths in JSON are relative to experiment directory (portable)
- [ ] Tests: verify schema correctness, PCAP path references, CSV formatting

## Type

AFK — Independently implementable, no external dependencies.

## Blocked by

None - can start immediately." --label "core,persistence" -q)
echo "Created issue #$ISSUE_5: Experiment Recorder"

# 6. IDS Management API (blocked by Project Setup)
ISSUE_6=$(gh issue create --title "6. IDS Management API" --body "## What to build

REST API wrapper on Entity 2 (IDS host) that Entity 1 calls to validate rules, inject rules, and monitor alerts.

## Acceptance Criteria

- [ ] FastAPI server runs on configurable port (default 8002)
- [ ] \`POST /validate\` accepts rule (string), calls \`snort -T\` via subprocess, returns \`{valid: bool, error?: str}\`
- [ ] \`POST /rules\` accepts rule (string) + sid (int), writes to \`ai_generated.rules\`, sends SIGHUP to Snort, returns \`{ok: bool}\`
- [ ] \`GET /alerts?sid=<int>&since=<timestamp>\` reads IDS alert log (path configurable), returns \`{fired: bool, count: int}\`
- [ ] All endpoints timeout after 30s; return 500 on subprocess failure with error details
- [ ] Tests: mock Snort subprocess calls, verify log file parsing, verify timestamps
- [ ] README documents all endpoints with curl examples

## Type

AFK — Independently implementable once Project Setup complete.

## Blocked by

#$ISSUE_1" --label "core,ids-management" -q)
echo "Created issue #$ISSUE_6: IDS Management API"

# 7. IDS Abstractions (blocked by IDS Management API)
ISSUE_7=$(gh issue create --title "7. IDS Abstractions" --body "## What to build

Abstract base classes (interfaces) for IDS interaction with Snort implementations. Allows swapping Snort for Suricata later.

## Acceptance Criteria

- [ ] \`IDSValidator\` (abstract) + \`SnortValidator\`: \`validate(rule: str) -> {valid: bool, error?: str}\`, calls IDS Management API \`/validate\`
- [ ] \`IDSInjector\` (abstract) + \`SnortInjector\`: \`inject(rule: str, sid: int) -> bool\`, calls IDS Management API \`/rules\`
- [ ] \`IDSMonitor\` (abstract) + \`SnortMonitor\`: \`__init__(log_path: str)\`, \`check_fired(sid: int, since: Timestamp) -> bool\`, calls IDS Management API \`/alerts\`
- [ ] All classes handle timeouts + network errors gracefully
- [ ] Implementations are swappable via dependency injection
- [ ] Tests: verify each implementation with mock IDS Management API

## Type

AFK — Independently implementable once IDS Management API complete.

## Blocked by

#$ISSUE_6" --label "core,ids-abstractions" -q)
echo "Created issue #$ISSUE_7: IDS Abstractions"

# 8. Rule Agent Core (blocked by SID Manager + IDS Abstractions)
ISSUE_8=$(gh issue create --title "8. Rule Agent Core" --body "## What to build

Agno agent that generates IDS rules from natural-language intent and revises them based on feedback. Uses Groq (configurable model).

## Acceptance Criteria

- [ ] Agno agent initializes with Groq model (configurable via env var \`GROQ_MODEL\`, default documented in README)
- [ ] \`generate(intent: str) -> {rule: str, sid: int, raw_rule: str}\`: Prompts Groq, calls SID Manager, validates via IDSValidator, retries up to 2x on invalid rule
- [ ] \`revise(intent: str, rule: str, feedback: {diagnosis, ids_logs, pcap_path}) -> {rule: str, sid: int}\`: Revises rule based on feedback, validates, same SID
- [ ] Injection into IDS via IDSInjector before returning
- [ ] All Groq API calls include 30s timeouts
- [ ] Tests: mock Groq responses, mock SID Manager, mock IDS validators

## Type

AFK — Independently implementable once dependencies complete.

## Blocked by

#$ISSUE_3, #$ISSUE_7" --label "core,rule-agent" -q)
echo "Created issue #$ISSUE_8: Rule Agent Core"

# 9. Rule Agent REST API (blocked by Rule Agent Core)
ISSUE_9=$(gh issue create --title "9. Rule Agent REST API" --body "## What to build

FastAPI wrapper that Orchestrator calls to generate and revise rules.

## Acceptance Criteria

- [ ] \`POST /generate\` accepts \`{intent: str}\`, calls Rule Agent Core, returns \`{rule: str, sid: int}\`
- [ ] \`POST /revise\` accepts \`{intent: str, rule: str, feedback: {diagnosis, ids_logs, pcap_path}}\`, returns \`{rule: str, sid: int}\`
- [ ] Error responses: 400 (invalid input), 500 (Groq API error), 503 (IDS unavailable)
- [ ] Server runs on configurable port (default 8001)
- [ ] Tests: mock Rule Agent Core, verify endpoint contracts

## Type

AFK — Independently implementable once Rule Agent Core complete.

## Blocked by

#$ISSUE_8" --label "core,rule-agent" -q)
echo "Created issue #$ISSUE_9: Rule Agent REST API"

# 10. Attack Skill: Reconnaissance (blocked by Define Attack Skill Taxonomy)
ISSUE_10=$(gh issue create --title "10. Attack Skill: Reconnaissance" --body "## What to build

First attack skill implementing network reconnaissance (port scanning, service discovery). Validates the skill directory structure and serves as a template for future skills.

## Acceptance Criteria

- [ ] Directory structure matches Agno standard: \`SKILL.md\`, \`scripts/main.py\`, \`references/arguments.md\`
- [ ] \`SKILL.md\` contains YAML frontmatter (\`name: attack-reconnaissance\`), \"When to Use\" section, \"How to Use\" section with examples
- [ ] \`main.py\` accepts positional args: \`python3 main.py <intent> <variant_count>\`, returns JSON: \`{fired: bool, pcap_path: str, diagnosis: str, ids_logs: str}\`
- [ ] \`references/arguments.md\` specifies arg[0]=intent, arg[1]=variant_count
- [ ] Skill is discoverable via Agno's LocalSkills loader (validate structure on load)
- [ ] Tests: mock nmap calls, verify skill structure validation
- [ ] Approved by user as template for future skills

## Type

HITL — Requires domain expertise and user approval for skill structure.

## Blocked by

#$ISSUE_2" --label "attack-skills,reconnaissance" -q)
echo "Created issue #$ISSUE_10: Attack Skill: Reconnaissance"

# 11. Attacker Agent Core (blocked by PCAP Capture + Attack Skill: Reconnaissance)
ISSUE_11=$(gh issue create --title "11. Attacker Agent Core" --body "## What to build

Agno agent that selects an appropriate attack skill based on operator intent + generated rule, invokes it, and generates feedback on failure.

## Acceptance Criteria

- [ ] Agno agent initializes with LocalSkills loader pointing to \`skills/\` directory
- [ ] \`execute_attack(intent: str, rule: str, sid: int, variant_count: int) -> {fired: bool, feedback?: {diagnosis, pcap_path, ids_logs}}\`
- [ ] Loads skills via LocalSkills, prompts Groq to choose best skill, reads REFERENCE.md, invokes \`python3 scripts/main.py\` with args
- [ ] If fired=true: returns \`{fired: true}\`; If fired=false: generates diagnosis via Groq + includes pcap_path + ids_logs
- [ ] Handles missing skills gracefully: returns structured error if intent doesn't map (satisfies US15)
- [ ] IDSMonitor integration: checks if rule fired after skill executes
- [ ] Tests: mock LocalSkills, mock Groq, mock skill subprocess calls, mock IDS Monitor

## Type

AFK — Independently implementable once dependencies complete.

## Blocked by

#$ISSUE_4, #$ISSUE_10" --label "core,attacker-agent" -q)
echo "Created issue #$ISSUE_11: Attacker Agent Core"

# 12. Attacker REST API (blocked by Attacker Agent Core)
ISSUE_12=$(gh issue create --title "12. Attacker REST API" --body "## What to build

FastAPI wrapper that Orchestrator calls to execute attacks and get results.

## Acceptance Criteria

- [ ] \`POST /attacks\` accepts \`{intent: str, rule: str, sid: int, variant_count: int}\`
- [ ] Calls Attacker Agent Core, returns \`{fired: bool, feedback?: {diagnosis, pcap_path, ids_logs}}\`
- [ ] Server runs on configurable port (default 8003)
- [ ] Error handling: 400 (invalid input), 500 (skill invocation failed), 503 (IDS unavailable)
- [ ] Tests: mock Attacker Agent Core, verify endpoint contract

## Type

AFK — Independently implementable once Attacker Agent Core complete.

## Blocked by

#$ISSUE_11" --label "core,attacker-agent" -q)
echo "Created issue #$ISSUE_12: Attacker REST API"

# 13. Orchestrator Loop (blocked by Rule Agent REST API + Attacker REST API + Experiment Recorder)
ISSUE_13=$(gh issue create --title "13. Orchestrator Loop" --body "## What to build

State machine that owns the feedback loop. Calls Rule Agent → Attacker Agent → Experiment Recorder in sequence, evaluates termination conditions.

## Acceptance Criteria

- [ ] \`ExperimentState\` dataclass: \`{experiment_id, intent, iteration: int, status, max_iterations, variant_count}\`
- [ ] \`run_experiment(intent: str, max_iterations: int, variant_count: int) -> ExperimentRecord\`
- [ ] Iteration 1: generate rule, record, execute attack, check fired, handle feedback
- [ ] Iterations 2..N: revise rule, record, execute attack, check convergence/termination
- [ ] Evaluates: converged? → finalize; max_iterations reached? → mark failed + finalize
- [ ] Handles errors: Rule Agent failure → record + mark failed; Attacker Agent failure → record + mark failed
- [ ] Configurable \`max_iterations\` (per-experiment) with global default
- [ ] Tests: mock Rule Agent + Attacker Agent APIs, simulate convergence + failure scenarios

## Type

AFK — Independently implementable once dependencies complete.

## Blocked by

#$ISSUE_9, #$ISSUE_12, #$ISSUE_5" --label "core,orchestrator" -q)
echo "Created issue #$ISSUE_13: Orchestrator Loop"

# 14. Orchestrator REST API (blocked by Orchestrator Loop)
ISSUE_14=$(gh issue create --title "14. Orchestrator REST API" --body "## What to build

Entry point for operators. Accepts experiment requests, returns experiment IDs, allows status polling.

## Acceptance Criteria

- [ ] \`POST /experiments\` accepts \`{intent: str, max_iterations?: int, variant_count?: int}\`, returns \`{experiment_id: str}\`
- [ ] Validates intent is non-empty, calls Orchestrator Loop (async/background), returns immediately with experiment_id
- [ ] \`GET /experiments/{experiment_id}\` returns \`{status: \"running\"|\"converged\"|\"failed\", result?: {json_path, csv_path}}\`
- [ ] Server runs on configurable port (default 8000)
- [ ] OpenAPI/Swagger docs available at \`/docs\`
- [ ] Tests: verify endpoint contracts, simulate async experiment execution

## Type

AFK — Independently implementable once Orchestrator Loop complete.

## Blocked by

#$ISSUE_13" --label "core,orchestrator" -q)
echo "Created issue #$ISSUE_14: Orchestrator REST API"

# 15. End-to-End Integration Tests (blocked by all components)
ISSUE_15=$(gh issue create --title "15. End-to-End Integration Tests" --body "## What to build

Full integration tests that simulate a complete experiment flow with mock agents and IDS.

## Acceptance Criteria

- [ ] Test scenario: \"Rule succeeds on first attack\" (convergence in 1 iteration)
- [ ] Test scenario: \"Rule succeeds after 2 revisions\" (convergence in 3 iterations)
- [ ] Test scenario: \"Max iterations reached without convergence\" (failure)
- [ ] Test scenario: \"Unmapped intent\" (error handling per US15)
- [ ] All scenarios verify: correct status, metrics recorded, PCAP referenced, feedback stored

## Type

AFK — Independently implementable once all components complete.

## Blocked by

#$ISSUE_14" --label "testing,integration" -q)
echo "Created issue #$ISSUE_15: End-to-End Integration Tests"

# 16. Documentation & Operating Guides (blocked by Orchestrator REST API)
ISSUE_16=$(gh issue create --title "16. Documentation & Operating Guides" --body "## What to build

End-user documentation for operators, researchers, and developers.

## Acceptance Criteria

- [ ] **OPERATING.md**: How to set up isolated testbed (network topology, Entity configuration, firewall rules)
- [ ] **QUICKSTART.md**: Run a complete example experiment from intent → result
- [ ] **API.md**: OpenAPI reference for all REST endpoints (Orchestrator, Rule Agent, Attacker, IDS Management)
- [ ] **ARCHITECTURE.md**: Deep dive on the 4-entity topology, each component's responsibility
- [ ] **SKILLS.md**: Template for creating new attack skills, step-by-step walkthrough for Reconnaissance
- [ ] **DEPLOYMENT.md**: Production deployment checklist (Groq API key setup, IDS configuration, logging)
- [ ] All docs reference CONTEXT.md for terminology

## Type

HITL — Requires review and user approval for final documentation.

## Blocked by

#$ISSUE_14" --label "documentation" -q)
echo "Created issue #$ISSUE_16: Documentation & Operating Guides"

echo ""
echo "✅ All 16 issues created successfully!"
echo ""
echo "Issue mapping:"
echo "  1. Project Setup: #$ISSUE_1"
echo "  2. Define Attack Skill Taxonomy: #$ISSUE_2"
echo "  3. SID Manager: #$ISSUE_3"
echo "  4. PCAP Capture: #$ISSUE_4"
echo "  5. Experiment Recorder: #$ISSUE_5"
echo "  6. IDS Management API: #$ISSUE_6"
echo "  7. IDS Abstractions: #$ISSUE_7"
echo "  8. Rule Agent Core: #$ISSUE_8"
echo "  9. Rule Agent REST API: #$ISSUE_9"
echo " 10. Attack Skill: Reconnaissance: #$ISSUE_10"
echo " 11. Attacker Agent Core: #$ISSUE_11"
echo " 12. Attacker REST API: #$ISSUE_12"
echo " 13. Orchestrator Loop: #$ISSUE_13"
echo " 14. Orchestrator REST API: #$ISSUE_14"
echo " 15. End-to-End Integration Tests: #$ISSUE_15"
echo " 16. Documentation & Operating Guides: #$ISSUE_16"

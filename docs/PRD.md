# PRD — Rules Farmer: Multi-Agent IDS Rule Generation and Validation System

## Problem Statement

Network operators need to maintain effective IDS rules, but writing them requires deep knowledge of rule syntax (e.g., Snort) and deep understanding of the attack patterns being defended against. When a rule is written incorrectly or incompletely, it fails silently — traffic passes without an alert. There is no automated feedback mechanism to tell the operator that the rule is wrong or how to fix it. Testing a rule against realistic attack traffic is a manual, expert-level process that rarely happens in practice.

## Solution

A multi-agent system that accepts a natural-language security intent from the operator, generates a valid IDS rule automatically, tests the rule against realistic simulated attacks, and iterates via a feedback loop until the rule either converges or exhausts the maximum number of allowed attempts. Every iteration is recorded with full metrics, enabling research into both the quality of LLM-based rule generation and the dynamics of multi-agent feedback convergence.

## User Stories

1. As a network operator, I want to submit a security intent in natural language, so that I don't need to know Snort rule syntax to protect my network.
2. As a network operator, I want to receive an experiment ID immediately after submitting my intent, so that I can track the experiment's progress asynchronously.
3. As a network operator, I want the system to automatically generate a syntactically valid IDS rule from my intent, so that invalid rules never reach the IDS.
4. As a network operator, I want the generated rule to receive a unique SID automatically, so that it never conflicts with existing rules in the IDS.
5. As a network operator, I want the generated rule to be injected into the IDS and the IDS reloaded, so that the testbed can iterate without manual intervention.
6. As a network operator, I want the Attacker Agent to automatically select and invoke the appropriate attack skill based on my stated intent, so that the rule is tested under realistic conditions without manual tool selection.
7. As a network operator, I want the attack traffic to be captured as a PCAP and made available for inspection, so that I can examine exactly what was sent during each test.
8. As a network operator, I want the system to test the rule against multiple attack variants after initial detection, so that I know the rule is not fragile against minor parameter changes.
9. As a network operator, I want to configure how many attack variants are tested per iteration, so that I can trade off thoroughness against experiment duration.
10. As a network operator, I want the system to automatically revise the rule when it fails to detect an attack, so that convergence happens without my intervention.
11. As a network operator, I want the feedback sent to the rule agent to include a packet-level summary of the attack, the IDS logs, and the attacker's evasion rationale, so that the agent has all the evidence needed to revise the rule correctly.
12. As a network operator, I want the loop to stop after a configurable maximum number of iterations if no convergence is reached, so that the experiment always terminates.
13. As a network operator, I want to know whether the experiment converged or failed, so that I can assess whether my intent was achievable within the given constraints.
14. As a network operator, I want the system to raise a structured error if my intent cannot be mapped to any available attack skill, so that the experiment fails clearly rather than executing undefined behavior.
15. As a network operator, I want to configure the IDS backend via a parameter (e.g., log file path), so that I can use the system with Snort or Suricata without modifying the codebase.
16. As a researcher, I want all four metrics (detection rate, precision+recall, iterations to convergence, structural quality) recorded for every attack execution of every experiment, so that I can analyze both research axes independently.
17. As a researcher, I want the complete generated rule set stored for each iteration, along with the Rule Agent's diagnosis, so that I can trace how the rule evolved and understand the agent's reasoning across the feedback loop.
18. As a researcher, I want all feedback payloads exchanged between agents stored, so that I can understand the agent reasoning and diagnose failure cases.
19. As a researcher, I want experiment results exported in both JSON and CSV formats, so that I can load them into Python for analysis without writing a parser.
20. As a researcher, I want PCAP files downloaded and stored locally alongside the experiment record, so that I can inspect them with Wireshark without accessing remote machines.
21. As a researcher, I want the SID-to-intent mapping to be persisted across experiments, so that I can trace any alert in the IDS back to the operator intent that produced it.

## Implementation Decisions

### Module Inventory

The system is distributed across three application entities running on separate physical machines:

**Entity 1 — Orchestrator Application**

- **Orchestrator** — Owns the feedback loop. Maintains experiment state in memory (current iteration, convergence status). Sequences calls to the Rule Agent and Attacker Agent via REST APIs. After each attack execution, downloads the PCAP from Entity 3 via `GET /pcaps/{filename}` and stores it locally. Evaluates termination conditions and triggers the Experiment Recorder. State is not persisted — if the process crashes, the experiment is lost and must be resubmitted. Both agents are stateless; the Orchestrator decides what happens next.
- **Rule Agent** — Stateless LLM agent (built with Agno). On the first call, receives the operator's intent and produces one or more candidate IDS rules. On subsequent calls, receives the operator's intent, the previous rule set, and the FeedbackPayload, and produces a revised rule set plus a diagnosis of why the previous rules failed. Delegates syntax validation to the IDS Rule Validator and injection to the IDS Rule Injector before returning to the Orchestrator.
- **SID Manager** — Deterministic component that assigns unique SIDs within the reserved local range (9,000,000–9,999,999) using a persistent counter (`sid_counter.json`). Always replaces any SID produced by the LLM. Assigns a separate SID to each rule when multiple rules are produced. Persists a `sid → intent` mapping to disk. If `sid_counter.json` is missing or corrupted at startup, raises `SIDCounterCorruptedError` and halts with recovery instructions.
- **IDS Rule Validator** — Abstract interface with a Snort implementation that calls `POST /validate` on the IDS Management API. Returns either `valid` or the raw error output (which feeds back into the Rule Agent on failure).
- **IDS Rule Injector** — Abstract interface with a Snort implementation that writes the rule set to `ai_generated.rules` via `POST /rules` on the IDS Management API, then triggers `POST /reload`. The file is cleared at the start of each experiment and overwritten (not appended) on each injection. After triggering the reload, the Orchestrator polls `GET /health` until the IDS container reports healthy before authorizing the Attacker Agent to proceed.
- **IDS Monitor** — Abstract interface that reads the IDS alert log via `GET /alerts` on the IDS Management API and checks for any alert matching the set of active SIDs. Returns `fired=True` if any rule in the current set triggered. The log file path is a configurable parameter.
- **Experiment Recorder** — Writes `results/{experiment_id}/experiment.json` (complete record: all iterations, rule sets, diagnoses, feedback payloads, PCAP paths) and `results/{experiment_id}/metrics.csv` (one row per attack execution — base attack and each variant — with columns: iteration, execution_type, catalog_entry_id, slots, fired, evasion_rationale). Raw PCAPs are stored in `results/{experiment_id}/pcaps/` after download from Entity 3.
- **Orchestrator REST API** — Exposes `POST /experiments` (submit intent, returns experiment ID) and `GET /experiments/{id}` (retrieve status or result). Returns `{ "status": "running" }` while the experiment is in progress — no partial state is exposed. Built with FastAPI.

**Entity 2 — IDS Management API**

- **IDS Management API** — A thin REST API that wraps IDS operations on its local host: rule validation (`POST /validate`), rule injection (`POST /rules`), IDS reload (`POST /reload`, executes `docker restart snort_ids`), health check (`GET /health`, polls until the Snort container is running), and alert log reading (`GET /alerts?sid=...`). This is the only component that touches IDS files and Docker directly. Built with FastAPI.

**Entity 3 — Attacker Application**

- **Attacker Agent** — Stateless LLM agent (built with Agno). Receives the operator's intent, the generated rule set, and the cumulative variant history. Selects the appropriate catalog entry, fills the slot values, and declares an evasion rationale. Generates one `AttackPlan` per call (base attack or one variant). Variant generation is incremental: each call receives the full history of previous attempts so the LLM can avoid repeating strategies that already fired or failed.
- **Attack Skill Catalog** — A collection of 10 self-contained Attack Skills (XRCE-DDS and MQTT), each packaged as a pre-configured Docker image on Entity 3. Each catalog entry defines: the Docker image name, the slot template, expected exit codes, and the stdout/stderr contract. All attacks use the Docker invocation model — there is no CLI fallback. If the operator's intent cannot be mapped to any catalog entry, the agent raises `UnmappedIntentError` and halts.
- **PCAP Capture** — Each Docker attack container captures its own traffic internally via `tcpdump` and exposes the PCAP at a known path on Entity 3's filesystem. After execution, the Attacker Agent converts the PCAP to a human-readable summary using `tshark` and returns the summary in the response. The raw PCAP filename is also returned so the Orchestrator can download it.
- **Attacker REST API** — Exposes `POST /attacks` (execute one attack — base or variant — and return the result) and `GET /pcaps/{filename}` (serve a raw PCAP file for download by the Orchestrator). Built with FastAPI.

### API Contracts

**POST /experiments (Orchestrator API)**
```
Request:  { intent: str, max_iterations?: int, variant_count?: int }
Response: { experiment_id: str }
```

**GET /experiments/{id} (Orchestrator API)**
```
Response (running):   { status: "running" }
Response (completed): { status: "converged" | "failed", result: ExperimentRecord }
```

**POST /attacks (Attacker API)**
```
Request:
  intent: str
  rule: str
  sid: int
  variant_history: list[{ slots: dict[str, str], fired: bool }]  # empty on base attack call

Response:
  fired: bool
  pcap_filename: str
  feedback?: {
    pcap_summary: str       # tshark-converted packet summary
    ids_logs: str
    evasion_rationale: str
  }
```

**GET /pcaps/{filename} (Attacker API)**
```
Response: raw PCAP file (application/octet-stream)
```

**POST /validate (IDS Management API)**
```
Request:  { rules: list[str] }
Response: { valid: bool, error?: str }
```

**POST /rules (IDS Management API)**
```
Request:  { rules: list[str], sids: list[int] }
Response: { ok: bool }
```

**POST /reload (IDS Management API)**
```
Response: { ok: bool }  # triggers docker restart snort_ids
```

**GET /health (IDS Management API)**
```
Response: { status: "running" | "starting" | "error", error_log?: str }
```

**GET /alerts (IDS Management API)**
```
Query:    ?sids=<int>,<int>&since=<timestamp>
Response: { fired: bool, count: int }
```

### Pydantic Schemas

**LLM Output Schemas** (enforced via structured output — no field outside these schemas is produced by the LLM):

```python
class RuleAgentOutput(BaseModel):
    rules: list[str]       # one or more Snort rule strings; SIDs replaced by SID Manager before injection
    diagnosis: str | None  # Rule Agent's stated reasoning for this revision; None on first iteration

class AttackPlan(BaseModel):
    catalog_entry_id: str    # must match an existing catalog entry
    slots: dict[str, str]    # values for declared variable slots only
    evasion_rationale: str   # why these parameters challenge the rule under test
```

**Deterministic Output Schemas** (assembled by deterministic code after execution):

```python
class VariantResult(BaseModel):
    slots: dict[str, str]   # slot values used in this attempt
    fired: bool             # True if any active SID matched

class FeedbackPayload(BaseModel):
    pcap_summary: str       # tshark-converted packet summary (human-readable)
    ids_logs: str           # IDS alert log content during the attack window (empty if no alerts)
    evasion_rationale: str  # Attacker Agent's pre-execution rationale for these slot choices

class AttackerAgentOutput(BaseModel):
    fired: bool                       # True if any active SID matched
    pcap_filename: str                # filename on Entity 3; downloaded by Orchestrator via GET /pcaps/{filename}
    feedback: FeedbackPayload | None  # present only when fired=False
```

### Key Architectural Decisions

- **The LLM is never responsible for system guarantees.** SID uniqueness, tool selection boundaries, variant count, and loop termination are all controlled by deterministic code. See ADR-0001 for the REST communication decision.
- **All attack tools use Docker.** Both XRCE-DDS and MQTT attacks are pre-configured Docker images on Entity 3. There is no CLI fallback. The Attacker Agent uses a single invocation model for all skills. See ADR-0002 for the Attack Skills architecture decision.
- **Multiple rules per iteration are permitted.** The Rule Agent may generate more than one Snort rule when a generic intent spans multiple attack vectors. The SID Manager assigns a unique SID to each. The IDS Monitor checks if any rule in the active set fired.
- **Variants are generated one at a time, with cumulative history.** The Orchestrator calls `POST /attacks` up to N+1 times per main iteration (once for the base attack, then once per variant). Each variant call includes the full history of all previous attempts across the entire experiment. The Orchestrator stops calling variants and sends feedback to the Rule Agent as soon as the first evasion is found — 100% detection across all variants is required for convergence.
- **PCAP is converted to a text summary before reaching the Rule Agent.** The Rule Agent is an LLM and cannot read binary PCAP directly. The Attacker Agent converts the PCAP to a human-readable summary (`tshark`) before including it in the FeedbackPayload. The raw PCAP is downloaded by the Orchestrator via HTTP and stored locally for Wireshark inspection.
- **`evasion_rationale` is included in the FeedbackPayload.** The Attacker Agent's pre-execution reasoning about which rule property it is exploiting is passed to the Rule Agent as part of every feedback cycle — not just stored as observability. This gives the Rule Agent the attacker's hypothesis alongside the packet evidence.
- **The Rule Agent's diagnosis is captured.** `RuleAgentOutput` includes `diagnosis: str | None` — the Rule Agent's stated reasoning for its revision. This is recorded in the Experiment Record and enables qualitative analysis of agent reasoning.
- **`ai_generated.rules` is overwritten on each injection.** The file is cleared at the start of each experiment and overwritten (not appended) on each new injection. Exactly one rule set is active at any time. This prevents alert noise from previous iterations contaminating the IDS logs passed to the Rule Agent.
- **IDS reload is confirmed via health check.** After `POST /reload`, the Orchestrator polls `GET /health` until the Snort container reports `status: running` before authorizing any attack. This prevents silent false negatives from attacks starting before Snort has loaded the new rules.
- **Experiment state is in memory only.** If the Orchestrator process crashes mid-experiment, the experiment is lost. The operator must resubmit. The Experiment Recorder writes only on experiment completion.
- **The IDS Rule Validator, IDS Rule Injector, and IDS Monitor are abstract interfaces.** The Snort implementation is the initial backend. Adding Suricata requires implementing the interface, not changing the agents.
- **Validation failure feeds back into the Rule Agent as part of the standard feedback loop** — it is not a separate error path. A syntactically invalid rule costs one iteration.

### Error Taxonomy

All structured errors halt the current experiment and are recorded in the Experiment Record.

| Error | When raised |
|---|---|
| `UnmappedIntentError` | Operator intent cannot be mapped to any catalog entry |
| `SlotValidationError` | Attacker Agent exhausted `slot_validation.max_retries` with invalid slot values |
| `SIDCounterCorruptedError` | `sid_counter.json` is missing or corrupted at startup |
| `AttackTimeoutError` | Attack container killed after timeout + extension period |
| `IDSReloadError` | `GET /health` returns `status: error` after `docker restart snort_ids` |
| `PCAPRetrievalError` | PCAP file not found or download failed after container execution |
| `IDSAPIUnreachableError` | Entity 2 does not respond after retry exhaustion |
| `AttackerAPIUnreachableError` | Entity 3 does not respond after retry exhaustion |

`IDSAPIUnreachableError` and `AttackerAPIUnreachableError` are raised after 3 attempts with exponential backoff (1s, 2s, 4s). Configurable via `rest_api_retry.max_attempts` and `rest_api_retry.base_delay_seconds`.

## Testing Decisions

A good test exercises the module's observable behavior through its public interface, using realistic inputs and asserting on outputs or side effects. Tests must not assert on internal implementation details. Tests should remain valid if the internal implementation is refactored, as long as behavior is preserved.

Two-level testing strategy:

**Unit tests (no infrastructure required):** All modules with external dependencies are tested using doubles — a fake FastAPI server for the IDS Management API and Attacker API, `tmp_path` for filesystem modules, and a mocked subprocess for PCAP capture. These drive the red-green-refactor cycle.

**Integration tests (`@pytest.mark.integration`, require Docker):** Run with `pytest -m integration`. Test the IDS Rule Injector against the real `snort_ids` container and attack skills against real Docker containers. Not required for every `pytest` run.

| Module | What to test |
|---|---|
| **SID Manager** | Counter increments correctly; SID always falls within 9,000,000–9,999,999; LLM-supplied SID is always overwritten; multiple rules in one iteration each receive a distinct SID; `sid → intent` mapping persists across process restarts; `SIDCounterCorruptedError` raised on missing or corrupted file |
| **Attack Skills** | Skills are discoverable; `main.py` executes with correct arguments; unmapped intent raises `UnmappedIntentError` without invoking any container; PCAP file is produced at the expected path and converted to a text summary |
| **IDS Rule Validator** | Valid rule set returns `valid=True`; invalid rule returns `valid=False` with non-empty error; the implementation calls the IDS Management API correctly |
| **IDS Rule Injector** | Rule set is written to the dedicated file with correct SIDs; `POST /reload` is called; `GET /health` is polled until `running`; a second injection overwrites the previous rule set; `IDSReloadError` raised if health check returns `error` |
| **IDS Monitor** | Returns `fired=True` when the alert log contains any active SID; returns `fired=False` when the log is empty or contains only other SIDs; configurable log path is honored |
| **Experiment Recorder** | JSON contains all required fields (metrics, rule sets, diagnoses, feedback payloads, PCAP paths); CSV has one row per attack execution with correct column values; PCAP paths are local and relative to the experiment directory |
| **PCAP Capture** | PCAP is produced and converted to a non-empty text summary; raw PCAP is served correctly via `GET /pcaps/{filename}`; errors during capture are surfaced as exceptions |

## Out of Scope

- **Network isolation** — The system assumes an isolated testbed. Configuring or enforcing network isolation is the operator's responsibility.
- **Authentication between services** — No auth is implemented. The system trusts the network boundary.
- **Web UI or dashboard** — The operator interface is REST-only. No frontend is included.
- **False positive testing against legitimate traffic** — The precision+recall metric is defined but generating realistic legitimate traffic baselines is deferred.
- **Multi-experiment parallelism** — The Orchestrator handles one experiment at a time in this version.
- **IDS backends other than Snort** — The abstraction layer supports multiple backends, but only the Snort implementation is in scope for this version.
- **`allowed_catalog_entries` filter** — Restricting which catalog entries are available per experiment (User Story 7 in the original spec) is deferred. The Attacker Agent has access to the full catalog of 10 attacks.
- **Artifact retention policy** — PCAPs and JSON records accumulate indefinitely. Cleanup is the operator's responsibility.

## Further Notes

- The project uses TDD: no module is implemented before a test that requires it.
- All source code is in English (US), including variable names, function names, comments, and commit messages.
- Dependency management: `uv`. Runtime: Python 3.12+. Agent framework: Agno. Web framework: FastAPI.
- The SID range 9,000,000–9,999,999 is the range recommended by the Snort project for local/custom rules. This avoids conflicts with official rulesets (1–3,464,999) and community rules.
- Configuration is via `config.yaml` with environment variable overrides. API keys are never stored in `config.yaml`.

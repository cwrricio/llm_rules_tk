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
5. As a network operator, I want the generated rule to be injected into the IDS without restarting it, so that the testbed can iterate quickly.
6. As a network operator, I want the system to automatically simulate an attack that matches my stated intent, so that the rule is tested under realistic conditions.
7. As a network operator, I want to restrict which attack tools are used in a given experiment, so that I can control the scope and risk of the simulation.
8. As a network operator, I want the attack traffic to be captured as a PCAP, so that I can inspect exactly what was sent during each test.
9. As a network operator, I want the system to test the rule against multiple attack variants after initial detection, so that I know the rule is not fragile against minor parameter changes.
10. As a network operator, I want to configure how many attack variants are tested per iteration, so that I can trade off thoroughness against experiment duration.
11. As a network operator, I want the system to automatically revise the rule when it fails to detect an attack, so that convergence happens without my intervention.
12. As a network operator, I want the feedback sent to the rule agent to include a natural-language diagnosis, the raw PCAP, and the IDS logs, so that the agent has all the evidence needed to revise the rule correctly.
13. As a network operator, I want the loop to stop after a configurable maximum number of iterations if no convergence is reached, so that the experiment always terminates.
14. As a network operator, I want to know whether the experiment converged or failed, so that I can assess whether my intent was achievable within the given constraints.
15. As a network operator, I want the system to raise a structured error if my intent cannot be mapped to any available attack tool, so that the experiment fails clearly rather than executing undefined behavior.
16. As a network operator, I want to configure the IDS backend via a parameter (e.g., log file path), so that I can use the system with Snort or Suricata without modifying the codebase.
17. As a researcher, I want all four metrics (detection rate, precision+recall, iterations to convergence, structural quality) recorded for every iteration of every experiment, so that I can analyze both research axes independently.
18. As a researcher, I want the complete generated rule stored for each iteration, so that I can trace how the rule evolved across the feedback loop.
19. As a researcher, I want all feedback payloads exchanged between agents stored, so that I can understand the agent reasoning and diagnose failure cases.
20. As a researcher, I want experiment results exported in both JSON and CSV formats, so that I can load them into Python for analysis without writing a parser.
21. As a researcher, I want PCAP files stored separately and referenced by path in the experiment record, so that the JSON remains lightweight and PCAPs can be inspected with Wireshark independently.
22. As a researcher, I want the SID-to-intent mapping to be persisted across experiments, so that I can trace any alert in the IDS back to the operator intent that produced it.

## Implementation Decisions

### Module Inventory

The system is distributed across three application entities:

**Entity 1 — Orchestrator Application**

- **Orchestrator** — Owns the feedback loop. Maintains experiment state (current iteration, convergence status), sequences calls to the Rule Agent and Attacker Agent via their REST APIs, evaluates termination conditions, and triggers the Experiment Recorder. Agents are stateless; the Orchestrator decides what happens next.
- **Rule Agent** — Stateless LLM agent (built with Agno). On first call, receives the operator's intent and produces a candidate IDS rule. On subsequent calls, receives the feedback payload and a revised rule. Delegates syntax validation to the IDS Rule Validator and injection to the IDS Rule Injector before returning a result to the Orchestrator.
- **SID Manager** — Deterministic component that assigns unique SIDs within the reserved local range (9,000,000–9,999,999) using a persistent counter. Always replaces any SID produced by the LLM. Persists a `sid → intent` mapping to disk.
- **IDS Rule Validator** — Abstract interface with a Snort implementation that calls `snort -T` via the IDS Management API on Entity 2. Returns either `valid` or the raw error output (which feeds back into the Rule Agent on failure).
- **IDS Rule Injector** — Abstract interface with a Snort implementation that writes the approved rule to a dedicated file (e.g., `ai_generated.rules`) and signals the IDS to reload via the IDS Management API. Uses a dedicated file to keep AI-generated rules separate from pre-existing rules.
- **IDS Monitor** — Abstract interface that reads the IDS alert log via the IDS Management API and checks for an alert matching a given SID. The log file path is a configurable parameter.
- **Experiment Recorder** — Writes a JSON record per experiment containing all metrics, rules, and feedback payloads, plus a tabular CSV of metrics for analysis. PCAPs are stored as separate files; the JSON holds their paths.
- **Orchestrator REST API** — Exposes `POST /experiments` (submit intent, returns experiment ID) and `GET /experiments/{id}` (retrieve result). Built with FastAPI.

**Entity 2 — IDS Management API**

- **IDS Management API** — A thin REST API that wraps IDS operations on the local host: rule validation (`POST /validate`), rule injection (`POST /rules`), and alert log reading (`GET /alerts?sid=...`). This is the only component that touches IDS files directly. Built with FastAPI.

**Entity 3 — Attacker Application**

- **Attacker Agent** — Stateless LLM agent (built with Agno). Receives the operator's intent and the generated rule, queries the Attack Tool Catalog to select an appropriate tool, invokes the PCAP Capture module before executing the attack, checks the IDS Monitor after execution, and returns the result or feedback payload to the Orchestrator.
- **Attack Tool Catalog** — A static registry mapping attack types to available tools (e.g., port scan → `nmap`, flood → `hping3`, exploits → `metasploit`). The LLM selects among catalog entries. If the intent cannot be mapped to any entry, the catalog raises a structured `UnmappedIntentError` — no tool is invoked.
- **PCAP Capture** — Starts a `tcpdump` capture before the attack and stops it after, producing a PCAP file. Requires network capture privileges on Entity 3. Returns the PCAP file path.
- **Attacker REST API** — Exposes `POST /attacks` (execute attack, returns result or feedback payload). Built with FastAPI.

### API Contracts

**POST /experiments (Orchestrator API)**
```
Request:  { intent: str, max_iterations?: int, allowed_tools?: list[str], variant_count?: int }
Response: { experiment_id: str }
```

**GET /experiments/{id} (Orchestrator API)**
```
Response: { status: "running" | "converged" | "failed", result?: ExperimentRecord }
```

**POST /attacks (Attacker API)**
```
Request:  { intent: str, rule: str, sid: int, variant_count: int, allowed_tools?: list[str] }
Response: { fired: bool, feedback?: { diagnosis: str, pcap_path: str, ids_logs: str } }
```

**POST /validate (IDS Management API)**
```
Request:  { rule: str }
Response: { valid: bool, error?: str }
```

**POST /rules (IDS Management API)**
```
Request:  { rule: str, sid: int }
Response: { ok: bool }
```

**GET /alerts (IDS Management API)**
```
Query:    ?sid=<int>&since=<timestamp>
Response: { fired: bool, count: int }
```

### Key Architectural Decisions

- The LLM is never responsible for system guarantees. SID uniqueness, tool selection boundaries, and loop termination are all controlled by deterministic code. See ADR-0001 for the REST communication decision.
- The IDS Rule Validator, IDS Rule Injector, and IDS Monitor are abstract interfaces. The Snort implementation is the initial backend. Adding Suricata requires implementing the interface, not changing the agents.
- Validation failure feeds back into the Rule Agent as part of the standard feedback loop — it is not a separate error path. This means a syntactically invalid rule costs one iteration, not a hard failure.
- The Orchestrator is a separate component from the agents, not embedded in either. Both agents are stateless workers. This keeps loop logic testable in isolation from LLM behavior.

## Testing Decisions

A good test exercises the module's observable behavior through its public interface, using realistic inputs and asserting on outputs or side effects. Tests must not assert on internal implementation details (e.g., which private method was called). Tests should remain valid if the internal implementation is refactored, as long as behavior is preserved.

The following deep modules will have unit/integration tests. All are testable without a running LLM or live network:

| Module | What to test |
|---|---|
| **SID Manager** | Counter increments correctly; SID always falls within 9,000,000–9,999,999; LLM-supplied SID is always overwritten; `sid → intent` mapping persists across process restarts; concurrent calls do not produce duplicate SIDs |
| **Attack Tool Catalog** | Intent maps to the correct tool; `allowed_tools` filter restricts selection; unmapped intent raises `UnmappedIntentError` without invoking any executable; catalog entries are validated at startup |
| **IDS Rule Validator** | Valid rule returns `valid=True`; invalid rule returns `valid=False` with non-empty error string; the Snort implementation passes the rule to the IDS Management API correctly |
| **IDS Rule Injector** | Rule is written to the dedicated file with the correct SID; the IDS Management API is called to trigger a reload; a second injection for the same experiment overwrites the previous rule |
| **IDS Monitor** | Returns `fired=True` when the alert log contains an entry matching the target SID; returns `fired=False` when the log is empty or contains only other SIDs; configurable log path is honored |
| **Experiment Recorder** | JSON output contains all required fields (metrics, rules per iteration, feedback payloads, PCAP paths); CSV contains one row per iteration with correct metric values; PCAP paths are relative and portable |
| **PCAP Capture** | Capture produces a non-empty file; file is created at the expected path; capture stops cleanly after the attack window; errors during capture are surfaced as exceptions, not silent failures |

## Out of Scope

- **Network isolation** — The system assumes an isolated testbed. Configuring or enforcing network isolation is the operator's responsibility.
- **Authentication between services** — No auth is implemented. The system trusts the network boundary.
- **Web UI or dashboard** — The operator interface is REST-only (`POST /experiments`). No frontend is included.
- **False positive testing against legitimate traffic** — The precision+recall metric is defined but generating realistic legitimate traffic baselines is deferred.
- **Multi-experiment parallelism** — The Orchestrator handles one experiment at a time in this version.
- **IDS backends other than Snort** — The abstraction layer supports multiple backends, but only the Snort implementation is in scope for this version.

## Further Notes

- The project uses TDD: no module is implemented before a test that requires it.
- All source code is in English (US), including variable names, function names, comments, and commit messages.
- Dependency management: `uv`. Runtime: Python 3.12+. Agent framework: Agno. Web framework: FastAPI.
- The SID range 9,000,000–9,999,999 is the range recommended by the Snort project for local/custom rules. This avoids conflicts with official rulesets (1–3,464,999) and community rules.

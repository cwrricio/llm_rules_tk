# Context Map — Rules Farmer

## Operator Interface

The operator submits a natural-language intent via `POST /experiments` to the Orchestrator's REST API (Entity 1). The response includes an experiment ID for tracking progress and retrieving results.

## Entity Mapping

| Entity | Components |
|---|---|
| Entity 1 | Orchestrator, Rule Agent, operator interface |
| Entity 2 | IDS (Snort) — exposes a REST API consumed by the IDS Rule Injector, IDS Rule Validator, and IDS Monitor running on Entity 1 |
| Entity 3 | Attacker Agent — runs on the same network segment as Entity 4 to generate real traffic |
| Entity 4 | Target host — receives attack traffic from Entity 3 |

Entity 2 exposes a REST API so that Entity 1 can remotely inject rules, validate them, and read IDS alerts without requiring SSH or shared filesystems.

## Orchestrator

A dedicated component on Entity 1 that controls the feedback loop. It maintains loop state (current iteration, convergence status), sequences calls to the Rule Agent and Attacker Agent, evaluates termination conditions, and records experiment results. Both agents are stateless — they perform their task and return a result; the Orchestrator decides what happens next.

## Agent Communication

Agents communicate via REST APIs over HTTP, allowing each entity to run on a separate host. The Rule Agent and Attacker Agent each expose HTTP endpoints. This enables the 4-entity topology to be distributed across machines.

## Research Objectives

**Rule Translation Quality** — Whether AI agents can correctly translate a natural-language intent into a valid, precise IDS rule.

**Feedback Loop Convergence** — Whether the multi-agent feedback cycle converges to a robust rule and how efficiently it does so.

## Metrics

Per iteration of the feedback loop, the system captures:

| Metric | Description |
|---|---|
| Detection Rate | Did the rule trigger on the original simulated attack? (binary) |
| Precision + Recall | Does the rule detect attack variants without generating false positives on legitimate traffic? |
| Iterations to Convergence | How many feedback cycles were needed to reach an effective rule? |
| Structural Quality | Is the rule syntactically valid, uses the correct protocol fields, and avoids overly broad patterns? |

## Feedback Payload

When a rule fails to fire, the Attacker Agent sends the following structured payload to the Rule Agent:

| Field | Description |
|---|---|
| `diagnosis` | Natural-language explanation of why the rule likely failed |
| `raw_attack_data` | The raw data describing the attack that was executed (TBD — see below) |
| `ids_logs` | The IDS log output captured during the attack window (no alerts fired) |

`raw_attack_data` — A PCAP file captured via `tcpdump` or `scapy` during the attack window, containing the packets effectively sent to the target. Requires network capture privileges on the Attacker entity.

**Attack Variant** — A modified execution of the original attack using the same tool but with different parameters (e.g., different port, source IP, payload, or TTL). Used to test rule robustness after the rule successfully detects the original attack.

## Feedback Loop

The loop terminates when either:
1. **Convergence** — the rule detects the original attack *and all* N variants (100% detection rate required). The Orchestrator stops calling variants as soon as the first evasion is found and sends feedback to the Rule Agent immediately. The goal is to refine the rule until the Attacker Agent can no longer evade it.
2. **Max iterations reached** — the loop exhausted N attempts without convergence (failure).

N is a configurable parameter. Both outcomes are recorded as part of the experiment results.

## Experiment Record

Each experiment produces a directory under `results/{experiment_id}/` containing:

```
results/
└── {experiment_id}/
    ├── experiment.json   # complete record: all iterations, rules, feedback payloads, diagnoses
    ├── metrics.csv       # one row per attack execution (base + each variant); columns: iteration, execution_type (base|variant), catalog_entry_id, slots, fired, evasion_rationale
    └── pcaps/
        ├── iter1_base.pcap
        ├── iter1_variant1.pcap
        └── ...
```

`experiment_id` is a UUID generated at `POST /experiments`. PCAPs are stored per-experiment (not globally) and referenced by relative paths in `experiment.json`. The CSV provides one row per attack execution — not one per main loop iteration — to enable granular evasion analysis.

## Security Model

The system relies entirely on network isolation for security. No authentication is implemented between REST APIs. This is an explicit assumption — the operator is responsible for ensuring the testbed network is isolated.

## Error Taxonomy

Structured errors raised by the system. All halt the current experiment and are recorded in the Experiment Record.

| Error | When raised |
|---|---|
| `UnmappedIntentError` | Operator intent cannot be mapped to any catalog entry |
| `SlotValidationError` | Attacker Agent exhausted `slot_validation.max_retries` with invalid slot values |
| `SIDCounterCorruptedError` | `sid_counter.json` is missing or corrupted at startup |
| `AttackTimeoutError` | Attack container killed after timeout + extension period |
| `IDSReloadError` | `GET /health` returns `status: error` after `docker restart snort_ids` (invalid rule or Snort crash) |
| `PCAPRetrievalError` | PCAP file not found at expected path after container execution |
| `IDSAPIUnreachableError` | Entity 2 does not respond after retry exhaustion |
| `AttackerAPIUnreachableError` | Entity 3 does not respond after retry exhaustion |

For `IDSAPIUnreachableError` and `AttackerAPIUnreachableError`: the Orchestrator retries with exponential backoff before failing — 3 attempts at 1s, 2s, 4s delays. Configurable via `rest_api_retry.max_attempts` and `rest_api_retry.base_delay_seconds` in `config.yaml`.

## Testing Strategy

Two-level approach to satisfy TDD without requiring live infrastructure in every test run:

**Unit tests (fast, no infrastructure):** All modules with external dependencies are tested using doubles:
- `IDS Rule Validator`, `IDS Rule Injector`, `IDS Monitor` — tested against a fake FastAPI server simulating the IDS Management API
- `SID Manager` — tested with `tmp_path` (temporary filesystem)
- `Experiment Recorder` — tested with `tmp_path`
- `PCAP Capture` — tested with a mocked `subprocess` that creates a fake PCAP file
- Attack Skills — tested with a mocked container runner that returns a predefined JSON output

**Integration tests (slow, require Docker, marked `@pytest.mark.integration`):** Run only when Docker is available via `pytest -m integration`. Test the IDS Rule Injector against the real `snort_ids` container, and attack skills against real Docker containers in an isolated network.

Unit tests drive the red-green-refactor cycle. Integration tests validate end-to-end behavior.

## Deferred Features

**`allowed_catalog_entries` filter** — User Story 7 (restricting which attack skills are available per experiment) is deferred. In the current version, the Attacker Agent has access to the full catalog of 10 pre-configured Docker attacks (MQTT + XRCE-DDS). The `allowed_catalog_entries` parameter is not included in `POST /experiments` or `POST /attacks`. This filter can be added later without schema-breaking changes.

## Gap-Filling Decisions

**Orchestrator state** — Experiment state (current iteration, rules generated, partial results) is maintained in memory only. If the Orchestrator process crashes mid-experiment, the experiment is lost. The operator must resubmit. `GET /experiments/{id}` returns 404 for experiment IDs no longer in memory. The Experiment Recorder writes the complete result record only upon experiment completion (convergence or max iterations reached). While running, `GET /experiments/{id}` returns only `{ "status": "running" }` — no partial progress is exposed via the API. Progress is observable through Orchestrator logs.

**SID Manager corruption** — If `sid_counter.json` is missing or corrupted at startup, the SID Manager raises `SIDCounterCorruptedError` and halts. The error message instructs the operator: `"sid_counter.json missing or corrupted. To reset safely, delete ai_generated.rules and recreate sid_counter.json with {\"counter\": 9000000}."` Automatic recreation is not performed — it would risk SID duplication if rules from previous runs still exist.

**Slot validation failure** — When the Attacker Agent LLM produces an `AttackPlan` with a slot value that fails catalog validation (e.g., `{port}: "abc"`, value out of declared range), the system does not execute the tool. It returns the validation error to the Attacker Agent LLM as a correction request. The LLM produces a new `AttackPlan`. This inner retry loop does not consume a main feedback loop iteration. After `slot_validation.max_retries` failed attempts, the system raises a structured error and halts the experiment.

**Attack tool timeout** — When a Docker attack container reaches `attack_tool_seconds` without completing, the system checks whether the container is still running (`docker inspect`). If running, the system waits an additional `attack_tool_extension_seconds`. If the container is still running after the extension, it is forcibly killed (`docker kill`) and the iteration is treated as a failure. The feedback payload for this failure includes a structured justification: `{ "reason": "timeout", "duration_seconds": <total_waited>, "container_status": "killed" }`. This counts as one consumed iteration in the main loop.

**IDS reload and health check** — Snort runs inside a Docker container (`snort_ids`). After the IDS Rule Injector writes the rule file, it triggers a reload via `POST /reload` on the IDS Management API, which executes `docker restart snort_ids`. The Orchestrator then polls `GET /health` until the container reports `status: running` before authorizing the Attacker Agent to proceed. If the container fails to restart (e.g., invalid rule causes Snort to exit), `GET /health` returns `status: error` with the docker logs — this error feeds back into the Rule Agent as a validation failure. The IDS Management API endpoints are: `POST /validate`, `POST /rules`, `POST /reload`, `GET /health`, `GET /alerts`.

## Assumptions & Constraints

- **Network isolation is out of scope.** The system assumes it runs in an isolated network environment, but does not implement or enforce that isolation. The operator is responsible for setting up a safe testbed.

- **Distributed topology across separate physical machines.** Entity 1 (Orchestrator), Entity 2 (IDS + IDS Management API), and Entity 3 (Attacker Agent + Attacker API) run on separate physical hosts. Each entity is started independently by the operator — there is no unified `docker-compose.yml`. Startup order: Entity 2 first, Entity 3 second, Entity 1 last. The REST APIs on Entity 2 and Entity 3 are the only interfaces Entity 1 uses — no direct SSH access from the Orchestrator.

- **PCAP capture and retrieval.** Each Docker-based attack tool captures its own traffic internally (via `tcpdump` inside the container) and exposes the PCAP file at a known path on Entity 3's filesystem after execution. The Attacker Agent converts it to a human-readable summary (`tshark`) and returns the summary in the `FeedbackPayload`. The Attacker API exposes `GET /pcaps/{filename}` for raw PCAP download over HTTP. The Orchestrator downloads the PCAP after each attack execution and stores it in `results/{experiment_id}/pcaps/` on Entity 1's local filesystem. The `pcap_path` in the Experiment Record is a local path on Entity 1 — the researcher opens it directly in Wireshark without SSH access to Entity 3.

## Configuration

All system parameters are configurable via `config.yaml`. Any value can be overridden by a corresponding environment variable (env vars take precedence). API keys are never stored in `config.yaml` — they are always loaded from environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GROQ_API_KEY`, etc.).

```yaml
llm:
  rule_agent:
    provider: anthropic        # anthropic | openai | groq
    model: claude-sonnet-4-6
    temperature: 0
  attacker_agent:
    provider: anthropic
    model: claude-sonnet-4-6
    temperature: 0

timeouts:
  attack_tool_seconds: 60      # initial wait for a Docker attack container to complete
  attack_tool_extension_seconds: 30  # added once if container is still running at timeout
  rest_api_seconds: 30         # max wait for internal REST API calls

slot_validation:
  max_retries: 3               # max AttackPlan correction attempts before halting the experiment

experiment_defaults:
  max_iterations: 5            # used when POST /experiments omits max_iterations
  variant_count: 3             # used when POST /experiments omits variant_count

testbed:
  orchestrator_host: localhost
  orchestrator_port: 8000
  attacker_api_host: localhost
  attacker_api_port: 8001
  ids_api_host: localhost
  ids_api_port: 8002
  ids_alert_log_path: /var/log/snort/alert
  ids_rules_file_path: /etc/snort/rules/ai_generated.rules
  sid_counter_file_path: ./data/sid_counter.json
  results_output_dir: ./results
```

Agno abstracts LLM provider differences — the `provider` + `model` fields map directly to Agno's model configuration. Each agent can use a different provider and model independently.

## Pydantic Schemas

### LLM Output Schemas

These schemas define what each LLM call must return. They are enforced via Pydantic structured output. No field outside these schemas is produced by the LLM.

```python
class RuleAgentOutput(BaseModel):
    rules: list[str]       # one or more complete Snort rule strings; SIDs replaced by SID Manager before injection
    diagnosis: str | None  # Rule Agent's stated reasoning for this revision; None on first iteration

class AttackPlan(BaseModel):
    catalog_entry_id: str    # must match an existing entry in the Attack Tool Catalog
    slots: dict[str, str]    # values for declared variable slots only; no invented parameters
    evasion_rationale: str   # why these parameters challenge the rule under test (Attacker Strategy)
```

`RuleAgentOutput` is the only LLM output schema for the Rule Agent. The Rule Agent is called once per iteration: on the first iteration it receives the operator intent; on subsequent iterations it receives the operator intent, the previous rule set, and the FeedbackPayload. It generates the diagnosis internally as part of its reasoning — the diagnosis is not a separate output field but is embedded in the LLM's chain-of-thought before producing the revised `rules`. The system may use multiple skills (chained LLM calls) internally within the Rule Agent if needed.

Multiple rules per iteration are permitted when a generic operator intent spans multiple attack vectors that cannot be expressed by a single Snort rule. The SID Manager assigns a unique SID to each rule. The IDS Monitor checks whether any rule in the active set fired for a given attack execution — convergence requires the full set to collectively detect the base attack and all variants.

`AttackPlan` is the only LLM output schema for the Attacker Agent. The LLM is called once per attack execution (base attack + each variant separately). Variants are generated one at a time, each informed by the results of previous variant attempts in the same iteration. Deterministic code executes the attack, captures the PCAP, reads the IDS logs, and assembles the `AttackerAgentOutput`.

### Deterministic Output Schemas

These schemas are assembled by deterministic code after execution — no LLM involvement.

```python
class VariantResult(BaseModel):
    slots: dict[str, str]   # slot values used in this variant attempt
    fired: bool             # True if IDS alert matched the injected SID

class FeedbackPayload(BaseModel):
    pcap_summary: str      # human-readable packet summary (tshark/tcpdump output); raw PCAP stored separately in Experiment Record
    ids_logs: str          # IDS alert log content captured during the attack window (empty if no alerts)
    evasion_rationale: str # Attacker Agent's stated reason why these slots challenge the rule (generated pre-execution)

class AttackerAgentOutput(BaseModel):
    fired: bool                       # True if IDS alert matched the injected SID
    pcap_filename: str                # filename on Entity 3; Orchestrator downloads via GET /pcaps/{filename} and stores locally
    feedback: FeedbackPayload | None  # present only when fired=False
```

### POST /attacks — Request Schema

`variant_count` is a parameter of the Orchestrator loop, not of the Attacker Agent. The Orchestrator calls `POST /attacks` up to N+1 times per main iteration (once for the base attack, then once per variant). Each call carries the full cumulative variant history so the LLM can reason about what has already been attempted.

```python
class AttackerRequest(BaseModel):
    intent: str
    rule: str
    sid: int
    variant_history: list[VariantResult]  # empty on base attack call; grows with each variant call
```

`variant_history` contains all `VariantResult` entries from the current iteration and all previous iterations, giving the Attacker Agent a complete view of what has been tried across the entire experiment.

## Terms

**Attack Tool Catalog** — A fully-specified registry of attack templates available to the Attacker Agent. Each entry defines: the attack type identifier, the invocation model (CLI or Docker), the complete invocation template with named variable slots (e.g., `{target_ip}`, `{target_port}`), and the set of variables the LLM is allowed to fill. The LLM's role is limited to: (1) selecting the appropriate catalog entry based on the operator's intent, and (2) providing values for the declared variable slots. The LLM does not construct arguments, invent flags, or reason about tool internals. If the intent cannot be mapped to any catalog entry, the system raises a structured `UnmappedIntentError` and halts — no tool is invoked with undefined behavior.

All attack entries use the **Docker invocation model**. Each attack is packaged in its own pre-configured Docker image on Entity 3. XRCE-DDS attacks are custom C programs compiled against `libmicroxrcedds_client`, `libmicrocdr`, and `pthread`. MQTT attacks are containerized tooling (e.g., `mosquitto_pub`-based). The catalog entry for every attack defines: the Docker image name, the environment variables or CLI arguments passed to the container's `entrypoint.sh`, expected exit codes (success / attack executed / precondition failure), and the log contract (what the container writes to stdout/stderr). The Attacker Agent uses a single invocation model for all skills — no CLI fallback.

**SID Manager** — A system component responsible for assigning unique Snort Signature IDs (SIDs) to AI-generated rules. Uses a reserved local range (e.g., 9,000,000–9,999,999) with a persistent counter. The LLM-generated rule's SID is always replaced by the SID Manager before injection. Maintains a persistent mapping of `sid → operator intent` for traceability.

**IDS Rule Validator** — An abstraction layer that validates a generated rule's syntax before injection. The initial implementation invokes `snort -T` (test mode) against the candidate rule. If validation fails, the error output is returned to the Rule Agent as feedback instead of proceeding to injection. The abstraction allows other IDS backends to plug in their own validation mechanism (e.g., `suricata --test-config`).

**IDS Rule Injector** — An abstraction layer that the Rule Agent uses to inject a generated rule into the IDS. The initial implementation writes the rule set to a dedicated file (e.g., `ai_generated.rules`) via `POST /rules` on the IDS Management API, then triggers a container restart (`docker restart snort_ids`) via `POST /reload`. The file is cleared at the start of each experiment and overwritten (not appended) on each injection. After triggering the restart, the Orchestrator polls `GET /health` until the container reports `status: running` before authorizing the Attacker Agent to proceed — this prevents false negatives caused by attacks starting before Snort has loaded the new rules. If the container fails to come back healthy (e.g., invalid rule causes Snort to exit), `GET /health` returns the docker logs as the error signal, which feeds back into the Rule Agent.

**IDS Monitor** — An abstraction layer that the Attacker Agent uses to check whether the IDS fired a rule during a simulated attack. The initial implementation reads the IDS alert log file and checks for an alert matching the injected rule's `sid`. The log file path is a configurable parameter, allowing the same implementation to monitor different IDS backends by pointing to their respective log files (e.g., `/var/log/snort/alert` for Snort, or a Suricata EVE JSON file).

**Attack Tool** — An external executable (e.g., `nmap`, `hping3`, `metasploit`) invoked by the Attacker Agent to generate realistic attack traffic against the Target. The system must support multiple tools, since different attack types require different tools. The Attacker Agent selects the appropriate tool based on the attack being simulated.

**Attack Simulation** — The act of invoking one or more Attack Tools to generate traffic with the characteristics described in the operator's intent, in order to test whether the IDS rule fires correctly.

**Attacker Strategy** — The Attacker Agent operates in two distinct phases within each iteration, both informed by the content of the generated rule:

1. **Detection Phase** — Executes the canonical attack (as described by the operator's intent) to verify the rule fires. The agent uses the rule to confirm it is targeting what the rule was designed to detect.
2. **Evasion Phase** — Uses knowledge of the rule's structure (e.g., specific ports, protocols, payload patterns it matches on) to craft variants that attempt to evade detection. A variant is a modified execution of the same attack tool with parameters adjusted to probe the rule's boundaries (e.g., different port, encoding, TTL, or source IP). If any variant evades detection, the feedback payload includes the specific evasion that succeeded and why the rule likely missed it.

The agent is not simply running random parameter changes — it reasons about the rule's logic to generate targeted evasion attempts. This is the "white hacker" property: the attacker has full visibility into the rule under test and uses that visibility adversarially.

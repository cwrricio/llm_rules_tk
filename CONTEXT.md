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

## Attacker Agent

A stateless LLM agent (built with Agno) running on Entity 3 that simulates attacks against the target (Entity 4). The agent receives the operator's intent, the generated IDS rule, and the rule's SID. It discovers available Attack Skills via Agno's LocalSkills loader, reasons about which skill best matches the intent and rule characteristics, loads the skill's reference documentation, invokes the skill's main.py script with the appropriate arguments, captures the attack traffic as a PCAP, checks whether the IDS fired the rule, and returns the result to the Orchestrator. If the rule does not fire, the agent generates and returns a structured feedback payload (diagnosis, pcap_path, ids_logs) for the Rule Agent to revise the rule.

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
1. **Convergence** — the rule detects the original attack *and* a defined set of variants without false positives (success), or
2. **Max iterations reached** — the loop exhausted N attempts without convergence (failure).

N is a configurable parameter. Both outcomes are recorded as part of the experiment results.

## Experiment Record

Each experiment run produces a file containing:
- All metrics (detection rate, precision/recall, iterations to convergence, structural quality)
- Each generated rule per iteration
- Feedback payloads exchanged between agents
- References to PCAP files captured during the run

Format: JSON (structured data) + CSV (tabular metrics for analysis). PCAPs are stored as separate files referenced by path.

## Security Model

The system relies entirely on network isolation for security. No authentication is implemented between REST APIs. This is an explicit assumption — the operator is responsible for ensuring the testbed network is isolated.

## Assumptions & Constraints

- **Network isolation is out of scope.** The system assumes it runs in an isolated network environment, but does not implement or enforce that isolation. The operator is responsible for setting up a safe testbed.

## Terms

**Attack Skill** — A self-contained package containing instructions (SKILL.md), executable scripts (scripts/main.py), and reference documentation (references/) for simulating a specific class of attacks. Each skill encapsulates one attack type (e.g., reconnaissance, DoS, exploitation) and may use multiple underlying tools (e.g., nmap, hping3, metasploit). The Attacker Agent discovers available skills via Agno's LocalSkills loader, reasons about which skill matches the operator's intent and generated rule, and invokes the skill's main.py script with the appropriate arguments.

**Attack Skill Catalog** — The registry of all available Attack Skills, organized by attack type. Skills are loaded dynamically from the `skills/` directory by the Attacker Agent at startup. If the operator's intent cannot be mapped to any available skill, the system raises a structured error and halts execution — no tool is invoked with undefined behavior.

**SID Manager** — A system component responsible for assigning unique Snort Signature IDs (SIDs) to AI-generated rules. Uses a reserved local range (e.g., 9,000,000–9,999,999) with a persistent counter. The LLM-generated rule's SID is always replaced by the SID Manager before injection. Maintains a persistent mapping of `sid → operator intent` for traceability.

**IDS Rule Validator** — An abstraction layer that validates a generated rule's syntax before injection. The initial implementation invokes `snort -T` (test mode) against the candidate rule. If validation fails, the error output is returned to the Rule Agent as feedback instead of proceeding to injection. The abstraction allows other IDS backends to plug in their own validation mechanism (e.g., `suricata --test-config`).

**IDS Rule Injector** — An abstraction layer that the Rule Agent uses to inject a generated rule into the IDS. The initial implementation writes the rule to a dedicated file (e.g., `ai_generated.rules`) and signals the IDS process to reload (e.g., `SIGHUP` for Snort). Using a dedicated file keeps AI-generated rules separate from pre-existing IDS rules.

**IDS Monitor** — An abstraction layer that the Attacker Agent uses to check whether the IDS fired a rule during a simulated attack. The initial implementation reads the IDS alert log file and checks for an alert matching the injected rule's `sid`. The log file path is a configurable parameter, allowing the same implementation to monitor different IDS backends by pointing to their respective log files (e.g., `/var/log/snort/alert` for Snort, or a Suricata EVE JSON file).

**Attack Tool** — An external executable (e.g., `nmap`, `hping3`, `metasploit`) invoked internally by an Attack Skill to generate realistic attack traffic against the Target. Each Attack Skill may use one or more tools internally; tool selection is encapsulated within the skill's scripts.

**Attack Simulation** — The act of executing an Attack Skill, which invokes one or more Attack Tools internally to generate traffic with the characteristics described in the operator's intent, in order to test whether the IDS rule fires correctly.

# Pending Issues — Rules Farmer

Issues resolved during grilling sessions (2026-05-13) are noted. Remaining items are implementation details to be worked out during TDD.

---

## 1. Attack Tool Catalog — Slots específicos das 10 entradas (Issue 1.1)

**Schema do catalog entry — RESOLVIDO (2026-05-13):**
- Docker image: `rules-farmer/{id}:latest`
- Invocação: `docker run rules-farmer/{id}:latest {arg1} {arg2} ...` (via SSH na Entity 3)
- Slots: args posicionais ao `entrypoint.sh` — ordem é o contrato entre catálogo e entrypoint
- Exit 0 → `stdout: {"pcap_path": "/tmp/attack.pcap", "packets_sent": N, "duration_seconds": T}`
- Exit 1 → `stderr: {"error": "..."}` (pré-condição falhou)
- Exit 2 → `stderr: {"error": "timed out after N seconds"}`
- PCAP path: `/tmp/attack.pcap` (fixo em todos os containers)

**Conteúdo específico por entry — a ser definido durante TDD:**
Os slots (nome, tipo, range) de cada uma das 10 entradas serão derivados dos `entrypoint.sh` reais na Entity 3. Não devem ser inferidos — devem ser lidos dos scripts disponíveis na máquina atacante.

Entradas pendentes:
- `xrce-dds-entity-flood`
- `xrce-dds-fragment-abuse`
- `xrce-dds-malformed-inject`
- `xrce-dds-session-hijack`
- `xrce-dds-time-desync`
- `xrce-dds-udp-dos`
- `mqtt-bruteforce`
- `mqtt-lwt-abuse`
- `mqtt-publisher-flood`
- `mqtt-qos-amplification`

---

## 2. Prompts dos Agentes (Issues 6.1, 6.2, 6.3)

**Decisões de design — RESOLVIDAS (2026-05-13). Ver CONTEXT.md § "Agent Prompt Constraints".**

**6.1 — Rule Agent system prompt:** Decisões resolvidas (Snort 3.9.12.0, sid:0, rev incremental, msg=intent, múltiplas regras em ambiguidade, sem exemplos, campos aplicáveis, detection_filter). Texto do prompt a ser redigido durante implementação do agente.

**6.2 — Attacker Agent system prompt:** Decisões resolvidas (catálogo embutido no system prompt, evasion_rationale pré-execução, declaração explícita quando variant_history saturada). Texto do prompt a ser redigido durante implementação do agente.

**6.3 — Slot correction prompt:** Decisões resolvidas (appendado à conversa existente, inclui slot name + valor inválido + catalog_entry_id, não inclui range — agente consulta catálogo no system prompt). Texto da mensagem de correção a ser redigido durante implementação.

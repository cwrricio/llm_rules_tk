# Pending Issues — Rules Farmer

Issues resolved during grilling session (2026-05-13) are removed. Remaining items are implementation details to be worked out during TDD.

---

## 1. Attack Tool Catalog — Contrato das 10 entradas (Issue 1.1)

Cada entrada do catálogo precisa definir:
- Nome da Docker image
- Slots declarados: nome + tipo + range válido
- Exit codes esperados (sucesso / ataque executado / pré-condição falhou)
- Contrato de stdout/stderr

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

**Status:** a ser definido durante a implementação de cada skill (TDD).

---

## 2. Prompts dos Agentes (Issues 6.1, 6.2, 6.3)

- **6.1** System prompt do Rule Agent: formato exato esperado da regra, campos obrigatórios, exemplos, comportamento em caso de ambiguidade.
- **6.2** System prompt do Attacker Agent: descrição do catálogo, contrato dos slots, comportamento de evasão, como preencher `evasion_rationale`.
- **6.3** Prompt de correção de slot inválido: formato da mensagem de `SlotValidationError` enviada ao Attacker Agent (qual slot falhou, valor fornecido, range válido).

**Status:** a ser definido durante a implementação dos agentes (TDD).

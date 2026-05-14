# VISÃO GERAL

Rules Farmer e um prototipo de pesquisa para gerar regras Snort a partir de intencoes em linguagem natural e valida-las contra trafego de ataque real em um testbed isolado.

## Objetivos

1. **Qualidade da traducao de intencao em regra**: medir se o agente gera uma regra sintaticamente valida e semanticamente adequada.
2. **Convergencia do loop de feedback**: medir se a regra melhora depois de ataques que nao disparam alerta.

## Entidades

| Entidade | Responsabilidade | Comunicacao |
|---|---|---|
| Entidade 1 | Aplicacao Rules Farmer, Orchestrator, agentes, CLI/API | Local |
| Entidade 2 | Snort IDS no container `snort_ids` | SSH a partir da Entidade 1 |
| Entidade 3 | Diretorios de ataques e imagens Docker | SSH/SCP a partir da Entidade 1 |
| Entidade 4 | Alvo do trafego | Rede do testbed |

A unica API HTTP e a interface opcional da Entidade 1 (`POST /experiments`, `GET /experiments/{id}`). Entidade 2 e Entidade 3 nao expõem APIs REST.

## Estruturas Esperadas

### IDS

O host IDS deve seguir a estrutura observada em `estrura_ids.txt`:

```text
~/ataques-regras-e-assinaturas/snort/
├── snort.lua
├── start_snort.sh
├── renew-snort.sh
├── logs/
└── rules/
    ├── all.rules
    ├── temp/
    └── *.rules
```

O sistema escreve regras geradas em `testbed.ids_rules_file_path`, garante a linha `testbed.ids_rule_include_statement` em `testbed.ids_rules_include_file_path`, reinicia `testbed.ids_container_name` e monitora `testbed.ids_alert_log_path`.

### Ataques

O host atacante deve seguir a estrutura observada em `estrutura_attacks.txt`:

```text
~/ataques/attackers-claude/
└── <attack_id>/
    ├── README.md
    ├── Dockerfile
    ├── entrypoint.sh
    └── arquivos auxiliares opcionais
```

Nao existe lista interna de ataques no codigo. Na inicializacao, `RemoteAttackDiscovery` procura subdiretorios com `entrypoint.sh`, le o `README.md`, extrai a imagem Docker do exemplo `docker run ...:latest` e extrai os argumentos obrigatorios da linha `usage: entrypoint.sh <...>`.

## Componentes

### Orchestrator

Controla o loop. Recebe a intencao do operador, chama o Rule Agent, valida e injeta regras, aciona o Attacker Agent, executa ataques, consulta alertas e grava resultados.

### Rule Agent

Recebe a intencao e gera regras Snort 3 com `sid:0;`. O `SIDManager` substitui esse placeholder por SIDs unicos antes da injecao.

### Attacker Agent

Recebe intencao, regra ativa e historico de variantes. Seleciona um `attack_id` descoberto no host atacante e produz `arguments` posicionais para o `entrypoint.sh`.

### Attack Executor

Cria um diretorio temporario remoto em `/tmp/rules-farmer-attack-*`, inicia captura com `tcpdump`, executa `docker run --rm <imagem> <arguments...>` e copia o PCAP de volta para `results/{experiment_id}/pcaps/`.

### IDS Rule Validator

Valida a regra via SSH no host IDS antes da injecao.

### IDS Rule Injector

Sobrescreve o arquivo de regras configurado, garante que `rules/all.rules` inclua esse arquivo e reinicia o container Snort. Depois, aguarda `docker inspect` indicar que o container esta rodando.

### IDS Monitor

Le o arquivo de alertas do Snort e verifica se o SID ativo disparou.

## Loop

```text
Operador/CLI/API
  -> Orchestrator
  -> Rule Agent
  -> IDS Rule Validator
  -> SID Manager
  -> IDS Rule Injector
  -> Attacker Agent
  -> Attack Executor
  -> IDS Monitor
  -> feedback para Rule Agent se nao disparar
```

O experimento converge quando o ataque base e todas as variantes configuradas disparam alerta. Falha quando atinge `max_iterations`.

## Artefatos

```text
results/{experiment_id}/
├── experiment.json
├── metrics.csv
└── pcaps/
```

`metrics.csv` possui `iteration`, `execution_type`, `attack_id`, `arguments`, `fired` e `evasion_rationale`.

Além dos artefatos por experimento, a execução CLI mantém `output.log` na raiz do projeto. Esse arquivo recebe as mesmas mensagens exibidas no terminal e é atualizado a cada evento registrado. O nivel padrao prioriza banners de fase, resumos, avisos e erros; detalhes repetitivos ficam em `DEBUG`.

## Restricoes

- O testbed deve estar isolado pelo operador.
- Chaves SSH precisam estar configuradas previamente.
- As imagens Docker citadas nos READMEs dos ataques precisam existir na Entidade 3.
- `tcpdump` precisa estar disponivel no host atacante para captura de PCAP.

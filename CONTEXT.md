# Context Map — Rules Farmer

## Operator Interface

O operador pode iniciar um experimento de duas formas:

- CLI: `uv run --python 3.12 rules-farmer`, que aguarda `Intent:`.
- API opcional na Entidade 1: `POST /experiments` e `GET /experiments/{id}`.

## Entity Mapping

| Entity | Components |
|---|---|
| Entity 1 | Orchestrator, Rule Agent, Attacker Agent, CLI/API |
| Entity 2 | Snort IDS no container `snort_ids`, acessado via SSH |
| Entity 3 | Diretorios de ataques e imagens Docker, acessados via SSH/SCP |
| Entity 4 | Host alvo do trafego |

Entity 1 fala com Entity 2 e Entity 3 usando `paramiko` (`SSHClient` para comandos e SFTP para PCAPs). Nao ha servicos REST nas entidades remotas.

## Remote Structures

IDS esperado:

```text
~/ataques-regras-e-assinaturas/snort/
├── snort.lua
├── renew-snort.sh
├── logs/
└── rules/
    ├── all.rules
    ├── temp/
    └── *.rules
```

Ataques esperados:

```text
~/ataques/attackers-claude/
└── <attack_id>/
    ├── README.md
    ├── Dockerfile
    └── entrypoint.sh
```

O codigo nao contem lista fixa de ataques. `RemoteAttackDiscovery` descobre subdiretorios com `entrypoint.sh`, le o README, extrai imagem Docker e nomes de argumentos da linha de usage.

## Research Objectives

- **Rule Translation Quality**: regra valida, precisa e rastreavel.
- **Feedback Loop Convergence**: quantidade de iteracoes ate detectar ataque base e variantes.

## Feedback Loop

1. Operador fornece intencao.
2. Rule Agent produz regra Snort com `sid:0;`.
3. Validator testa sintaxe no IDS.
4. SID Manager atribui SID unico.
5. Injector escreve regra e reinicia Snort.
6. Attacker Agent seleciona `attack_id` descoberto e `arguments`.
7. Attack Executor cria temp dir remoto, captura PCAP com `tcpdump`, roda `docker run` e copia PCAP.
8. IDS Monitor verifica alerta pelo SID.
9. Se nao disparar, feedback volta ao Rule Agent.

Convergencia exige alerta no ataque base e em todas as variantes configuradas.

## Experiment Record

```text
results/{experiment_id}/
├── experiment.json
├── metrics.csv
└── pcaps/
```

`metrics.csv` tem uma linha por execucao:

```text
iteration, execution_type, attack_id, arguments, fired, evasion_rationale
```

## Schemas

```python
class AttackPlan(BaseModel):
    attack_id: str
    arguments: list[str]
    evasion_rationale: str

class VariantResult(BaseModel):
    attack_id: str
    arguments: list[str]
    fired: bool
```

## Configuration

```yaml
testbed:
  ids_alert_log_path: /var/log/snort/alert
  ids_rules_file_path: /home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/temp/rules_farmer_ai.rules
  ids_rules_include_file_path: /home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/all.rules
  ids_rule_include_statement: include rules/temp/rules_farmer_ai.rules
  ids_container_name: snort_ids
  ids_snort_config_path: /opt/snort3/etc/snort/snort.lua
  attacker_attacks_root: /home/unipampa/ataques/attackers-claude
  attacker_capture_interface: any
  sid_counter_file_path: ./data/sid_counter.json
  results_output_dir: ./results
```

Any config value can be overridden with environment variables using `__`, for example `TESTBED__ATTACKER_CAPTURE_INTERFACE=ens33`.

## Security Model

O sistema assume rede isolada. SSH usa chaves configuradas pelo operador. Nao ha autenticacao adicional.

## Structured Errors

| Error | When raised |
|---|---|
| `UnmappedIntentError` | `attack_id` escolhido nao foi descoberto |
| `AttackPlanValidationError` | Quantidade de argumentos invalida apos retries |
| `SIDCounterCorruptedError` | Contador de SID ausente ou corrompido |
| `IDSReloadError` | Snort nao volta a rodar apos reload |
| `PCAPRetrievalError` | PCAP remoto nao pode ser copiado |
| `SSHUnreachableError` | SSH falha apos tentativas configuradas |

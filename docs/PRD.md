# PRD — Rules Farmer

## Problema

Operadores precisam criar regras IDS eficazes, mas escrever regras Snort exige conhecimento de sintaxe e do comportamento dos ataques. Regras ruins podem falhar silenciosamente. O projeto automatiza geracao, injecao, execucao de ataque e feedback para reduzir esse ciclo manual.

## Solucao

Um sistema multiagente que recebe uma intencao textual do operador, gera regras Snort, valida e injeta essas regras no IDS, descobre ataques disponiveis no host atacante pela estrutura de diretorios existente, executa ataques Docker, captura PCAPs e itera ate convergir ou atingir o limite configurado.

## Interfaces do Operador

### CLI

O modo principal para execucao local e:

```bash
uv run --python 3.12 rules-farmer
```

O processo aguarda uma intencao textual:

```text
Intent: Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888
```

A CLI registra progresso em tempo real no terminal e em `output.log`, com banners de fase como `<------------- AGORA ESTA RODANDO O ATACANTE ------------->`. O nivel padrao mostra etapas, resumos, avisos e erros; detalhes repetitivos ficam em `DEBUG`. O log cobre carregamento de configuracao, conexoes SSH, descoberta de ataques, geracao/validacao/injecao de regras, execucao de ataques, checagem de alertas e erro com traceback quando a execucao para.

### API Opcional

```text
POST /experiments
GET /experiments/{id}
```

Somente a Entidade 1 expoe HTTP. Entidade 2 e Entidade 3 sao acessadas por SSH.

## Estrutura de Ataques

O sistema nao declara ataques em `config.yaml` nem em codigo. Na inicializacao, ele descobre ataques em:

```yaml
testbed:
  attacker_attacks_root: /home/unipampa/ataques/attackers-claude
```

Cada ataque deve ser um subdiretorio:

```text
<attack_id>/
├── README.md
├── Dockerfile
└── entrypoint.sh
```

Contrato extraido:

- `attack_id`: nome do subdiretorio.
- `docker_image`: token `...:latest` encontrado em exemplo `docker run` no README. Fallback: `iotedu-attack-{attack_id}:latest`.
- `required_arguments`: nomes entre `<...>` na linha `usage: entrypoint.sh <...>`.
- `description`: primeira linha `>` do README, ou o titulo.

## Estrutura IDS

O IDS segue a estrutura Snort observada:

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

O arquivo de regra gerada e configurado em `testbed.ids_rules_file_path`. O injector garante que `testbed.ids_rules_include_file_path` contenha `testbed.ids_rule_include_statement`, de forma que o `rules/all.rules` carregue a regra temporaria. O container reiniciado e `testbed.ids_container_name`.

## Componentes

| Componente | Responsabilidade |
|---|---|
| Orchestrator | Controla iteracoes, parada e persistencia |
| Rule Agent | Gera regras Snort com `sid:0;` |
| SID Manager | Atribui SIDs unicos e persiste mapeamentos |
| IDS Rule Validator | Valida regras no host IDS via SSH |
| IDS Rule Injector | Escreve regra, reinicia Snort e aguarda saude |
| Remote Attack Discovery | Descobre ataques pela estrutura real na Entidade 3 |
| Attacker Agent | Escolhe `attack_id` descoberto e argumentos posicionais |
| Attack Executor | Cria temp dir remoto, captura PCAP e roda `docker run` |
| IDS Monitor | Verifica se o SID ativo disparou alerta |
| Experiment Recorder | Grava JSON, CSV e PCAPs por experimento |

## Schemas

```python
class RuleAgentOutput(BaseModel):
    rules: list[str]
    diagnosis: str | None

class AttackPlan(BaseModel):
    attack_id: str
    arguments: list[str]
    evasion_rationale: str

class VariantResult(BaseModel):
    attack_id: str
    arguments: list[str]
    fired: bool

class FeedbackPayload(BaseModel):
    pcap_summary: str
    ids_logs: str
    evasion_rationale: str
```

## Loop de Execucao

1. Operador informa intencao via CLI ou API.
2. Rule Agent gera uma ou mais regras.
3. Validator testa sintaxe.
4. SID Manager substitui `sid:0;`.
5. Injector escreve a regra e reinicia Snort.
6. Attacker Agent seleciona ataque descoberto e argumentos.
7. Attack Executor cria `/tmp/rules-farmer-attack-*`, captura PCAP com `tcpdump`, roda Docker e copia PCAP para `results/`.
8. IDS Monitor verifica alerta pelo SID.
9. Se nao disparar, o feedback volta ao Rule Agent.
10. O loop para em convergencia ou `max_iterations`.

## Artefatos

```text
results/{experiment_id}/
├── experiment.json
├── metrics.csv
└── pcaps/
```

`metrics.csv` contem:

```text
iteration, execution_type, attack_id, arguments, fired, evasion_rationale
```

## Erros Estruturados

| Erro | Quando ocorre |
|---|---|
| `UnmappedIntentError` | O Attacker Agent escolhe um `attack_id` que nao foi descoberto |
| `AttackPlanValidationError` | Numero de argumentos nao bate com `entrypoint.sh` apos retries |
| `SIDCounterCorruptedError` | Contador de SID ausente ou corrompido |
| `IDSReloadError` | Container Snort nao volta a rodar apos reload |
| `PCAPRetrievalError` | PCAP remoto nao foi encontrado ou nao pode ser copiado |
| `SSHUnreachableError` | SSH falha apos retries |

## Fora de Escopo

- Isolamento de rede automatizado.
- Autenticacao HTTP.
- Dashboard web.
- Geracao de trafego legitimo para falsos positivos.
- Execucao paralela de multiplos experimentos.

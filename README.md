# Rules Farmer

Rules Farmer é um sistema multiagente baseado em **agno** que gera regras Snort 3.9.7.0 a partir de uma intenção em linguagem natural, injeta a regra no IDS, executa um ataque real em um testbed isolado e itera com feedback até convergir ou exaurir o orçamento de tentativas.

## Topologia

| Entidade | Responsabilidade | Acesso |
|---|---|---|
| Entidade 1 | Aplicação Rules Farmer (Orchestrator, agentes agno, CLI/API) | Local |
| Entidade 2 | Snort IDS no container `snort_ids` | SSH a partir da Entidade 1 |
| Entidade 3 | Diretórios de ataques e imagens Docker | SSH/SCP a partir da Entidade 1 |
| Entidade 4 | Alvo do tráfego | Rede do testbed |

Somente a Entidade 1 expõe HTTP. As Entidades 2 e 3 são acessadas por SSH (chaves pré-configuradas).

## Arquitetura

```
src/rules_farmer/
├── agents/                  Agentes agno
│   ├── rules_agent.py       Driver do ciclo de regras (output_schema=IterationResult)
│   └── attacker_agent.py    Executa ataques (output_schema=AttackerResult)
├── skills/                  Pacotes SKILL.md (progressive discovery agno)
│   ├── rules/               Skills do Rules Agent
│   │   ├── snort-rule-generation/   SKILL.md + references/
│   │   ├── rule-validation-workflow/
│   │   ├── rule-deployment/
│   │   ├── alert-interpretation/
│   │   └── iteration-recording/
│   ├── attacks/             Skills do Attack Agent
│   │   ├── attack-selection/
│   │   ├── attack-execution/
│   │   └── evasion-variants/ SKILL.md + references/
│   ├── references/          10 playbooks de refinamento por ataque (Rules Agent)
│   │   ├── mqtt-bruteforce/         SKILL.md + references/refinamento.md
│   │   ├── mqtt-lwt-abuse/
│   │   ├── mqtt-publisher-flood/
│   │   ├── mqtt-qos-amplification/
│   │   ├── xrce-dds-entity-flood/
│   │   ├── xrce-dds-fragment-abuse/
│   │   ├── xrce-dds-malformed-inject/
│   │   ├── xrce-dds-session-hijack/
│   │   ├── xrce-dds-time-desync/
│   │   └── xrce-dds-udp-dos/
│   └── shared/
│       ├── experiment-cycle/   Protocolo do ciclo (ambos agentes)
│       └── attack-destinations/ Constraint de IP/porta fixas (ambos agentes)
├── tools/                   Tool factories agno (@tool wrappers)
│   ├── rule_tools.py        validate_rule_syntax, assign_sid, deploy_rule
│   ├── monitor_tools.py     check_alert_fired
│   ├── attack_tools.py      list_available_attacks, read_attack_definition, execute_attack
│   ├── persistence_tools.py record_iteration
│   └── inter_agent_tools.py trigger_attacker
├── orchestrator.py          Loop externo do variant_count
├── app_factory.py           Cria modelo agno (Anthropic/OpenAI/Groq/DeepSeek) e wirea tudo
├── config.py                Pydantic schema do config.yaml
├── ssh.py, ids_*.py, attack_*.py, sid_manager.py, experiment_recorder.py
├── cli.py, api.py, execution_logging.py
```

**Princípios da arquitetura agno:**

- **Skills** (`skills/<category>/<name>/SKILL.md`) = conhecimento de domínio carregado **sob demanda** via `get_skill_instructions(name)`. O agente vê só um sumário XML no system prompt; carrega o SKILL.md completo + `references/` apenas quando precisa.
- **Tools** (`tools/*.py`) = funções Python decoradas com `@tool` para operações com side effect (SSH, escrita de arquivo, invocação do sub-agente).
- **Agentes** combinam `skills=Skills(loaders=[LocalSkills(...)])` + `tools=[...]` + `output_schema=PydanticModel`.
- **Skills de refinamento por ataque** (`skills/references/<attack-id>/`) — 10 playbooks (um por ataque do testbed) com hipóteses de detecção e catálogo de mutações de evasão, carregados pelo Rules Agent. Cada um aponta para `references/refinamento.md` com o conteúdo completo (em pt-BR).

## Estrutura Esperada no Testbed

IDS na Entidade 2:

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

Ataques na Entidade 3:

```text
~/ataques/attackers-claude/
└── <attack_id>/
    ├── README.md       # contém exemplo `docker run ...:latest "<arg1>" "<arg2>" ...`
    ├── Dockerfile
    └── entrypoint.sh   # contém `usage: entrypoint.sh <arg1> <arg2> ...`
```

O sistema não mantém lista interna de ataques. Ao iniciar, ele acessa `testbed.attacker_attacks_root`, encontra subdiretórios com `entrypoint.sh`, lê o `README.md`, extrai a imagem Docker e os argumentos obrigatórios — o catálogo descoberto é injetado no system prompt do Attack Agent.

## Instalar

```bash
uv sync --python 3.12
```

Se `uv` reclamar de permissão no cache: `UV_CACHE_DIR=/tmp/uv-cache uv sync --python 3.12`.

Crie `.env` ao lado de `config.yaml` (ou exporte direto no shell):

```bash
ANTHROPIC_API_KEY=sk-...
OPENAI_API_KEY=sk-...
GROQ_API_KEY=...
DEEPSEEK_API_KEY=...
```

Você só precisa da chave do provider que estiver em `config.yaml` — agno lê do ambiente. As demais ficam vazias.

Inicialize o contador de SID. Use o snippet Python abaixo — ele funciona em Linux, macOS e Windows e garante UTF-8 (o `>` do PowerShell 5.1 escreve UTF-16 e quebra a leitura):

```bash
uv run --python 3.12 python -c "from pathlib import Path; import json; p = Path('data/sid_counter.json'); p.parent.mkdir(exist_ok=True); p.exists() or p.write_text(json.dumps({'counter': 9000000}, indent=2), encoding='utf-8')"
```

Se o arquivo já existir com encoding errado (UTF-16 BOM, comum quando criado via `echo > file.json` no PowerShell), o SID Manager já tolera a leitura e regrava em UTF-8 limpo no primeiro `assign_sid`.

## Configurar

`config.yaml`:

```yaml
llm:
  rule_agent:
    provider: anthropic        # anthropic | openai | groq | deepseek
    model: claude-sonnet-4-6
    temperature: 0
    max_tokens: 8192
  attacker_agent:
    provider: anthropic
    model: claude-sonnet-4-6
    temperature: 0
    max_tokens: 8192

timeouts:
  attack_tool_seconds: 60
  attack_tool_extension_seconds: 30
  ssh_connect_seconds: 10

ssh:
  entity2_host: 192.168.137.1
  entity2_user: gtiotedu
  entity2_key_path: ~/.ssh/id_ed25519_vitima
  entity3_host: 192.168.137.94
  entity3_user: unipampa
  entity3_key_path: ~/.ssh/id_ed25519_atacante

ssh_retry:
  max_attempts: 3
  base_delay_seconds: 1

experiment_defaults:
  max_iterations: 10           # regenerações de regra permitidas por variant cycle
  variant_count: 3             # variantes do ataque após o base (total: base + 3 variantes)

testbed:
  ids_alert_log_path: /home/gtiotedu/ataques-regras-e-assinaturas/snort/logs/alert_fast.txt
  ids_rules_file_path: /home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/temp/rules_farmer_ai.rules
  ids_rules_include_file_path: /home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/all.rules
  ids_rule_include_statement: include rules/temp/rules_farmer_ai.rules
  ids_container_name: snort_ids
  ids_snort_config_path: /opt/snort3/etc/snort/snort.lua
  attacker_attacks_root: /home/unipampa/ataques-artigo
  attacker_capture_interface: any
  sid_counter_file_path: ./data/sid_counter.json
  experiment_counter_file_path: ./data/experiment_counter.json
  results_output_dir: ./results

# Destino fixo por família de ataque. Os agentes NUNCA mutam IP/porta — só argumentos que NÃO
# sejam destino (rate, payload size, source port, timing).
attack_destinations:
  mqtt:
    ip: 172.17.0.2
    port: 1883
  xrce:
    ip: 172.17.0.2
    port: 8888
```

### Pré-processamento de intent

Ao iniciar um experimento, o Orchestrator inspeciona a intent do operador:

- intent contém `mqtt` (case-insensitive) → resolve `attack_destinations.mqtt` (IP/porta 1883)
- intent contém `xrce`, `dds` ou `rtps` → resolve `attack_destinations.xrce` (IP/porta 8888)
- nenhum match → `fixed_destination=None` (agentes recebem aviso)

O `fixed_destination` resolvido é injetado:
1. **No prompt do Rules Agent** — para que o cabeçalho da regra Snort use IP/porta corretos.
2. **No `AttackerRequest`** — para que o Attack Agent atribua corretamente argumentos `target_ip`/`port` quando o ataque escolhido os exige.
3. **Na skill `attack-destinations`** (carregada por ambos agentes) — explicitando que IP/porta NUNCA podem ser mutados em variantes.

Chaves SSH precisam funcionar da Entidade 1 para 2 e 3 antes de rodar o sistema.

Override de qualquer campo via env: `LLM__RULE_AGENT__MODEL=gpt-5 uv run rules-farmer` (duplo underline `__` é separador de nível).

## Rodar pela CLI

```bash
uv run --python 3.12 rules-farmer
```

A CLI imprime os banners de fase em tempo real no terminal e em `output.log`. Digite a intenção quando aparecer o prompt:

```text
Intent: Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888
```

Para acompanhar em outro terminal:

```bash
tail -f output.log
```

## Rodar pela API

```bash
uv run --python 3.12 uvicorn rules_farmer.app_factory:create_real_app --factory --host localhost --port 8000
```

Submeter experimento:

```bash
curl -X POST http://localhost:8000/experiments \
  -H 'content-type: application/json' \
  -d '{"intent":"Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888"}'
```

Consultar status:

```bash
curl http://localhost:8000/experiments/<experiment_id>
```

## Logs e Observabilidade

`output.log` recebe a mesma trilha do terminal. A granularidade INFO mostra:

**Banners de fase** (`<------------- MENSAGEM ------------->`):

| Banner | Origem |
|---|---|
| `MONTANDO COMPONENTES` / `CONECTANDO NO IDS` / `CONECTANDO NO ATACANTE` / `DESCOBRINDO ATAQUES DISPONIVEIS` / `RUNTIME PRONTO` | `app_factory.py` |
| `INTENCAO RECEBIDA` / `MONTANDO RUNTIME` / `INICIANDO EXPERIMENTO` / `EXECUCAO FINALIZADA` | `cli.py` |
| `EXPERIMENTO INICIADO` / `AGORA ESTA RODANDO BASE` ou `AGORA ESTA RODANDO VARIANT_N` / `EXPERIMENTO CONVERGIU` / `EXPERIMENTO FALHOU` / `EXPERIMENTO PAROU COM ERRO` | `orchestrator.py` |
| `AGORA O AGENTE DE REGRAS ESTA RACIOCINANDO` | Rules Agent (`agents/rules_agent.py`) |
| `AGORA O AGENTE DE ATAQUES ESTA RACIOCINANDO` | Attack Agent (`agents/attacker_agent.py`) |
| `AGORA ESTA VALIDANDO A REGRA` | Tool `validate_rule_syntax` |
| `AGORA ESTA INJETANDO A REGRA NO IDS` | Tool `deploy_rule` |
| `AGORA ESTA PLANEJANDO O ATAQUE` | Tool `trigger_attacker` |
| `AGORA ESTA RODANDO O ATACANTE` | Tool `execute_attack` |
| `AGORA ESTA VERIFICANDO ALERTAS DO IDS` | Tool `check_alert_fired` |

**Mensagens INFO** detalhadas por chamada de tool (SID atribuído, regra deployada, attack_id escolhido, exit code do container, se o alerta disparou).

**Mensagens DEBUG** (silenciadas por padrão) incluem caminhos SFTP, tamanho dos buffers, polls do container Snort.

Para subir o nível de detalhe, edite `configure_execution_logging(level=logging.DEBUG)` em `cli.py` ou `app_factory.py`.

## Testar

A suíte cobre os componentes determinísticos (SSH, attack discovery, attack executor, IDS rule validator/injector/monitor, SID manager, experiment recorder), os tool factories agno, a carga dos pacotes SKILL.md, e o wiring dos agentes (com `_agent.run` mockado para não consumir tokens de LLM real).

```bash
uv run --python 3.12 pytest -q
```

Saída esperada: `80 passed`.

Para focar em uma área:

```bash
uv run --python 3.12 pytest tests/test_rule_agent.py -v          # agente de regras
uv run --python 3.12 pytest tests/test_attacker_agent.py -v      # agente de ataques
uv run --python 3.12 pytest tests/test_orchestrator.py -v        # loop de variant_count
uv run --python 3.12 pytest tests/test_tools.py -v               # tool factories
uv run --python 3.12 pytest tests/test_skills_loading.py -v      # carga das SKILL.md
```

## Ver Funcionando Localmente (sem testbed)

Você pode subir a API com um orchestrator stub que não toca SSH/Docker:

```bash
uv run --python 3.12 uvicorn rules_farmer.dev_server:create_dev_app --factory --host localhost --port 8000
```

`POST /experiments` retorna um experiment_id imediatamente, `GET /experiments/<id>` devolve um resultado fake "converged". Útil para validar contratos de API.

Para verificar que os agentes agno foram corretamente montados sem rodar contra o testbed real:

```bash
uv run --python 3.12 python -c "
import os; os.environ.setdefault('ANTHROPIC_API_KEY', 'sk-test')
from unittest.mock import MagicMock
from rules_farmer.agents import RulesAgent, AttackerAgent
from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.config import AgentModelConfig
from rules_farmer.app_factory import _create_agno_model

cfg = AgentModelConfig(provider='anthropic', model='claude-sonnet-4-6', temperature=0, max_tokens=8192)
attacks = [DiscoveredAttack(attack_id='x', remote_path='/', description='x', docker_image='x:latest', required_arguments=['a'], readme_excerpt='')]
attacker = AttackerAgent(_create_agno_model(cfg), attacks, executor=MagicMock())
print('AttackerAgent skills:', attacker._agent.skills.get_skill_names())
print('AttackerAgent tools:', [t.name for t in attacker._agent.tools])

rules = RulesAgent(_create_agno_model(cfg), MagicMock(), MagicMock(), MagicMock(), MagicMock(), attacker, MagicMock())
print('RulesAgent skills:', rules._agent.skills.get_skill_names())
print('RulesAgent tools:', [t.name for t in rules._agent.tools])
"
```

## Saída de Cada Experimento

```text
results/{experiment_id}/
├── experiment.json    Lista completa de executions com attack_id, arguments, rule, fired, etc.
└── metrics.csv        Uma linha por execution com iteration, execution_type, attack_id, arguments, container_exit_code, fired, evasion_rationale, rule.
```

Captura de PCAP foi removida — o feedback de evasão agora vem apenas de `container_exit_code` + `container_stderr` + presença/ausência de alerta no IDS.

## Decisões de Arquitetura

Veja `docs/adr/` para registros das decisões:

- `0001-rest-communication-between-entities.md` — Por que SSH/paramiko entre entidades em vez de REST.
- `0002-attack-skills-architecture.md` — Por que descoberta dinâmica de ataques em vez de lista fixa.

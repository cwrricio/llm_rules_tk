# Rules Farmer — Geração Autônoma de Regras Snort por Agentes LLM

Rules Farmer é um sistema **multiagente** baseado em **[agno](https://github.com/agno-agi/agno)** que gera regras Snort 3.9.7.0 a partir de uma intenção em linguagem natural, injeta a regra em um IDS real, executa um ataque em um testbed isolado e itera com o *feedback* do próprio IDS até convergir ou exaurir o orçamento de tentativas. Um segundo agente atua como atacante: além de escolher e parametrizar o ataque, ele **muta o código-fonte do ataque e reconstrói a imagem Docker** para produzir variantes evasivas, exercitando a robustez da regra gerada.

> **Sobre este README.** Este documento segue o roteiro de reprodutibilidade do **Salão de Ferramentas do SBSeg**. As seções **Teste mínimo** e **Experimentos** são autocontidas: o **Teste mínimo roda offline**, sem testbed, sem Docker e sem chaves de API. A reprodução completa dos **Experimentos** exige o testbed de 4 entidades descrito adiante.

---

## Selos considerados

Os autores solicitam a avaliação dos seguintes selos:

| Selo | Sigla | Justificativa |
|---|---|---|
| **Disponível** | SeloD | Código-fonte público, versionado em Git, com `README.md` e licença. |
| **Funcional** | SeloF | O **Teste mínimo** (adiante) demonstra o sistema funcionando de ponta a ponta sem infraestrutura externa: um **ciclo real de detecção contra um contêiner Snort 3 local** (valida regra, injeta, dispara alerta em ataque e não dispara em tráfego benigno), além de suíte de testes (`80 passed`), montagem dos agentes agno e a API em modo *stub*. |
| **Sustentável** | SeloS | Arquitetura modular documentada (agentes/skills/tools separados), suíte de testes determinística, ADRs em `docs/adr/` e documentação de contexto em `CONTEXT.md`. |

O **Selo Reprodutível (SeloR)** depende do testbed físico descrito na seção **Experimentos** e das chaves de API de um provedor LLM; não é reproduzível apenas com o pacote de código. O roteiro completo está documentado para permitir a reprodução por quem dispuser do ambiente.

---

## Informações básicas

**Ambiente validado pelos autores (Entidade 1 — aplicação):**

| Item | Versão / valor |
|---|---|
| Sistema operacional | Linux (kernel 7.0.0) — também roda em macOS e Windows |
| Python | 3.12 (validado com 3.12.3) |
| Gerenciador de pacotes | [`uv`](https://docs.astral.sh/uv/) 0.11+ |
| Framework de agentes | agno ≥ 2.2 |
| Provedor LLM | Anthropic / OpenAI / Groq / DeepSeek (configurável) |
| Hardware | Qualquer máquina capaz de rodar Python 3.12; o custo real é o das chamadas de LLM |

O **Teste mínimo** não requer GPU, chave de API nem SSH. Seu teste principal (T1) precisa apenas de **Docker** (roda um contêiner Snort 3 local); os complementares (T2–T4) dispensam até o Docker. Os **Experimentos** completos exigem, adicionalmente, o testbed descrito adiante (IDS Snort em contêiner, host atacante com Docker, rede isolada) e uma chave de LLM.

**Topologia do testbed (para os Experimentos):**

| Entidade | Responsabilidade | Acesso |
|---|---|---|
| Entidade 1 | Aplicação Rules Farmer (Orchestrator, agentes agno, CLI/API) | Local |
| Entidade 2 | Snort IDS no container `snort_ids` | SSH a partir da Entidade 1 |
| Entidade 3 | Diretórios de ataques e imagens Docker | SSH/SCP a partir da Entidade 1 |
| Entidade 4 | Alvo do tráfego | Rede do testbed |

Somente a Entidade 1 expõe HTTP. As Entidades 2 e 3 são acessadas por SSH (chaves pré-configuradas).

---

## Dependências

**Para o Teste mínimo:**

- Python 3.12
- `uv` (instala o restante automaticamente a partir de `pyproject.toml` / `uv.lock`)
- **Docker** — necessário apenas para o teste principal T1 (contêiner Snort 3 local); os complementares T2–T4 dispensam Docker

As dependências Python são fixadas em `uv.lock` e resolvidas por `uv sync`: `agno`, `anthropic`, `openai`, `fastapi`, `uvicorn`, `paramiko`, `pydantic`, `pyyaml`, além de `pytest` (grupo `dev`). **Nenhuma chave de API é necessária para o Teste mínimo.**

**Para os Experimentos completos, adicionalmente:**

- Chave de API do provedor LLM configurado em `config.yaml` (ex.: `ANTHROPIC_API_KEY`).
- Testbed de 4 entidades com o IDS Snort 3.9.7.0 em contêiner e o host atacante com Docker.
- Acesso SSH por chave da Entidade 1 para as Entidades 2 e 3.

---

## Preocupações com segurança

**Esta ferramenta gera e executa ataques de rede reais.** Trate-a como uma ferramenta ofensiva de laboratório:

- Os **Experimentos** disparam ataques (flood UDP, brute force MQTT, malformações XRCE-DDS etc.) contra o alvo do testbed. **Execute-os exclusivamente em rede isolada e em máquinas que você controla e está autorizado a atacar.** Nunca aponte o sistema para hosts de produção ou de terceiros.
- O agente atacante **modifica código-fonte e reconstrói imagens Docker** no host atacante (Entidade 3) via SSH. Use uma máquina dedicada e descartável para esse papel.
- O sistema **assume rede confiável e isolada**: o SSH usa chaves configuradas pelo operador e não há autenticação adicional entre entidades (ver `docs/adr/0001-*`).
- **Segredos:** as chaves de API ficam em `.env` (nunca versionado — ver `.gitignore`). Use `.env.example` como modelo.
- O **Teste mínimo é inofensivo**: não executa ataques nem gera tráfego real. O T1 sobe um contêiner Snort **local e isolado** (`--network none`, sem privilégios, rodando com o UID do usuário) que apenas lê PCAPs sintéticos minúsculos em modo *read-file*; os complementares T2–T4 não sobem contêiner algum.

---

## Instalação

```bash
uv sync --python 3.12
```

Se `uv` reclamar de permissão no cache: `UV_CACHE_DIR=/tmp/uv-cache uv sync --python 3.12`.

Isso basta para rodar o **Teste mínimo**. Os passos abaixo (`.env` e contador de SID) só são necessários para os **Experimentos**.

Crie `.env` ao lado de `config.yaml` (copie de `.env.example`):

```bash
ANTHROPIC_API_KEY=sk-...
OPENAI_API_KEY=sk-...
GROQ_API_KEY=...
DEEPSEEK_API_KEY=...
```

Você só precisa da chave do provider que estiver em `config.yaml` — agno lê do ambiente. As demais ficam vazias.

Inicialize o contador de SID (funciona em Linux, macOS e Windows e garante UTF-8):

```bash
uv run --python 3.12 python -c "from pathlib import Path; import json; p = Path('data/sid_counter.json'); p.parent.mkdir(exist_ok=True); p.exists() or p.write_text(json.dumps({'counter': 9000000}, indent=2), encoding='utf-8')"
```

---

## Teste mínimo

Objetivo: **o avaliador executa e valida o funcionamento da ferramenta** — sem testbed remoto, sem SSH e sem chaves de API. O teste principal (**T1**) roda o **ciclo real de detecção** da ferramenta contra um contêiner Snort 3 local; os complementares (T2–T4) confirmam, sem Docker, que o sistema está corretamente construído.

### T1 — Ciclo de detecção contra Snort real (auto-contido, **principal**)

Executa o motor de detecção da ferramenta de ponta a ponta contra um **contêiner Snort 3 local**, dirigindo as **classes de produção reais** (`SnortRuleValidator`, `IDSRuleInjector`, `IDSMonitor`) por meio de um `LocalCommandClient` que substitui o `SSHClient` e roda comandos localmente. **Não** requer SSH, testbed, chave de LLM, nem captura de pacotes ao vivo (sem `sudo`/privilégios) — **só Docker**. O tráfego de ataque é fornecido como PCAPs minúsculos reproduzidos pelo Snort em modo *read-file*, de forma determinística.

```bash
uv run --python 3.12 python teste_minimo/run_teste_minimo.py
```

Verifica: (1) regra válida **aceita** pelo Snort real; (2) regra impossível de parsear **rejeitada** com o erro do Snort; (3) após injetar a regra, um PCAP de ataque **dispara** o alerta; (4) tráfego benigno **não** dispara (sem falso positivo).

**Saída esperada** (código de saída `0`):

```text
  [PASS  ] Regra valida aceita pelo Snort real
  [PASS  ] Regra invalida rejeitada pelo Snort real
  [PASS  ] Ataque detectado (alerta disparado)
  [PASS  ] Trafego benigno NAO dispara alerta
  RESULTADO: TODOS OS TESTES PASSARAM [OK]
```

A primeira execução puxa a imagem base do Snort 3 (~1.8 GB). Detalhes em [`teste_minimo/README.md`](teste_minimo/README.md).

### T2 — Suíte de testes automatizados (offline)

Cobre os componentes determinísticos (SSH, descoberta de ataques, executor de ataques, validador/injetor/monitor do IDS, gerenciador de SID, gravador de experimentos), os *tool factories* agno, a carga dos pacotes `SKILL.md` e o *wiring* dos agentes (com `_agent.run` mockado — **não consome tokens de LLM**).

```bash
uv run --python 3.12 pytest -q
```

**Saída esperada:** `80 passed`.

Para focar em uma área:

```bash
uv run --python 3.12 pytest tests/test_rule_agent.py -v          # agente de regras
uv run --python 3.12 pytest tests/test_attacker_agent.py -v      # agente de ataques
uv run --python 3.12 pytest tests/test_orchestrator.py -v        # loop de variant_count
uv run --python 3.12 pytest tests/test_tools.py -v               # tool factories
uv run --python 3.12 pytest tests/test_skills_loading.py -v      # carga das SKILL.md
```

### T3 — Montagem dos agentes agno (offline)

Confirma que os dois agentes são montados com as skills e tools esperadas, usando uma chave *dummy* e *mocks* — nenhuma chamada de rede ou LLM ocorre.

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

rules = RulesAgent(_create_agno_model(cfg), MagicMock(), MagicMock(), MagicMock(), MagicMock(), attacker, MagicMock(), MagicMock())
print('RulesAgent skills:', rules._agent.skills.get_skill_names())
print('RulesAgent tools:', [t.name for t in rules._agent.tools])
"
```

**Saída esperada** (ordem das listas pode variar): o `AttackerAgent` expõe as tools `list_available_attacks`, `read_attack_definition`, `execute_attack`, `list_attack_files`, `read_attack_source_file`, `modify_attack_file`, `rebuild_attack_image`; o `RulesAgent` expõe `validate_rule_syntax`, `assign_sid`, `deploy_rule`, `trigger_attacker`, `check_alert_fired`, `record_iteration`, `get_validated_rules` e carrega, além das skills de workflow, os 10 *playbooks* de refinamento por ataque (`mqtt-*`, `xrce-dds-*`).

### T4 — API em modo *stub* (offline)

Sobe a API sem tocar em SSH/Docker, com um orchestrator *stub* que retorna um resultado convergido — útil para validar os contratos HTTP.

Terminal 1:

```bash
uv run --python 3.12 uvicorn rules_farmer.dev_server:create_dev_app --factory --host localhost --port 8000
```

Terminal 2:

```bash
curl -X POST http://localhost:8000/experiments \
  -H 'content-type: application/json' \
  -d '{"intent":"Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888"}'
# -> {"experiment_id":"<uuid>"}

curl http://localhost:8000/experiments/<uuid>
# -> {"status":"converged", "result": {...}}
```

**Saída esperada:** o `GET` retorna `"status": "converged"`.

---

## Experimentos

Esta seção reproduz o comportamento central do artigo: **a partir de uma intenção em linguagem natural, o sistema gera uma regra Snort, valida-a contra o ataque real e mede quantas iterações são necessárias até detectar o ataque base e suas variantes evasivas.** Requer o testbed completo.

### Configuração

O comportamento é controlado por `config.yaml`. Os campos centrais:

```yaml
llm:
  rule_agent:      { provider: anthropic, model: claude-sonnet-4-6, temperature: 0, max_tokens: 8192 }
  attacker_agent:  { provider: anthropic, model: claude-sonnet-4-6, temperature: 0, max_tokens: 8192 }

experiment_defaults:
  max_iterations: 10          # tentativas internas do LLM para gerar regra que detecte em um ciclo
  variant_count: 49           # variações do ataque após o base (total: 1 base + 49 variantes)
  continue_on_failure: true
  convergence_threshold: 20   # nº de variantes consecutivas detectadas para declarar "converged"

testbed:
  ids_alert_log_path: .../snort/logs/alert_fast.txt
  ids_rules_file_path: .../snort/rules/temp/rules_farmer_ai.rules
  ids_container_name: snort_ids
  attacker_attacks_root: /home/unipampa/ataques-artigo
  results_output_dir: ./results

attack_destinations:          # destino FIXO por família; os agentes NUNCA mutam IP/porta
  mqtt: { ip: 172.17.0.2, port: 1883 }
  xrce: { ip: 172.17.0.2, port: 8888 }
```

Qualquer campo pode ser sobrescrito por variável de ambiente com `__` como separador de nível: `LLM__RULE_AGENT__MODEL=gpt-5 uv run rules-farmer`.

As chaves SSH precisam funcionar da Entidade 1 para as Entidades 2 e 3 **antes** de rodar.

### Estrutura esperada no testbed

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
<attacker_attacks_root>/
└── <attack_id>/
    ├── README.md       # contém exemplo `docker run ...:latest "<arg1>" "<arg2>" ...`
    ├── Dockerfile
    └── entrypoint.sh   # contém `usage: entrypoint.sh <arg1> <arg2> ...`
```

O sistema **não** mantém lista interna de ataques: ao iniciar, ele acessa `attacker_attacks_root`, encontra subdiretórios com `entrypoint.sh`, lê o `README.md`, extrai a imagem Docker e os argumentos obrigatórios — o catálogo descoberto é injetado no *system prompt* do Attack Agent (ver `docs/adr/0002-*`).

### Execução — um experimento

Via CLI (lê a intenção do `stdin`):

```bash
uv run --python 3.12 rules-farmer
# Intent: Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888
```

Acompanhe em outro terminal com `tail -f output.log`.

Via API real:

```bash
uv run --python 3.12 uvicorn rules_farmer.app_factory:create_real_app --factory --host localhost --port 8000
curl -X POST http://localhost:8000/experiments -H 'content-type: application/json' \
  -d '{"intent":"Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888"}'
```

### Execução — lote (todas as famílias de ataque)

```bash
./scripts/run_all_attacks.sh
# ou um subconjunto:
ATTACKS="xrce-dds-udp-dos mqtt-bruteforce" ./scripts/run_all_attacks.sh
```

O script roda um experimento por família (10 no total), cada um com `1 base + variant_count variantes`, e acumula em `data/validated_rules/<attack_id>.rules` as regras que detectaram (`fired=True`), consultadas pelo Rules Agent antes de gerar novas regras da mesma família.

### Saída de cada experimento e *claims* verificáveis

```text
results/{experiment_id}/
├── experiment.json    # todas as execuções: attack_id, arguments, rule, fired, evasion_rationale, ...
└── metrics.csv        # 1 linha por execução: iteration, execution_type, attack_id, arguments,
                       #   container_exit_code, fired, evasion_rationale, rule
```

*Claims* que podem ser inspecionados nesses artefatos:

1. **Tradução de intenção → regra válida**: cada `experiment.json` contém uma regra Snort sintaticamente válida (validada no IDS antes do *deploy*) para a intenção fornecida.
2. **Convergência via feedback**: `metrics.csv` mostra a sequência de iterações até `fired=True` no ataque base — o número de iterações é a métrica de convergência.
3. **Robustez a evasão**: as linhas de variante mostram se a regra continua detectando (`fired`) mutações do ataque geradas pelo agente atacante.

> **Análise crítica dos resultados.** `docs/analise_convergencia.md` documenta, com honestidade científica, limitações observadas (ex.: convergência espúria por regras genéricas demais / falsos positivos) e as correções propostas. Recomenda-se lê-lo ao interpretar os `results/`.

---

## Arquitetura

```
src/rules_farmer/
├── agents/                  Agentes agno
│   ├── rules_agent.py       Driver do ciclo de regras (output_schema=IterationResult)
│   └── attacker_agent.py    Executa e muta ataques (output_schema=AttackerResult)
├── skills/                  Pacotes SKILL.md (progressive discovery agno)
│   ├── rules/               snort-rule-generation, rule-validation-workflow, rule-deployment,
│   │                        alert-interpretation, iteration-recording, validated-rules-library
│   ├── attacks/             attack-selection, attack-execution, evasion-variants
│   │   └── evasion-variants/references/<attack-id>/   10 playbooks de refinamento por ataque
│   └── shared/              experiment-cycle, attack-destinations
├── tools/                   Tool factories agno (@tool wrappers)
│   ├── rule_tools.py        validate_rule_syntax, assign_sid, deploy_rule
│   ├── monitor_tools.py     check_alert_fired
│   ├── attack_tools.py      list_available_attacks, read_attack_definition, execute_attack,
│   │                        list_attack_files, read_attack_source_file, modify_attack_file,
│   │                        rebuild_attack_image
│   ├── persistence_tools.py record_iteration
│   └── inter_agent_tools.py trigger_attacker
├── orchestrator.py          Loop externo do variant_count (base via LLM, variantes reusam a regra)
├── app_factory.py           Cria modelo agno e wirea tudo; dev_server.py monta a API stub
├── config.py                Pydantic schema do config.yaml
├── ssh.py, ids_*.py, attack_*.py, sid_manager.py, experiment_recorder.py, cli.py, api.py
```

**Princípios agno:** *Skills* (`SKILL.md`) carregam conhecimento de domínio **sob demanda** (`get_skill_instructions(name)`); *Tools* são funções `@tool` para operações com efeito colateral (SSH, escrita, invocação do subagente); *Agentes* combinam `skills` + `tools` + `output_schema` (Pydantic). Ver `CONTEXT.md`, `docs/system_overview.md` e `docs/adr/` para o detalhamento.

### Loop de feedback (resumo)

1. Operador fornece a intenção. 2. Rules Agent produz regra com `sid:0;`. 3. Validador testa sintaxe no IDS. 4. SID Manager atribui SID único. 5. Injetor escreve a regra, reinicia o Snort e limpa o *alert log*. 6. Attacker Agent seleciona `attack_id` e argumentos (e, em variantes, muta o código e reconstrói a imagem). 7. Executor roda `docker run` no host atacante. 8. Monitor verifica o alerta pelo SID. 9. Se não disparar, o *feedback* volta ao Rules Agent. A convergência exige alerta no ataque base e nas variantes configuradas.

---

## Logs e observabilidade

`output.log` recebe a mesma trilha do terminal. No nível INFO, banners de fase (`<------------- MENSAGEM ------------->`) marcam cada etapa (montagem de componentes, conexão ao IDS/atacante, raciocínio de cada agente, validação/injeção de regra, execução do ataque, verificação de alertas). Mensagens DEBUG (silenciadas por padrão) incluem caminhos SFTP e *polls* do contêiner. Para elevar o nível, edite `configure_execution_logging(level=logging.DEBUG)` em `cli.py`/`app_factory.py`.

---

## Decisões de arquitetura

- `docs/adr/0001-rest-communication-between-entities.md` — Por que SSH/paramiko entre entidades em vez de REST.
- `docs/adr/0002-attack-skills-architecture.md` — Por que descoberta dinâmica de ataques em vez de lista fixa.

---

## LICENSE

> **Pendente:** adicionar um arquivo `LICENSE` na raiz do repositório antes da submissão. O **Selo Disponível** exige uma licença explícita de código aberto (ex.: MIT, Apache-2.0 ou GPLv3). Enquanto o arquivo não existir, os termos de uso e redistribuição não estão definidos.
</content>

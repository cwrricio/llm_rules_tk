# Rules Farmer — Geração Autônoma de Regras Snort por Agentes LLM

Rules Farmer é um sistema **multiagente** baseado em **[agno](https://github.com/agno-agi/agno)** que gera regras Snort 3.9.7.0 a partir de uma intenção em linguagem natural, injeta a regra em um IDS Snort real, executa um ataque, e itera com o *feedback* do próprio IDS até **convergir** ou **esgotar o número de variantes**. Um segundo agente atua como atacante: além de escolher e parametrizar o ataque, ele **muta o código-fonte do ataque e reconstrói a imagem Docker** para produzir variantes evasivas, exercitando a robustez da regra gerada.

> **Sobre este README.** Segue o roteiro de reprodutibilidade do **Salão de Ferramentas do SBSeg**. O documento traz **um único fluxo de avaliação** (adiante), que o avaliador executa para testar a ferramenta de ponta a ponta. Esse fluxo roda **inteiramente em Docker local** — não precisa de testbed remoto, de SSH nem de múltiplas máquinas —, exigindo apenas **Docker + uma chave de API de um provedor LLM**.

---

## Selos considerados

Os autores solicitam a avaliação dos **quatro selos**:

| Selo | Sigla | Justificativa |
|---|---|---|
| **Disponível** | SeloD | Código-fonte público, versionado em Git, com `README.md` e **licença MIT** (arquivo [`LICENSE`](LICENSE)). |
| **Funcional** | SeloF | O **Fluxo de avaliação** (adiante) roda o pipeline completo de ponta a ponta em Docker local: gera regra pelo LLM, valida no Snort real, injeta, checa falso positivo, executa o ataque, detecta, muta o ataque e reconstrói a imagem, e grava os dados. Como evidência complementar de robustez, o projeto traz uma suíte de **80 testes** determinísticos (`uv run --python 3.12 pytest -q`). |
| **Sustentável** | SeloS | Arquitetura modular documentada (agentes / skills / tools separados), suíte de testes determinística, ADRs em `docs/adr/`, documentação de contexto em `CONTEXT.md` e `docs/system_overview.md`. |
| **Reprodutível** | SeloR | O fluxo é **reproduzível por qualquer avaliador** com Docker e uma chave de API. Gera artefatos inspecionáveis (`experiment.json`, `metrics.csv`, `mutations/`, `validated_rules/`). **Ressalva honesta:** o pipeline usa um LLM real, então a saída é **não determinística** — números exatos (regras, nº de iterações) variam entre execuções e **entre modelos**. O modelo usado no artigo foi o **`deepseek-v4-pro`**; modelos diferentes podem produzir resultados divergentes. |

---

## Informações básicas

**Ambiente validado pelos autores:**

| Item | Versão / valor |
|---|---|
| Sistema operacional | Linux (kernel 7.0) — também roda em macOS e Windows |
| Python | 3.12 (validado com 3.12.3) |
| Gerenciador de pacotes | [`uv`](https://docs.astral.sh/uv/) 0.11+ |
| Container runtime | Docker (baixa a imagem base do Snort 3, `ciscotalos/snort3`, ~1.8 GB na 1ª vez) |
| Framework de agentes | agno ≥ 2.2 |
| Provedor LLM | DeepSeek (artigo) — também Anthropic / OpenAI / Groq (configurável) |
| Hardware | Qualquer máquina capaz de rodar Docker + Python 3.12; o custo real é o das chamadas de LLM |

---

## Dependências

- **Docker** — roda o contêiner Snort 3 e os contêineres de ataque.
- **Python 3.12** + [`uv`](https://docs.astral.sh/uv/) — `uv` instala o restante a partir de `pyproject.toml` / `uv.lock` (`agno`, `anthropic`, `openai`, `fastapi`, `pydantic`, `pyyaml`, etc.; `pytest` no grupo `dev`).
- **Uma chave de API de LLM** — do provedor que você escolher (`deepseek`, `anthropic`, `openai` ou `groq`).

---

## Preocupações com segurança

**Esta ferramenta gera e muta ataques de rede reais.** Trate-a como ferramenta ofensiva de laboratório.

- **O fluxo de avaliação é seguro de rodar em qualquer máquina.** O contêiner de ataque **não transmite pacotes na rede** (`--network none`): ele **forja** os bytes exatos do ataque e os grava em um pcap, que o Snort real processa em modo *read-file*. O contêiner Snort também sobe isolado (`--network none`, sem privilégios, com o UID do usuário).
- O agente atacante **modifica código-fonte e reconstrói imagens Docker** localmente. As mutações ficam registradas em `results/<id>/mutations/`.
- **Segredos:** a chave de API fica em `.env` (nunca versionado — ver `.gitignore`) ou em variável de ambiente. Use `.env.example` como modelo.
- Fora deste pacote, a ferramenta **pode** disparar ataques de verdade contra um alvo de rede. Se você a apontar para um testbed com tráfego ao vivo, faça-o **exclusivamente em rede isolada e em máquinas que você controla e está autorizado a atacar**.

---

## Fluxo de avaliação

**Objetivo:** **auditar visualmente** o pipeline **inteiro** para um ataque (`xrce-dds-udp-dos`), do zero até **convergência** ou até **esgotar as variantes**. Siga os passos na ordem — **todos os comandos são executados a partir da raiz do repositório** (o diretório onde está `config.yaml`).

### Passo 1 — clonar o repositório e entrar na pasta

```bash
git clone https://github.com/cwrricio/llm_rules_tk.git
cd llm_rules_tk
```

**Todos os comandos seguintes são executados de dentro dessa pasta** (a raiz do repositório, onde está `config.yaml`).

### Passo 2 — instalar as dependências

```bash
uv sync --python 3.12
```

Se `uv` reclamar de permissão no cache, use: `UV_CACHE_DIR=/tmp/uv-cache uv sync --python 3.12`.

### Passo 3 — criar o arquivo `.env` com a sua chave de API

O pipeline faz chamadas **reais** ao LLM e lê a chave de um arquivo **`.env` na raiz do repositório** (ao lado de `config.yaml`). Crie-o a partir do modelo fornecido:

```bash
cp .env.example .env
```

Agora **abra o arquivo `.env`** e cole a sua chave na linha do provedor que vai usar. Para o provedor do artigo (DeepSeek), a linha deve ficar assim:

```bash
DEEPSEEK_API_KEY=sk-cole-sua-chave-aqui
```

Preencha **apenas** a linha do provedor escolhido; as demais podem ficar em branco. O `.env` **nunca** é versionado (já está no `.gitignore`).

> **Atalho (sem abrir editor):** crie o `.env` já com a chave em um único comando — troque `sk-cole-sua-chave-aqui` pela sua chave real:
>
> ```bash
> printf 'DEEPSEEK_API_KEY=%s\n' 'sk-cole-sua-chave-aqui' > .env
> ```

Mapa **provedor → variável** que você preenche no `.env`:

| Provedor | Variável no `.env` |
|---|---|
| DeepSeek (artigo) | `DEEPSEEK_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| Groq | `GROQ_API_KEY` |

### Passo 4 — (opcional) escolher outro provedor / modelo

O **default já é o do artigo**: provedor `deepseek`, modelo **`deepseek-v4-pro`** (definido em `pipeline_local/config.pipeline.yaml`). Se for usar esse, **pule este passo**.

Para usar outro provedor/modelo, há duas formas:

- **Sem editar arquivo** — defina variáveis de ambiente antes de rodar (Passo 5):

  ```bash
  export RF_PROVIDER=openai      # anthropic | openai | groq | deepseek
  export RF_MODEL=gpt-4o         # id do modelo no provedor escolhido
  ```

- **Editando o arquivo** — abra `pipeline_local/config.pipeline.yaml` e altere as **duas linhas** do bloco `llm` (`rule_agent` e `attacker_agent`):

  ```yaml
  llm:
    rule_agent:     { provider: openai, model: gpt-4o, temperature: 0, max_tokens: 8192 }
    attacker_agent: { provider: openai, model: gpt-4o, temperature: 0, max_tokens: 8192 }
  ```

  Em qualquer das formas, preencha no `.env` (Passo 3) a variável de chave do provedor escolhido.

> ⚠️ **O modelo importa.** O artigo usou **`deepseek-v4-pro`**. Como o pipeline é dirigido por um LLM real, **modelos diferentes (ou execuções diferentes do mesmo modelo) podem divergir** — na regra gerada, no número de iterações até detectar, e em quais variantes escapam. Modelos fracos podem gerar regras ruins ou não seguir o protocolo de ferramentas. Isso é esperado e faz parte da natureza da ferramenta.

### Passo 5 — rodar o teste

Há **dois testes**, ambos rodando o **mesmo pipeline** de ponta a ponta para o ataque `xrce-dds-udp-dos`. A única diferença é a **escala** (quantas variantes de evasão e o limiar de convergência):

| | **Teste mínimo** | **Teste completo** (config. do artigo) |
|---|---|---|
| Comando | `./scripts/teste_minimo.sh` | `./scripts/teste_completo.sh` |
| Execuções | 1 base + **1 variante** | 1 base + **49 variantes** = 50 |
| Convergência | 1 detecção | **20 detecções consecutivas** |
| Regeneração de regra / ciclo | até 5 | até 10 |
| Duração | rápida (~minutos) | **longa** (muitas chamadas ao LLM, custo proporcional) |
| Para quê | verificação e auditoria rápidas | reproduzir a escala do artigo |

```bash
# verificação rápida (recomendado para uma primeira avaliação):
./scripts/teste_minimo.sh

# reprodução na escala do artigo (50 execuções, convergência 20) — DEMORA:
./scripts/teste_completo.sh
```

Ambos os scripts repassam opções extras ao pipeline:

```bash
./scripts/teste_minimo.sh --keep                              # mantém o Snort de pé (ver "Auditoria visual")
RF_PROVIDER=openai RF_MODEL=gpt-4o ./scripts/teste_minimo.sh  # forçar provedor/modelo nesta execução
```

Se faltar a chave do provedor escolhido, o script **para com uma mensagem clara** dizendo qual variável definir. A **primeira execução** baixa a imagem base do Snort 3 (~1.8 GB); as seguintes reaproveitam. Ao final, o script imprime o **status** (`converged`/`partial`) e o **caminho dos dados gerados** (Passo 6).

> Os scripts são atalhos finos sobre `pipeline_local/run_pipeline.py`:
> `teste_minimo.sh` → `--variant-count 1 --convergence-threshold 1`;
> `teste_completo.sh` → `--variant-count 49 --convergence-threshold 20 --max-iterations 10`.
> Para uma escala intermediária, chame `run_pipeline.py` direto com os seus próprios valores.

### O que roda de ponta a ponta

Tudo com o **código de produção** (`Orchestrator`, os dois agentes agno, validador/injetor/monitor, executor, descoberta, recorders):

```
intenção → Rules Agent (LLM) gera regra Snort → valida sintaxe no Snort real →
injeta e reinicia o Snort → checagem de FALSO POSITIVO (tráfego benigno) →
Attack Agent (LLM) executa o ataque (contêiner Docker real) → feedback de detecção →
nas variantes o Attack Agent MUTA o código-fonte e RECONSTRÓI a imagem Docker (evasão) →
Rules Agent refina a regra → repete até CONVERGIR ou esgotar variant_count →
grava os dados do experimento
```

Uma execução termina quando: o nº de variantes consecutivas detectadas atinge `convergence_threshold` (**status `converged`**), ou o `variant_count` se esgota (**status `partial`**, quando alguma variante escapou). Ambos são resultados válidos — evasão bem-sucedida é um achado científico legítimo (ver `docs/analise_convergencia.md`).

---

### Auditoria visual

Cada etapa emite um banner `<------------- MENSAGEM ------------->` no terminal (e em `output.log`): descoberta de ataques, raciocínio de cada agente, regra gerada, validação/injeção, checagem de falso positivo, execução do ataque, replay no Snort, verificação de alertas, mutação de fonte + rebuild, e o desfecho. Com `--keep`, inspecione ao final:

```bash
docker exec rules_farmer_pipeline_snort cat /etc/snort/rules/temp/rules_farmer_ai.rules  # regra ativa
cat pipeline_local/.runtime/logs/alert_fast.txt                                            # alertas do Snort
```

### Passo 6 — inspecionar os dados gerados

O caminho é impresso ao final da execução. O avaliador tem acesso a tudo em `results/<experiment_id>/`:

```text
results/<experiment_id>/
├── experiment.json    # todas as execuções: attack_id, arguments, rule, fired, evasion_rationale, ...
├── metrics.csv        # 1 linha por execução (rule_version, execution_type, fired, arguments, rule, ...)
├── mutations/         # snapshot do código-fonte de ataque mutado a cada variante evasiva
└── validated_rules/   # regras que detectaram (fired=True), por família de ataque
```

*Claims* verificáveis nesses artefatos (os mesmos do artigo):

1. **Intenção → regra válida:** cada regra em `experiment.json` foi validada no Snort real antes do deploy.
2. **Convergência por feedback:** `metrics.csv` mostra a sequência de iterações até `fired=True` — o nº de iterações é a métrica de convergência.
3. **Robustez a evasão:** as linhas de variante mostram se a regra continua detectando (`fired`) as mutações do ataque; `mutations/` guarda o código que as gerou.

### Configuração

Os dois testes do Passo 5 já encapsulam os dois perfis de escala. Para uma escala customizada, os parâmetros ficam em [`pipeline_local/config.pipeline.yaml`](pipeline_local/config.pipeline.yaml): provedor/modelo do LLM, `variant_count` (variações após o base), `max_iterations` (orçamento de regeneração de regra por ciclo) e `convergence_threshold` — todos sobrescrevíveis por flags (`--variant-count`, `--max-iterations`, `--convergence-threshold`). Roteiro detalhado — tabela de auditoria por etapa, inspeção manual — em [`pipeline_local/README.md`](pipeline_local/README.md).

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
│   ├── benign_tools.py      run_benign_traffic  (checagem de falso positivo)
│   ├── attack_tools.py      list_available_attacks, read_attack_definition, execute_attack,
│   │                        list_attack_files, read_attack_source_file, modify_attack_file,
│   │                        rebuild_attack_image
│   ├── persistence_tools.py record_iteration
│   └── inter_agent_tools.py trigger_attacker
├── orchestrator.py          Loop externo do variant_count (base via LLM, variantes reusam/refinam a regra)
├── app_factory.py           Cria modelo agno e wirea tudo
├── config.py                Pydantic schema do config.yaml
├── ssh.py                   Interface de transporte (SSHClient) — trocada por LocalCommandClient no fluxo local
├── ids_*.py, attack_*.py, sid_manager.py, experiment_recorder.py, benign_traffic.py, cli.py, api.py

pipeline_local/              Fluxo de avaliação (Docker local, LLM real) — ver pipeline_local/README.md
├── run_pipeline.py          Entrypoint do avaliador
├── build_runtime.py         Espelha app_factory, mas 100% local
├── local_harness.py         LocalAttackExecutor (ataque + replay) e LocalBenignTrafficRunner
├── local_command_client.py  LocalCommandClient (substituto local do SSHClient)
├── config.pipeline.yaml     Provider/modelo + variant_count/convergência + destinos
├── snort/                   Imagem fina + snort.lua + rules/ do contêiner Snort local
└── attacks/xrce-dds-udp-dos/  Ataque REAL e mutável
```

**Princípios agno:** *Skills* (`SKILL.md`) carregam conhecimento de domínio **sob demanda** (`get_skill_instructions(name)`); *Tools* são funções `@tool` para operações com efeito colateral (execução, escrita, invocação do subagente); *Agentes* combinam `skills` + `tools` + `output_schema` (Pydantic). Ver `CONTEXT.md`, `docs/system_overview.md` e `docs/adr/`.

**Chave da portabilidade:** todo o código de produção fala com o IDS e com o host de ataque **apenas** pela pequena interface do `SSHClient` (`run_command`, `write_file`). O fluxo local injeta um `LocalCommandClient` que implementa essa mesma interface via Docker local — por isso as classes reais (`SnortRuleValidator`, `IDSRuleInjector`, `IDSMonitor`, `AttackExecutor`) rodam sem modificação, sem SSH e sem testbed.

### Loop de feedback (resumo)

1. Operador fornece a intenção. 2. Rules Agent produz regra com `sid:0;`. 3. Validador testa a sintaxe no Snort real. 4. SID Manager atribui SID único. 5. Injetor escreve a regra, reinicia o Snort e limpa o *alert log*. 6. Checagem de falso positivo com tráfego benigno. 7. Attacker Agent seleciona `attack_id` e argumentos (e, nas variantes, muta o código e reconstrói a imagem). 8. Executor roda o contêiner de ataque. 9. Monitor verifica o alerta pelo SID. 10. Se não disparar, o *feedback* volta ao Rules Agent. Convergência exige detecção no base e nas variantes configuradas.

---

## Logs e observabilidade

`output.log` recebe a mesma trilha do terminal. No nível INFO, banners de fase (`<------------- MENSAGEM ------------->`) marcam cada etapa. Mensagens DEBUG (silenciadas por padrão) incluem *polls* do contêiner. Para elevar o nível, edite `configure_execution_logging(level=logging.DEBUG)`.

---


## Licença

Distribuído sob a **licença MIT** — ver o arquivo [`LICENSE`](LICENSE).

# Pipeline completo local — geração de regra + variações de ataque (Salão de Ferramentas SBSeg)

Execução que o **avaliador** roda para acompanhar, de ponta a ponta e **visualmente**,
o pipeline inteiro do Rules Farmer para **um ataque** (`xrce-dds-udp-dos`):

```
intenção em linguagem natural
   → Rules Agent (LLM) gera uma regra Snort e valida a sintaxe no Snort real
   → injeta a regra e reinicia o Snort
   → checagem de FALSO POSITIVO com tráfego benigno
   → Attack Agent (LLM) escolhe e executa o ataque (contêiner Docker real)
   → Snort dá o feedback de detecção
   → nas variantes, o Attack Agent MUTA o código-fonte do ataque e RECONSTRÓI a imagem
     Docker para evadir
   → o Rules Agent refina a regra com o feedback
   → converge (ou esgota o orçamento) e grava os dados do experimento
```

Diferente do **teste mínimo** (que é offline e determinístico, sem LLM), este roda o
**LLM de verdade** — logo exige **uma chave de API** e é **não determinístico** (a saída
varia entre execuções, como qualquer sistema com LLM).

## O que é real e o que é substituído (honestidade científica)

**É o código de produção, sem modificação:** `Orchestrator`, os dois agentes agno
(`RulesAgent`, `AttackerAgent`) com suas skills e tools, `SnortRuleValidator`,
`IDSRuleInjector`, `IDSMonitor`, `RemoteAttackDiscovery`, `AttackExecutor`
(leitura/escrita de fontes e `docker build`), `SIDManager`, `ExperimentRecorder`,
`ValidatedRulesStore`, `MutationContext`. O LLM é o LLM real do provider configurado.

**Substituído por um adaptador local — as duas únicas concessões, ambas documentadas:**

| Camada | Testbed real | Aqui (local) | Por quê |
|---|---|---|---|
| Transporte entre entidades | SSH/paramiko (`SSHClient`) | `LocalCommandClient` (mesma interface, roda `docker` local) | dispensa o testbed de 4 entidades e chaves SSH |
| Captura do tráfego pelo IDS | Snort captura **ao vivo** na interface | o ataque **grava um pcap** com os mesmos bytes; o Snort real o processa em modo *read-file* (`snort -r`) | captura ao vivo exige *raw sockets*/privilégios indisponíveis num ambiente auto-contido/CI |

Os bytes do ataque são idênticos aos que iriam para a rede: a mutação de código do
Attack Agent e a reconstrução da imagem Docker são **exercitadas de verdade**. O ataque
**não transmite** nada na rede (`--network none`), o que o torna seguro de rodar em
qualquer máquina.

## Requisitos

- **Docker** (baixa a imagem base do Snort 3, `ciscotalos/snort3`, ~1.8 GB na 1ª vez).
- **Uma chave de API de LLM.** Providers suportados: `deepseek` (artigo), `anthropic`,
  `openai`, `groq`. Crie um `.env` na raiz do repositório (ao lado de `config.yaml`) —
  `cp .env.example .env` — e preencha a linha do provedor escolhido:

  ```bash
  # .env (na raiz do repositório — nunca versionado)
  DEEPSEEK_API_KEY=sk-...
  ```

O passo a passo completo (instalação, `.env`, escolha de modelo) está no
[`README.md`](../README.md) principal, seção **Fluxo de avaliação**.

## Como rodar

Entrypoints recomendados (a partir da raiz do repo) — os dois perfis de escala:

```bash
./scripts/teste_minimo.sh     # 1 base + 1 variante (rápido)
./scripts/teste_completo.sh   # 1 base + 49 variantes, convergência 20 (escala do artigo — demora)
```

Ou chame o pipeline direto, para controle fino:

```bash
# default = provedor/modelo do artigo (deepseek / deepseek-v4-pro), em config.pipeline.yaml.
uv run --python 3.12 python pipeline_local/run_pipeline.py \
  --variant-count 5 --convergence-threshold 3 --max-iterations 8

# trocar de provider/modelo sem editar o yaml:
RF_PROVIDER=openai RF_MODEL=gpt-4o \
  uv run --python 3.12 python pipeline_local/run_pipeline.py

# manter o contêiner Snort de pé ao final, para inspeção manual:
uv run --python 3.12 python pipeline_local/run_pipeline.py --keep
```

Se faltar a chave, o script **para com uma mensagem clara** dizendo qual variável definir.

## Como AUDITAR cada etapa visualmente

Toda etapa emite um **banner de fase** no terminal (nível INFO), no formato
`<------------- MENSAGEM ------------->`, além das linhas de log de cada componente.
A mesma trilha é gravada em `output.log` na raiz. Os banners que você verá, em ordem:

| Banner / log | O que está acontecendo | Onde auditar |
|---|---|---|
| `BUILD DA IMAGEM DO SNORT` / `DO ATAQUE` | build das imagens Docker | saída do `docker build` |
| `SUBINDO O CONTAINER DO SNORT` | Snort sobe isolado (`--network none`, sem privilégios) | `docker ps` (com `--keep`) |
| `DESCOBRINDO ATAQUES DISPONIVEIS` | descoberta dinâmica do catálogo de ataques | `attack_id`, imagem e argumentos no log |
| `AGORA O AGENTE DE REGRAS ESTA RACIOCINANDO` | o LLM do Rules Agent gera a regra | `RulesAgent attempted rule ... rule=<regra>` |
| `validate_rule_syntax` | sintaxe checada no **Snort real** (`snort -T`) | `Snort rule validation accepted/rejected` |
| `assign_sid` / `deploy_rule` | SID único + injeção + restart do Snort | `IDS injection finished` |
| `AGORA ESTA GERANDO TRAFEGO BENIGNO` | checagem de **falso positivo** | `Benign traffic check done ... false_positive=<bool>` |
| `AGORA O AGENTE DE ATAQUES ESTA RACIOCINANDO` | o LLM do Attack Agent planeja o ataque | `AttackerAgent run finished attack_id=... arguments=...` |
| `EXECUTANDO O CONTAINER DE ATAQUE` → `REPRODUZINDO TRAFEGO NO SNORT` | ataque roda e o pcap é reproduzido no Snort | `container_exit_code`, pcap em `pipeline_local/.runtime/pcaps/` |
| `VERIFICANDO ALERTAS DO IDS` | leitura do `alert_fast.txt` pelo SID | `IDS alert log checked sid=... fired=<bool>` |
| `AGORA ESTA VARIANDO O ATAQUE` (+ `modify_attack_file` / `Docker build`) | mutação de fonte + rebuild da imagem (evasão) | snapshots em `results/<id>/mutations/` |
| `EXPERIMENTO CONVERGIU` / `... COM FALHAS PARCIAIS` | fim do loop | tabela de resumo + arquivos de dados |

Para inspeção manual ao final, rode com `--keep` e:

```bash
docker exec rules_farmer_pipeline_snort cat /etc/snort/rules/temp/rules_farmer_ai.rules  # regra ativa
cat pipeline_local/.runtime/logs/alert_fast.txt                                            # alertas do Snort
ls  pipeline_local/.runtime/pcaps/                                                         # tráfego reproduzido
```

## Dados gerados (o avaliador tem acesso a tudo)

Ao final, o caminho é impresso no terminal. Os artefatos ficam em `results/<experiment_id>/`:

```text
results/<experiment_id>/
├── experiment.json     # TODAS as execuções: attack_id, arguments, rule, fired,
│                       #   evasion_rationale, container_exit_code, ...
├── metrics.csv         # 1 linha por execução: iteration, execution_type, attack_id,
│                       #   arguments, container_exit_code, fired, evasion_rationale, rule
├── mutations/          # snapshot do código-fonte de ataque mutado a cada variante
│   └── variant_N__xrce-dds-udp-dos__attack_udp_dos.py
└── validated_rules/    # regras que detectaram (fired=True), por família de ataque
```

*Claims* verificáveis nesses arquivos (os mesmos do artigo):

1. **Intenção → regra válida:** cada regra em `experiment.json` foi validada no Snort real
   antes do deploy.
2. **Convergência por feedback:** `metrics.csv` mostra a sequência de iterações até `fired=True`.
3. **Robustez a evasão:** as linhas de variante mostram se a regra continua detectando
   (`fired`) as mutações do ataque; `mutations/` guarda o código que as gerou.

## Arquivos deste diretório

```text
pipeline_local/
├── run_pipeline.py            # entrypoint do avaliador: setup Docker → roda o experimento → dados
├── build_runtime.py           # espelha app_factory.build_runtime, mas 100% local + LLM real
├── local_harness.py           # LocalAttackExecutor (ataque + replay) e LocalBenignTrafficRunner
├── local_command_client.py    # LocalCommandClient (substituto local do SSHClient)
├── config.pipeline.yaml       # provider/modelo do LLM + variant_count/convergência + destinos
├── snort/                      # imagem fina + snort.lua + rules/ do contêiner Snort local
└── attacks/
    └── xrce-dds-udp-dos/       # ataque REAL e mutável (Dockerfile, entrypoint.sh, fonte, README)
```

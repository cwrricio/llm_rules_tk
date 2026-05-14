# Rules Farmer

Rules Farmer gera regras Snort a partir de uma intenção em linguagem natural, injeta a regra no IDS, executa um ataque real no testbed e repete o ciclo com feedback até convergir ou atingir o limite de iterações.

## Topologia

- **Entidade 1**: aplicação Rules Farmer. Roda o Orchestrator, Rule Agent, Attacker Agent, SID Manager, adaptadores IDS, executor de ataques e interface do operador.
- **Entidade 2**: host IDS. Roda Snort no container `snort_ids`. A Entidade 1 acessa por SSH.
- **Entidade 3**: host atacante. Contem os diretórios de ataques e imagens Docker. A Entidade 1 acessa por SSH.
- **Entidade 4**: alvo do tráfego de ataque.

Somente a Entidade 1 expõe HTTP. As Entidades 2 e 3 não precisam rodar FastAPI.

## Estrutura Esperada

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
├── xrce-dds-udp-dos/
│   ├── README.md
│   ├── Dockerfile
│   └── entrypoint.sh
├── xrce-dds-fragment-abuse/
│   ├── README.md
│   ├── Dockerfile
│   └── entrypoint.sh
└── mqtt-publisher-flood/
    ├── README.md
    ├── Dockerfile
    └── entrypoint.sh
```

O sistema nao mantem uma lista interna de ataques. Ao iniciar, ele acessa `testbed.attacker_attacks_root`, encontra subdiretorios com `entrypoint.sh`, le o `README.md`, extrai a imagem Docker de exemplos `docker run ...:latest` e extrai os argumentos obrigatorios da linha `usage: entrypoint.sh <...>`.

## Instalar

Instale dependencias com `uv`:

```bash
uv sync --python 3.12
```

Se o `uv` reclamar de permissao no cache (`~/.cache/uv`), rode o mesmo comando com `UV_CACHE_DIR=/tmp/uv-cache` antes de `uv`. Isso nao e requisito do projeto, apenas um desvio para ambientes com cache sem permissao de escrita.

Crie `.env` ao lado de `config.yaml` ou exporte as variaveis:

```bash
GROQ_API_KEY=...
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
```

Crie o contador de SID local:

```bash
mkdir -p data
test -f data/sid_counter.json || echo '{"counter": 9000000}' > data/sid_counter.json
```

## Configurar

Edite `config.yaml`:

```yaml
ssh:
  entity2_host: 192.168.137.1
  entity2_user: gtiotedu
  entity2_key_path: ~/.ssh/id_ed25519_vitima
  entity3_host: 192.168.137.94
  entity3_user: unipampa
  entity3_key_path: ~/.ssh/id_ed25519_atacante

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

attack_plan_validation:
  max_retries: 3
```

As chaves SSH precisam funcionar da Entidade 1 para as Entidades 2 e 3 antes de rodar o sistema.

## Rodar Pelo Terminal

Use a CLI para digitar a intenção no terminal:

```bash
uv run --python 3.12 rules-farmer
```

Toda execução escreve progresso em tempo real no terminal e em `output.log` na raiz do projeto. O fluxo normal usa banners de fase, por exemplo `<------------- AGORA ESTA RODANDO O ATACANTE ------------->`, para ficar claro onde a execução está ou onde parou. Detalhes repetitivos ficam em nível `DEBUG` e não aparecem na execução padrão.

Para acompanhar em outro terminal:

```bash
tail -f output.log
```

O processo fica aguardando texto:

```text
Intent: Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888
```

Ao finalizar, a CLI imprime o status e os caminhos de `experiment.json` e `metrics.csv`.

## Rodar API

```bash
uv run --python 3.12 uvicorn rules_farmer.app_factory:create_real_app --factory --host localhost --port 8000
```

A API tambem configura `output.log` ao inicializar.

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

## Testes

```bash
uv run --python 3.12 pytest -q
```

## Saida

Cada experimento grava:

```text
results/{experiment_id}/
├── experiment.json
├── metrics.csv
└── pcaps/
```

`metrics.csv` usa uma linha por execucao de ataque com `iteration`, `execution_type`, `attack_id`, `arguments`, `fired` e `evasion_rationale`.

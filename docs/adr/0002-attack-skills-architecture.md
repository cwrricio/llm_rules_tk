# ADR 0002 — Descoberta de Ataques pela Estrutura Remota

## Status

Aceito.

## Contexto

O host atacante ja possui uma arvore de ataques em `~/ataques/attackers-claude`, onde cada ataque e um diretorio com `README.md`, `Dockerfile`, `entrypoint.sh` e arquivos auxiliares. Exemplos:

```text
xrce-dds-udp-dos/
├── README.md
├── Dockerfile
└── entrypoint.sh
```

Manter uma lista fixa de ataques dentro do projeto duplica essa fonte de verdade e quebra quando um diretorio novo e adicionado no host atacante.

## Decisao

Rules Farmer descobre ataques via SSH na Entidade 3:

1. Procura subdiretorios de `testbed.attacker_attacks_root` com `entrypoint.sh`.
2. Usa o nome do subdiretorio como `attack_id`.
3. Le `README.md` para obter descricao e imagem Docker.
4. Le `entrypoint.sh` para extrair argumentos obrigatorios da linha `usage: entrypoint.sh <...>`.
5. Entrega esses ataques descobertos ao Attacker Agent no prompt de sistema.

O Attacker Agent retorna:

```python
class AttackPlan(BaseModel):
    attack_id: str
    arguments: list[str]
    evasion_rationale: str
```

O codigo deterministico valida se `attack_id` existe e se `arguments` tem a mesma quantidade esperada pelo `entrypoint.sh`.

## Execucao

O executor:

1. Cria `/tmp/rules-farmer-attack-*` no host atacante.
2. Inicia `tcpdump` no `testbed.attacker_capture_interface`.
3. Roda `docker run --rm <docker_image> <arguments...>`.
4. Encerra captura.
5. Copia `attack.pcap` via SFTP para `results/{experiment_id}/pcaps/`.

O `entrypoint.sh` e executado pelo Docker porque ele e o `ENTRYPOINT` das imagens de ataque.

## Consequencias

### Positivas

- Adicionar ataque novo nao exige mudar codigo nem config.
- A documentacao do ataque fica junto do ataque.
- O agente enxerga exatamente a estrutura disponivel no host atacante no momento da execucao.

### Negativas

- README e `entrypoint.sh` precisam manter contratos legiveis.
- A imagem Docker citada no README precisa existir no host atacante.
- A ordem dos argumentos e contrato entre `entrypoint.sh` e `AttackPlan.arguments`.

## Alternativas Consideradas

- Lista fixa em `config.yaml`: descartada por duplicar a estrutura remota.
- Scripts locais por ataque: descartado porque os ataques ja estao empacotados em Docker.
- API no host atacante: descartada para evitar infraestrutura extra; SSH ja e necessario para operacao.

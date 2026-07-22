# Teste mínimo — Rules Farmer (Salão de Ferramentas SBSeg)

Teste funcional **auto-contido** que o avaliador executa para validar o
funcionamento da ferramenta. Roda o **ciclo real de detecção** da ferramenta
contra um **contêiner Snort 3 local** — **sem SSH, sem testbed remoto, sem chave
de LLM e sem captura de pacotes ao vivo** (portanto sem `sudo`/privilégios).

## O que ele exercita

O driver aponta as **classes de produção reais** da ferramenta para um
`LocalCommandClient` (um substituto do `SSHClient` que roda comandos localmente),
de modo que o mesmo código usado num experimento real roda contra o Docker local:

| Classe de produção | Papel no teste |
|---|---|
| `SnortRuleValidator` | valida uma regra candidata contra o **motor Snort real** (`snort -T`) |
| `IDSRuleInjector` | injeta a regra no contêiner do IDS e o reinicia |
| `IDSMonitor` | lê o `alert_fast.txt` do Snort para decidir se a regra disparou |

O tráfego de ataque é fornecido como PCAPs minúsculos (gerados em Python puro) e
reproduzidos pelo Snort em modo *read-file* (`snort -r`) — 100% determinístico.

**Verificações (todas devem passar):**

1. Uma regra bem-formada é **ACEITA** pelo validador Snort real.
2. Uma regra que o motor Snort não consegue parsear é **REJEITADA** (com o erro do Snort).
3. Após injetar a regra, um PCAP de ataque faz o IDS **DISPARAR** o alerta.
4. Um PCAP benigno **NÃO** dispara o alerta (sem falso positivo).

## Requisitos

- **Docker** (o único requisito além do projeto instalado com `uv sync`).
- A primeira execução puxa a imagem base do Snort 3 (`ciscotalos/snort3`, ~1.8 GB)
  e constrói uma imagem fina em cima dela.
- **Não** requer chave de API, SSH, GPU, nem capacidades de rede elevadas.

## Como rodar

A partir da raiz do repositório:

```bash
uv run --python 3.12 python teste_minimo/run_teste_minimo.py
```

Opcional: `--keep` mantém o contêiner de pé após o teste para inspeção manual.

## Saída esperada

```
====================================================================
  TESTE MINIMO — Rules Farmer (ciclo de detecao contra Snort real)
====================================================================
  [PASS  ] Regra valida aceita pelo Snort real
  [PASS  ] Regra invalida rejeitada pelo Snort real
  [PASS  ] Ataque detectado (alerta disparado)
  [PASS  ] Trafego benigno NAO dispara alerta
====================================================================
  RESULTADO: TODOS OS TESTES PASSARAM [OK]
====================================================================
```

O processo termina com **código de saída 0** quando tudo passa (1 caso contrário),
e remove o contêiner ao final.

## Arquivos

```
teste_minimo/
├── run_teste_minimo.py       # driver: costura as classes reais e reporta PASS/FAIL
├── local_command_client.py   # LocalCommandClient (substituto local do SSHClient)
├── make_pcaps.py             # gerador de PCAPs (ataque/benigno) em Python puro
└── snort/
    ├── Dockerfile            # imagem fina: expõe `snort` no PATH + entrypoint sleep
    ├── snort.lua             # configuração Snort 3 mínima (includes absolutos)
    └── rules/
        ├── all.rules         # inclui a regra deployada
        └── temp/             # IDSRuleInjector escreve rules_farmer_ai.rules aqui
```

> **Escopo.** Este teste demonstra o *motor de detecção* e o código real de
> validação/injeção/monitoramento de regras da ferramenta, de forma reprodutível
> em qualquer máquina com Docker. A **geração de regras dirigida por LLM** e a
> execução de **ataques reais** (contêineres que mutam código e reconstroem
> imagens contra um alvo XRCE-DDS/MQTT) exigem chave de API e o testbed de 4
> entidades — reproduzidas na seção **Experimentos** do `README.md` principal.

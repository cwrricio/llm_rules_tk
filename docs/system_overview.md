# VISÃO GERAL

Este projeto de pesquisa investiga dois eixos complementares:

1. **Qualidade da tradução de intenção em regra** — se agentes de IA conseguem traduzir corretamente uma intenção em linguagem natural em uma regra de IDS válida e precisa.
2. **Convergência do loop de feedback** — se o ciclo multi-agente converge para regras robustas, e com que eficiência.

Cada eixo possui métricas independentes registradas por experimento.

# MÉTRICAS

| Métrica | Descrição |
|---|---|
| Taxa de detecção | A regra disparou durante o ataque simulado original? (binário) |
| Precisão + Revocação | A regra detecta variantes do ataque sem gerar falsos positivos em tráfego legítimo? |
| Iterações até convergência | Quantos ciclos de feedback foram necessários para a regra convergir? |
| Qualidade estrutural | A regra é sintaticamente válida, usa os campos corretos do protocolo e evita padrões excessivamente genéricos? |

# ARQUITETURA

## Entidades

O sistema é composto por 4 entidades que podem rodar em hosts separados ou compartilhados:

| Entidade | Responsabilidade | Componentes |
|---|---|---|
| Entidade 1 | Aplicação de IA | Orquestrador, Agente de Regras, interface do operador |
| Entidade 2 | IDS | Snort (ou outro IDS) + API REST de gerenciamento |
| Entidade 3 | Atacante | Agente Atacante + ferramentas de ataque |
| Entidade 4 | Alvo | Host que recebe o tráfego de ataque |

A Entidade 2 expõe uma API REST consumida pela Entidade 1 para injeção, validação e monitoramento de regras. A Entidade 3 precisa estar na mesma rede que a Entidade 4 para gerar tráfego real.

## Componentes

### Orquestrador (Entidade 1)
Controla o loop de feedback. Mantém o estado do experimento (iteração atual, status de convergência), sequencia as chamadas ao Agente de Regras e ao Agente Atacante, avalia as condições de parada e persiste os resultados. Os agentes são stateless — o Orquestrador decide o que acontece a seguir.

### Agente de Regras (Entidade 1)
Recebe a intenção do operador em linguagem natural e produz uma regra de IDS válida. Em cada iteração subsequente, recebe o payload de feedback do Agente Atacante e revisa a regra. Antes da injeção, delega a validação ao **IDS Rule Validator** e a escrita ao **IDS Rule Injector**.

### Agente Atacante (Entidade 3)
Recebe a intenção do operador e a regra gerada. Seleciona a ferramenta de ataque adequada a partir do **Catálogo de Ferramentas**, executa o ataque contra a Entidade 4, captura o tráfego gerado (PCAP), consulta o **IDS Monitor** para verificar se a regra disparou e retorna o resultado ao Orquestrador. Se a regra não disparar, gera e retorna o payload de feedback.

### IDS Rule Validator (Entidade 1 → Entidade 2)
Abstração que valida a sintaxe de uma regra gerada antes da injeção. A implementação inicial invoca `snort -T` via a API da Entidade 2. Se a validação falhar, o erro é devolvido ao Agente de Regras como feedback. A abstração permite plugar validadores de outros IDS (ex: `suricata --test-config`).

### IDS Rule Injector (Entidade 1 → Entidade 2)
Abstração que escreve a regra aprovada em um arquivo dedicado (ex: `ai_generated.rules`) e sinaliza o IDS para recarregar as regras via a API da Entidade 2. O uso de um arquivo dedicado mantém as regras geradas por IA separadas das regras pré-existentes.

### IDS Monitor (Entidade 1 → Entidade 2)
Abstração que verifica se o IDS disparou uma regra durante uma janela de ataque. A implementação inicial lê o arquivo de alertas do IDS (caminho configurável, ex: `/var/log/snort/alert`) via a API da Entidade 2 e verifica a presença de um alerta com o `sid` da regra injetada. O caminho do arquivo é parametrizável para suportar diferentes IDS.

### SID Manager (Entidade 1)
Atribui SIDs únicos às regras geradas por IA dentro de um range reservado (ex: 9.000.000–9.999.999), usando um contador persistente. O LLM nunca é responsável por garantir unicidade de SIDs — o SID gerado pelo modelo é sempre substituído antes da injeção. Mantém um mapeamento persistente de `sid → intenção do operador` para rastreabilidade.

### Catálogo de Ferramentas (Entidade 3)
Registro das ferramentas de ataque disponíveis, organizadas por tipo de ataque (ex: port scan → `nmap`, flood → `hping3`, exploits → `metasploit`). O Agente Atacante seleciona entre as entradas do catálogo com base na intenção. Se a intenção não mapear para nenhuma entrada, o sistema levanta um erro estruturado e interrompe a execução sem invocar nenhuma ferramenta.

# LOOP DE FEEDBACK

```
Operador → POST /experiments → Orquestrador
                                    │
                          ┌─────────▼─────────┐
                          │  Agente de Regras  │◄──────────────┐
                          │  gera regra        │               │
                          └─────────┬─────────┘               │
                                    │                          │
                          ┌─────────▼─────────┐               │
                          │  IDS Rule Validator│               │
                          │  valida sintaxe    │               │
                          └─────────┬─────────┘               │
                                    │                          │ feedback
                          ┌─────────▼─────────┐               │ (diagnosis +
                          │  IDS Rule Injector │               │  PCAP +
                          │  injeta a regra    │               │  IDS logs)
                          └─────────┬─────────┘               │
                                    │                          │
                          ┌─────────▼─────────┐               │
                          │  Agente Atacante   │               │
                          │  executa ataque    │               │
                          │  + variantes       │               │
                          └─────────┬─────────┘               │
                                    │                          │
                          ┌─────────▼─────────┐               │
                          │  IDS Monitor       │               │
                          │  verifica alertas  │               │
                          └─────────┬─────────┘               │
                                    │                          │
                               regra falhou? ─── Sim ─────────┘
                                    │
                                   Não
                                    │
                          ┌─────────▼─────────┐
                          │  Convergência      │
                          │  Registra resultado│
                          └───────────────────┘
```

**Condição de parada:**
- **Sucesso** — a regra detecta o ataque original e todas as variantes testadas sem falsos positivos.
- **Falha** — o número máximo de iterações N (configurável por experimento) foi atingido sem convergência.

**Payload de feedback** (quando a regra falha):

| Campo | Descrição |
|---|---|
| `diagnosis` | Explicação em linguagem natural de por que a regra provavelmente falhou |
| `raw_attack_data` | PCAP capturado durante o ataque (via `tcpdump` ou `scapy`) |
| `ids_logs` | Log do IDS capturado durante a janela do ataque (sem alertas) |

**Variantes de ataque** — o mesmo ataque executado com parâmetros diferentes (ex: outra porta, IP de origem, payload, TTL). Usadas para testar a robustez da regra após a detecção do ataque original.

# INTERFACE DO OPERADOR

O operador submete experimentos via `POST /experiments` à API REST do Orquestrador (Entidade 1):

```json
{
  "intent": "Bloquear tráfego com características ABC",
  "max_iterations": 5,
  "allowed_tools": ["nmap", "hping3"],
  "variant_count": 3
}
```

| Campo | Obrigatório | Descrição |
|---|---|---|
| `intent` | Sim | Intenção em linguagem natural |
| `max_iterations` | Não | Número máximo de iterações (usa o padrão global se omitido) |
| `allowed_tools` | Não | Subconjunto do catálogo de ferramentas permitidas para este experimento |
| `variant_count` | Não | Quantas variantes do ataque testar na fase de robustez |

# PERSISTÊNCIA

Cada experimento gera um arquivo JSON com todas as métricas, regras geradas por iteração, payloads de feedback trocados e referências aos PCAPs capturados. Um CSV tabular com as métricas agrupadas por experimento é gerado separadamente para análise. Os arquivos PCAP são armazenados separadamente e referenciados por caminho.

# COMUNICAÇÃO ENTRE COMPONENTES

Todos os componentes distribuídos se comunicam via REST/HTTP. Não há autenticação entre os serviços — o sistema pressupõe que opera em uma rede isolada, cuja configuração é responsabilidade do operador.

# DETALHES TÉCNICOS

1. Python 3.12+ como linguagem de programação.
2. `uv` para gerenciamento de ambientes virtuais e dependências.
3. Agno para a criação dos agentes de IA.
4. TDD para garantir YAGNI — nenhuma funcionalidade implementada sem teste que a justifique.
5. Git para controle de versão, com commits frequentes e mensagens claras.
6. Clean Code para nomenclatura, organização e documentação.
7. Código-fonte em inglês (US).

# PRESSUPOSTOS E RESTRIÇÕES

- O sistema **não implementa isolamento de rede**. O operador é responsável por garantir que o testbed opere em uma rede isolada antes de invocar ferramentas de ataque reais.
- O sistema é **agnóstico ao IDS** — as abstrações IDS Rule Validator, IDS Rule Injector e IDS Monitor permitem suportar outros IDS além do Snort (ex: Suricata) sem alterar a lógica dos agentes.
- O **LLM nunca é responsável por garantias de sistema** — unicidade de SIDs, seleção de ferramentas e condições de parada são controladas por código determinístico.

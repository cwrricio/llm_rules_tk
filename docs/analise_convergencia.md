# Análise de Convergência Prematura e Qualidade de Regras

## Sumário Executivo

Os experimentos registrados em `results/` mostram um padrão preocupante: todas as variantes de
ataque são detectadas pela mesma regra, inclusive variantes que o próprio agente descreve como
evasivas. Esta análise identifica as causas raiz, documenta as hipóteses testadas e propõe
correções concretas.

---

## 1. Padrão Observado nos Resultados

### xrce-dds-udp-dos (experimento 0057)

**Regra deployada:** `dsize:100<>400; detection_filter:track by_src, count 1, seconds 10`

Todas as 20 variantes dispararam `fired=True` com a mesma regra, apesar de rationales como:
- Variante 2: "all packets carry 10-99 bytes (below range)" → deveria NÃO disparar `dsize:100<>400`
- Variante 5: "all packets carry 401-600 bytes (above range)" → deveria NÃO disparar
- Variante 3: "all payload sizes randomized 100-400 bytes" → o agente acredita erroneamente que isto EVADE a regra

### xrce-dds-entity-flood (experimento 0058)

**Regra deployada:** `content:"xml"; detection_filter:track by_src, count 5, seconds 30`

Todas as variantes dispararam `fired=True` apesar de rationales como:
- Variante 4: "1 packet with 35s inter-packet gaps, all payload bytes 0x00" → impossível atingir count=5 com 1 pacote
- Variante 5: "TCP transport to evade 'alert udp'" → TCP não é capturado por regra `alert udp`
- Variante 16: "UDP, count=4 (below threshold), CDR payload excluding xml bytes" → nem content nem count satisfeitos

---

## 2. Hipóteses de Causa Raiz

### H1: Falsos Positivos — Regras Genéricas Demais (PRINCIPAL)

**Evidências:**
- A regra `dsize:100<>400` é bidimensionalmente genérica: captura qualquer pacote UDP com
  payload de 100–400 bytes em QUALQUER direção.
- O Agent XRCE-DDS (192.168.137.1:8888) responde a cada ping recebido. Essas respostas têm
  payloads variáveis que podem facilmente estar na faixa 100–400 bytes.
- A regra `content:"xml"` captura qualquer tráfego XRCE-DDS que use encoding XML (operação normal
  em muitos modos de inicialização).
- O header `alert udp any any -> any any` captura tráfego em AMBAS as direções (servidor→cliente
  e cliente→servidor). As respostas do servidor aos ataques (e a tráfego legítimo) disparam a regra.

**Conclusão:** A regra detecta o tráfego de RESPOSTA do servidor, não o ataque em si. Por isso,
mesmo quando o ataque muda completamente (TCP, tamanho diferente, sem "xml"), o servidor continua
respondendo e as respostas disparam a regra.

**Solução:**
- Usar `->` (unidirecional), nunca `<>` ou headers bidirecionais implícitos
- Ancoragem mais específica no protocolo (bytes da biblioteca microxrcedds_client)
- Thresholds mais altos no detection_filter (500+ por 5s para DoS, não count=1)

---

### H2: Erro Semântico do Agente Atacante — `dsize:100<>400`

**Evidências:**
No arquivo `experiment.json` do experimento 0057, variante 3:
> "v120 In-Range Payload: rule dsize:100<>400 means 'NOT between 100-400', so all payload sizes
> now randomized 100-400 bytes — strictly inside the exclusion zone where dsize never matches."

O agente atacante entende `dsize:100<>400` como "NÃO entre 100 e 400". A semântica correta é:
**`dsize:100<>400` = payload IS between 100 and 400 (inclusive).**

Resultado: quando o agente "evade" enviando pacotes de 100–400 bytes (acreditando ser a zona
de exclusão), na verdade está garantindo que os pacotes serão detectados. Paradoxalmente, as
variantes que deveriam ter maior chance de evasão real (abaixo de 100 ou acima de 400 bytes)
disparam por causa do H1 (respostas do servidor).

**Solução:** Documentação correta no cheatsheet (já corrigido em `snort3-syntax-cheatsheet.md`).

---

### H3: Falha Silenciosa no Rebuild de Imagens Docker

**Evidências (inferidas):**
- O agente modifica arquivos fonte C e reporta evasion_rationale descrevendo payloads específicos
- Se o `docker build` falha (erro de compilação), o container usa a imagem antiga
- A ferramenta `rebuild_attack_image` retorna `exit_code` mas o agente pode não verificar isso
- Um build falho resulta na execução do ataque ORIGINAL, que a regra genuinamente detecta

**Evidências circunstanciais:**
- Variante 1 do udp-dos: argumento-apenas (sem rebuild), rationale descreve "above-range payload"
  mas `fired=True` — sugere que o ataque original ainda está sendo executado
- Múltiplas variantes consecutivas com estratégias radicalmente diferentes (TCP, zero bytes, etc.)
  todas disparando — improvável se os rebuilds fossem bem-sucedidos

**Solução:** 
- Skill atualizada exige verificação de `exit_code == 0` antes de executar
- Nunca chamar `execute_attack` após rebuild com `exit_code != 0`
- Reportar erro de compilação no `evasion_rationale`

---

### H4: Variantes Não São Genuinamente Independentes

**Evidências:**
- Todas as 20 variantes do udp-dos repetem as mesmas 3 estratégias: below-range, above-range,
  in-range. Não há tentativa de mudar o protocolo, o padrão temporal, ou o tipo de submensagem.
- A regra `content:"xml"` com `count=5, seconds=30` não foi atacada por variantes que mantenham
  o volume mas eliminem "xml" dos payloads de forma genuína (CDR binário correto).

**Solução:**
- O algoritmo de adaptação no `refinamento.md` deve ser mais prescritivo sobre QUAL estratégia
  aplicar com base no mecanismo da regra, não apenas listar técnicas genéricas
- A skill de evasion-variants deve exigir que variante N+1 use estratégia DIFERENTE de variante N

---

## 3. Impacto nos Resultados de Pesquisa

### Convergência Prematura (threshold=20 consecutivos)

O sistema declara "converged" após 20 variantes consecutivas detectadas. Se as detecções são
falsos positivos (H1) ou causadas por rebuild falho (H3), a convergência é ESPÚRIA — a regra não
é genuinamente robusta, ela apenas é genérica demais.

**Consequência:** Os resultados publicados podem superestimar a capacidade de detecção das regras
geradas, enquanto na prática as regras causariam alto índice de falsos positivos em ambientes reais.

### Validade Experimental

Para que o sistema produza resultados válidos, é necessário:
1. **Tráfego benigno de controle**: rodar as regras contra tráfego legítimo XRCE-DDS/MQTT/HTTP
   e medir a taxa de falsos positivos.
2. **Isolamento temporal**: garantir que o alert log está limpo ANTES de cada variante (já
   implementado, mas verificar se o truncate está acontecendo via log SSH).
3. **Confirmação de rebuild**: registrar o exit_code do rebuild em cada variante como metadado.

---

## 4. Classificação das Regras Geradas

Com base nos experimentos disponíveis:

| Regra | Ataque | Classificação | Problema Principal |
|-------|--------|---------------|--------------------|
| `dsize:100<>400; detection_filter count 1, 10s` | udp-dos | **Falso Positivo Alto** | Captura qualquer UDP no range; count=1 é trivialmente baixo |
| `content:"xml"; detection_filter count 5, 30s` | entity-flood | **Falso Positivo Alto** | "xml" é common em XRCE-DDS normal; 5 packets/30s é trivial |
| `content:"create"; detection_filter count 50, 10s` | entity-flood | **Falso Positivo Médio** | "create" é operação normal DDS |
| `byte_test:1,>,0,4; dsize:10<>200` | session-hijack | **Razoável** | byte_test específico mas dsize amplo |
| `content:"xml"; pcre:...` | entity-flood | **Falso Positivo Alto** | sem fingerprint específico do ataque |

---

## 5. Melhorias Propostas

### 5.1 Qualidade de Regras

**Critério mínimo por regra:**
1. Deve conter fingerprint binário específico do protocolo (não apenas strings ASCII genéricas)
2. Deve ser unidirecional (`->`)
3. `detection_filter:count` deve ser calibrado contra tráfego legítimo
4. Deve ser testada contra tráfego benigno antes de ser declarada "validada"

**Exemplos de regras melhores para udp-dos:**
```
# Especifica tamanho de ping microXRCE-DDS (12-20 bytes) + taxa anômala
alert udp any any -> any any (
  msg:"XRCE-DDS UDP DoS - ping flood";
  dsize:5<>25;
  detection_filter:track by_src, count 500, seconds 5;
  sid:0; rev:1;
)

# Fingerprint da inicialização de sessão (CREATE_CLIENT byte inicial = 0x00)
alert udp any any -> any any (
  msg:"XRCE-DDS UDP DoS - session init flood";
  content:"|00 00|",offset 0,depth 2;
  dsize:<50;
  detection_filter:track by_src, count 50, seconds 10;
  sid:0; rev:1;
)
```

### 5.2 Variantes de Ataque

**Critério mínimo por variante:**
1. Deve aplicar estratégia DIFERENTE das variantes anteriores com `fired=True`
2. Deve verificar `exit_code == 0` após rebuild antes de executar
3. `evasion_rationale` deve referenciar a condição ESPECÍFICA da regra que está sendo atacada

**Estratégias mais sofisticadas a incluir no refinamento:**
- Fragmentação IP (payloads acima de MTU fragmentados em múltiplos datagrams)
- IP spoofing com raw sockets (varia o IP de origem)
- Mudança de protocolo de transporte (UDP → TCP quando a regra é `alert udp`)
- Padding em payloads para sair de filtros de tamanho
- Substituição de encoding XML por CDR binário em ataques XRCE-DDS

### 5.3 Processo de Validação

Adicionar fase de "validação cruzada" após convergência:
1. Manter a regra deployada
2. Executar tráfego benigno (XRCE-DDS normal, MQTT legítimo)
3. Verificar que a regra NÃO dispara para tráfego benigno
4. Apenas se `fired=False` para benigno: marcar como regra válida

---

## 6. Próximos Passos

1. **Imediato**: Rodar experimentos com tráfego benigno paralelo para medir taxa de falsos positivos
2. **Curto prazo**: Implementar fase de validação cruzada no orquestrador
3. **Curto prazo**: Adicionar metadado `rebuild_exit_code` nas execuções de variante
4. **Médio prazo**: Expandir refinamento.md de cada ataque com fingerprints binários precisos
5. **Médio prazo**: Calibrar thresholds de detection_filter contra dados reais de uso legítimo

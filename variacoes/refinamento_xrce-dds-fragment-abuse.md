# Refinamento: XRCE-DDS Fragment Abuse

## 1. Vetor Base

Abuso do mecanismo de fragmentação RTPS do protocolo DDS. Quando uma mensagem excede a MTU do transporte (tipicamente 1500 bytes para UDP), o protocolo RTPS divide a mensagem em submensagens `DATA_FRAG`. O atacante explora falhas no processo de reassembly do receptor: envia fragmentos incompletos (sem flush), fragmentos com offsets sobrepostos, e inundação de fragmentos que competem por buffers de reassembly. O efeito é esgotamento da memória de reassembly, corrupção de dados, ou crash do parser RTPS.

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade |
|----|----------|----------------------|------------|
| H1 | Buffer de reassembly pendente por tempo excessivo | Fragmentos de uma mensagem que permanecem incompletos por >30 segundos são anomalia. O protocolo RTPS espera que todos os fragmentos de uma mensagem cheguem em uma janela de tempo curta (ordem de ms). IDS com stateful inspection de sessão RTPS detecta mensagens com `fragmentCount > receivedFragments` por tempo anômalo. | Alta |
| H2 | Tamanho de fragmento homogêneo | Todos os fragmentos com exatamente o mesmo tamanho (ex: 1000 bytes) é padrão de fuzzing/ataque. Tráfego RTPS legítimo tem variação natural de tamanho entre fragmentos (último fragmento frequentemente é menor). | Média |
| H3 | Heartbeats com payload estático | Pacotes keep-alive (INFO_TS ou padding) com conteúdo idêntico em todas as iterações são assinatura de script de ataque. O campo timestamp do INFO_TS deve variar com o relógio real. | Alta |

## 3. Catálogo de Evasão

### H1: Buffer de reassembly pendente por tempo excessivo

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | **Fragment Slowloris com heartbeats variáveis**: enviar 9 de 10 fragmentos esperados e manter a sessão viva com pacotes INFO_TS cujo timestamp reflete o relógio real do sistema (`time(NULL)`). Cada heartbeat tem conteúdo distinto (timestamp avança), parecendo tráfego legítimo de um cliente com latência de rede. O buffer de reassembly permanece alocado aguardando o 10º fragmento que nunca chega. Referência: adaptação do Slowloris HTTP para RTPS. |
| **Fragmentação/Timing** | **Fragment interleaving entre DataWriters**: criar 4 DataWriters e entrelaçar fragmentos de diferentes mensagens entre eles. Writer1 envia fragmento 1, Writer2 envia fragmento 1, Writer3 envia fragmento 1, Writer4 envia fragmento 1, Writer1 envia fragmento 2... O tráfego parece ter múltiplos publishers legítimos operando simultaneamente. |
| **Context Shifting** | **Declarar sample_size massivo com payload mínimo**: no header do DATA_FRAG, declarar `sample_size = 0x7FFFFFFF` (~2GB), mas enviar apenas fragmentos pequenos (512 bytes cada). O receptor aloca buffer baseado no `sample_size` declarado ANTES de validar se os fragmentos correspondem. MCUs com 32KB de RAM sofrerão OOM imediato ao tentar alocar 2GB. Referência: Proposta XRCE DDS ENTITY FLOOD. |

### H2: Tamanho de fragmento homogêneo

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Variar `fragmentSize` e `fragmentsInSubmessage` entre mensagens usando distribuição de tamanhos realista: 512, 1024, 1400 (MTU típica), 8192. O último fragmento de cada mensagem deve ser menor que os anteriores. |
| **Fragmentação/Timing** | Variar o intervalo entre fragmentos com jitter: `usleep(random(500, 5000))`. Fragmentos de rede real chegam com latência variável — intervalos fixos são assinatura de script. |
| **Context Shifting** | Implementar **5 técnicas de fragmentação distintas** em fases sequenciais com pausas de 1-2s entre elas: (1) Slowloris, (2) Massive sample_size, (3) Overlapping offsets, (4) Manipulação de fragmentStartingNum, (5) Interleaving. Cada fase parece um incidente de rede diferente. |

### H3: Heartbeats com payload estático

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Construir heartbeats com **timestamp real** (`time(NULL)` para segundos, `gettimeofday()` para microssegundos). O campo de timestamp avança a cada heartbeat como em qualquer cliente RTPS legítimo. Variar o GUID prefix nos heartbeats para simular heartbeats de diferentes writers. |
| **Fragmentação/Timing** | Intercalar heartbeats com **fragmentos de mensagens novas** — o cliente parece estar publicando múltiplas streams de dados simultaneamente, não apenas segurando um buffer. |
| **Context Shifting** | Usar submensagens **INFO_DST + INFO_TS + HEARTBEAT** em sequência em vez de heartbeats isolados — este é o padrão exato de keep-alive de implementações DDS reais (Fast-DDS, OpenDDS). |

## 4. Algoritmo de Adaptação

```
SE erro_detectado == "stateful:reassembly_timeout" ENTÃO
    APLICAR context_shift("fragment_slowloris", fragmentos_enviados=9, fragmentos_total=10)
    APLICAR timing("heartbeat_intervalo", valor=random(1,3))
    APLICAR ofuscacao("heartbeat_timestamp", strategy="real_clock")

SE erro_detectado == "signature_match:fixed_fragment_size" ENTÃO
    APLICAR ofuscacao("tamanhos_variaveis", sizes=[512,1024,1400,8192])
    APLICAR timing("jitter_entre_fragmentos", intervalo=random(500,5000))

SE erro_detectado == "anomaly:static_heartbeat_content" ENTÃO
    APLICAR ofuscacao("timestamp_real", source="gettimeofday")
    APLICAR context_shift("heartbeat_complexo", submensagens=["INFO_DST","INFO_TS","HEARTBEAT"])

SE erro_detectado == "resource:reassembly_buffer_limit" ENTÃO
    APLICAR context_shift("massive_sample_size", valor=0x7FFFFFFF)
    APLICAR context_shift("fragment_interleaving", num_datawriters=4)

SE erro_detectado == "behavioral_anomaly:single_technique_flood" ENTÃO
    APLICAR context_shift("faseamento", fases=["slowloris","massive_sample","overlapping","frag_num_manip","interleaving"])
    APLICAR timing("pausa_entre_fases", valor=random(1000,3000))
```

## 5. Referências Acadêmicas

- Trend Micro (2022) — "A Security Analysis of the Data Distribution Service (DDS) Protocol" — Análise de fragmentação RTPS
- CVE-2021-38445 — OpenDDS/Fast-DDS — parameterLength handling causing OOB write
- Especificação RTPS v2.4 §8.3.7.10 — DATA_FRAG submessage format
- Especificação RTPS v2.4 §8.3.7.7 — HEARTBEAT submessage format
- Proposta XRCE DDS ENTITY FLOOD — sample_size = 0x7FFFFFFF para alocação massiva

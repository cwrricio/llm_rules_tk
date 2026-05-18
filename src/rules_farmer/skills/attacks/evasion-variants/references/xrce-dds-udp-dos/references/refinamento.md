# Refinamento: XRCE-DDS UDP DoS

## 1. Vetor Base

Negação de serviço via inundação UDP contra o Agent XRCE-DDS. O atacante cria múltiplas threads
(50) que, em loop, inicializam um transporte UDP XRCE, enviam pings via `uxr_ping_agent_attempts()`,
e fecham o transporte. Cada thread envia 10000 pings com `usleep(100)` entre iterações, totalizando
500.000 pings. O ataque satura a porta do Agent com tráfego UDP legítimo de ping XRCE, consumindo CPU
e banda. O efeito é 1:1 — cada pacote enviado gera no máximo 1 pacote de resposta.

### Estrutura de pacote XRCE-DDS ping (microxrcedds_client)

O ping é enviado pela função `uxr_ping_agent_attempts()`. O payload UDP tem formato XRCE:

```
Offset  Bytes  Campo
0       1      session_id (0x00 para session não iniciada / 0x80 XOR key para iniciada)
1       1      stream_id  (0x00 = NONE, 0x01 = BUILTIN, 0x80+ = USER)
2       2      seq_num    (little-endian)
4+      N      submessage (CREATE_CLIENT ou PING)
```

O submessage de ping tem ID `0x0C` (HEARTBEAT) com payload de 8 bytes (epoch+sequence).
CREATE_CLIENT tem ID `0x00` com payload ≥ 16 bytes contendo ClientKey (4 bytes) e Session (1 byte).

**Fingerprints confiáveis para detecção:**
- Payload total de um ping = 12–20 bytes. `dsize:<30` isola pings.
- CREATE_CLIENT com session nova: bytes `|00 00|` nos primeiros 2 bytes (session_id=0x00, stream_id=0x00).
- O fluxo de DoS gera > 1000 pacotes UDP para porta 8888 por segundo por thread (50 threads = 50.000/s).

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade | Fingerprint de Regra |
|----|----------|----------------------|------------|---------------------|
| H1 | Volume anômalo de pings (taxa) | Rate limiting por IP — 50 threads × 10k pings = 500k pings em ~5s | Crítica | `detection_filter:track by_src, count 500, seconds 1` (ou count 5000, seconds 10) |
| H2 | Inicialização repetida de sessão (CREATE_CLIENT flood) | Cada thread reinicia o transporte enviando CREATE_CLIENT com ClientKey diferente — detecção de padrão CREATE repetido do mesmo IP | Alta | `content:"\|00 00 00 00\|",offset 0,depth 4; detection_filter:track by_src, count 50, seconds 10` |
| H3 | Tamanho de payload característico | Pings microxrcedds têm payloads de 12–20 bytes — fora do range de qualquer operação normal de dados | Média | `dsize:<30; detection_filter:track by_src, count 200, seconds 5` |

## 3. Regras de Referência (testar em ordem)

```
# H1 — taxa bruta de pings (mais robusto, menos específico)
alert udp any any -> any any (msg:"XRCE-DDS UDP DoS - ping flood"; dsize:<30; detection_filter:track by_src, count 500, seconds 5; sid:0; rev:1;)

# H2 — CREATE_CLIENT flood (mais específico do microxrcedds_client)
alert udp any any -> any any (msg:"XRCE-DDS UDP DoS - session init flood"; content:"|00 00|",offset 0,depth 2; dsize:<50; detection_filter:track by_src, count 50, seconds 10; sid:0; rev:1;)

# H3 — combinação taxa + tamanho (melhor precisão)
alert udp any any -> any any (msg:"XRCE-DDS UDP DoS - small payload flood"; dsize:5<>25; detection_filter:track by_src, count 200, seconds 5; sid:0; rev:1;)
```

## 4. Catálogo de Evasão

### H1: Volume anômalo (taxa bruta)

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Fragmentação/Timing** | Reduzir para 5 threads e adicionar `usleep(10000)` (10ms entre pings). Mantém DoS mas fica abaixo de thresholds de 500/5s. Se o IDS exige 200/5s, reduzir para 150 pings em 5s total — ainda causa sobrecarga no Agent. |
| **Context Shifting** | Usar IP spoofing com raw sockets — cada pacote vem de IP diferente, impossibilitando `track by_src`. Requer privilégio root. |
| **Fragmentação** | Distribuir pings em múltiplas conexões TCP (XRCE-DDS suporta TCP) — a regra UDP não captura TCP. |

### H2: CREATE_CLIENT flood

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Usar `uxr_create_session()` com parâmetros customizados ao invés de ping loop — evita o padrão fixo de bytes `|00 00|` no início. |
| **Context Shifting** | Reutilizar a mesma sessão (session_id ≠ 0x00) e enviar apenas WRITE_DATA submessages — elimina o CREATE flood mas mantém volume. |
| **Fragmentação/Timing** | Alternar entre CREATE e CLOSE numa janela de 30s, nunca excedendo o threshold de count em `seconds`. |

### H3: Tamanho de payload pequeno

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Padding: adicionar `N` bytes de zeros após o submessage PING para superar o `dsize:<30` threshold. Ping normal = 12 bytes + 30 bytes de padding = 42 bytes, fora do filtro `dsize:5<>25`. |
| **Context Shifting** | Substituir pings por WRITE_DATA com payload de dados aleatórios de 200 bytes — escapa de qualquer filtro de tamanho pequeno, mas ainda gera DoS via volume. |

## 5. Algoritmo de Adaptação

```
SE regra contém dsize:<30 ou dsize:5<>25:
    APLICAR ofuscacao("padding", extra_bytes=50)  # payload fica > 30 bytes

SE regra contém detection_filter count > 100:
    APLICAR fragmentacao_timing("rate_reduction", packets_per_5s=80)

SE regra contém detection_filter count <= 50:
    APLICAR context_shift("tcp_transport")  # alert udp não captura TCP

SE regra contém content:"|00 00|" (CREATE_CLIENT fingerprint):
    APLICAR ofuscacao("session_reuse", skip_create=True)

SE regra contém detection_filter count <= 10 AND seconds >= 30:
    # threshold muito permissivo — qualquer flood ainda é DoS
    APLICAR context_shift("distributed_threads", ips_distintos=True, requer_raw_socket=True)
```

## 6. Referências Acadêmicas

- Trend Micro (2022) — "Critically Underrated: Studying the Data Distribution Service (DDS) Protocol" — BAF 9.875x (Fast-DDS) a 32.82x (CoreDX)
- Michaud et al. (2018) — "Attacking OMG DDS Based Real-Time Mission Critical Distributed Systems" — [DOI: 10.1109/malware.2018.8659368]
- Kumar & Singh (2024) — "Detection and prevention of DDoS attacks on edge computing of IoT devices through reinforcement learning" — [DOI: 10.1007/s41870-023-01508-z]

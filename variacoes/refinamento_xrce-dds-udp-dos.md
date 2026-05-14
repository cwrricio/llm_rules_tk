# Refinamento: XRCE-DDS UDP DoS

## 1. Vetor Base

Negação de serviço via inundação UDP contra o Agent XRCE-DDS. O atacante cria múltiplas threads (50) que, em loop, inicializam um transporte UDP XRCE, enviam pings via `uxr_ping_agent_attempts()`, e fecham o transporte. Cada thread envia 10000 pings com `usleep(100)` entre iterações, totalizando 500.000 pings. O ataque satura a porta do Agent com tráfego UDP legítimo de ping XRCE, consumindo CPU e banda. O efeito é 1:1 — cada pacote enviado gera no máximo 1 pacote de resposta.

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade |
|----|----------|----------------------|------------|
| H1 | Origem única de tráfego | Todos os 500.000 pacotes originam do mesmo IP de origem. Rate limiting por IP bloqueia o ataque em segundos. Firewall de borda descarta tráfego do IP atacante sem afetar clientes legítimos. | Crítica |
| H2 | Fingerprint da biblioteca microxrcedds_client | Os pacotes de ping gerados por `uxr_ping_agent_attempts()` têm estrutura RTPS previsível, com GUID e vendor ID fixos da biblioteca. Um IDS com DPI identifica o fingerprint e bloqueia. | Alta |
| H3 | Volume 1:1 sem amplificação | Cada pacote de ping (≈60 bytes) gera uma resposta de tamanho similar. Não há amplificação de banda — o atacante precisa gerar tanto tráfego quanto quer infligir ao alvo. | Média |

## 3. Catálogo de Evasão

### H1: Origem única de tráfego

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | **Ataque de reflexão/amplificação RTPS**: em vez de enviar tráfego diretamente para o alvo, enviar pacotes de descoberta SPDP com **IP de origem spoofado** (IP da vítima) para múltiplos Agents DDS na rede (refletores). Cada refletor responde ao pacote com metadados volumosos (lista de participantes, tópicos, locators) — e envia a resposta para a vítima (IP de origem do pacote spoofado). O tráfego chega à vítima de múltiplos IPs internos (os refletores), contornando regras de firewall/IDS de borda. Referência: Trend Micro (2022). |
| **Fragmentação/Timing** | **SPDP flood com GUIDs aleatórios**: enviar anúncios SPDP com GUID prefix aleatório a cada 2 segundos via multicast (239.255.0.1:7400) ou diretamente para o Agent. Cada anúncio força processamento de descoberta — e GUIDs aleatórios impedem deduplicação. |
| **Context Shifting** | **IP spoofing distribuído por múltiplas threads**: cada thread usa um IP de origem diferente (spoofed). O IDS vê tráfego de dezenas de "clientes" distintos, impossibilitando bloqueio por IP único. |

### H2: Fingerprint da biblioteca microxrcedds_client

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Substituir `uxr_ping_agent_attempts()` por **raw UDP sockets** com payloads RTPS construídos manualmente. Construir pacotes SPDP e DATA RTPS byte a byte, eliminando completamente a dependência da biblioteca e seu fingerprint de rede. |
| **Fragmentação/Timing** | Variar o tamanho do payload entre pacotes (512, 1024, 1400 bytes). A biblioteca microxrcedds_client produz pacotes de tamanho consistente — a variação de tamanho é característica de implementação nativa. |
| **Context Shifting** | **RTPS data flood em tópicos de percepção**: construir pacotes DATA RTPS com writerId aleatório e payload de 1400 bytes de dados pseudoaleatórios, simulando tráfego de múltiplos sensores publicando em alta frequência. O IDS vê tráfego RTPS normal de um domínio DDS com muitos publishers. |

### H3: Volume 1:1 sem amplificação

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Construir pacotes de descoberta SPDP que forçam **respostas volumosas**: solicitar informação completa de participant (builtin topics) com `PID_PARTICIPANT_BUILTIN_TOPICS`, `PID_METATRAFFIC_UNICAST_LOCATOR`, `PID_DEFAULT_UNICAST_LOCATOR`. A resposta do Agent contém centenas de bytes de metadados para cada consulta de 60 bytes — o **Bandwidth Amplification Factor (BAF)** varia de 9.875x (Fast-DDS) a 32.82x (CoreDX). Referência: Trend Micro (2022). |
| **Fragmentação/Timing** | Distribuir consultas de amplificação entre **múltiplos refletores** simultaneamente. Se 5 refletores respondem com BAF médio de 15x, o atacante gera 1 Mbps e a vítima recebe 15 Mbps de tráfego interno (IPs confiáveis). |
| **Context Shifting** | **SYN flood na camada de transporte**: complementar o ataque RTPS com inundação de pacotes TCP SYN na porta do Agent. A saturação de half-open connections na camada 4 é ortogonal ao ataque na camada 7 (RTPS) — o IDS precisa defender duas frentes simultâneas. |

## 4. Algoritmo de Adaptação

```
SE erro_detectado == "rate_limit:single_ip_block" ENTÃO
    APLICAR context_shift("reflection_amplification", strategy="ip_spoofing", victim_ip=TARGET)
    APLICAR ofuscacao("spdp_guid_aleatorio", charset="random_12_bytes")

SE erro_detectado == "signature_match:microxrcedds_client" ENTÃO
    APLICAR ofuscacao("raw_udp_sockets", camada="transporte")
    APLICAR ofuscacao("payload_size_variation", sizes=[512,1024,1400])

SE erro_detectado == "rate_limit:packets_per_second" ENTÃO
    APLICAR context_shift("spdp_flood_distribuido", threads=10, delay_entre_threads=0.02)
    APLICAR context_shift("data_flood_sensors", writer_ids_aleatorios=True)

SE erro_detectado == "resource:bandwidth_1to1" ENTÃO
    APLICAR context_shift("amplificacao_baf", baf_alvo=15.0, num_refletores=5)
    APLICAR context_shift("builtin_topics_query", parametros=["PARTICIPANT","METATRAFFIC","DEFAULT_UNICAST"])

SE erro_detectado == "firewall:udp_only_block" ENTÃO
    APLICAR context_shift("syn_flood", porta=TARGET_PORT)
    APLICAR context_shift("multi_protocol", transportes=["UDP","TCP","multicast"])
```

## 5. Referências Acadêmicas

- Trend Micro (2022) — "Critically Underrated: Studying the Data Distribution Service (DDS) Protocol" — BAF 9.875x (Fast-DDS) a 32.82x (CoreDX)
- Michaud et al. (2018) — "Attacking OMG DDS Based Real-Time Mission Critical Distributed Systems" — [DOI: 10.1109/malware.2018.8659368]
- Kumar & Singh (2024) — "Detection and prevention of DDoS attacks on edge computing of IoT devices through reinforcement learning" — [DOI: 10.1007/s41870-023-01508-z]
- Hnamte et al. (2024) — "DDoS attack detection and mitigation using deep neural network in SDN environment" — [DOI: 10.1016/j.cose.2023.103661]
- Wei et al. (2016) — "Counteracting UDP Flooding Attacks in SDN" — [DOI: 10.1109/netsoft.2016.7502468]

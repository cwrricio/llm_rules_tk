# Refinamento: XRCE-DDS Time Desync

## 1. Vetor Base

Dessincronização do relógio entre cliente XRCE e Agent via manipulação do callback `uxr_set_time_callback()`. O atacante estabelece múltiplas sessões XRCE (20 processos `fork()`) e, a cada iteração de sincronismo, adiciona +10 segundos ao campo `time_offset` da sessão. O offset corrompido é propagado para o algoritmo de sincronismo do cliente, causando timestamps incorretos em dados de sensores e afetando algoritmos de fusão sensorial (EKF2) e controle de voo (GNC).

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade |
|----|----------|----------------------|------------|
| H1 | Offset linear determinístico | O offset cresce +10s a cada iteração, linearmente. Um monitor de integridade temporal (Temporal Integrity Monitor) detecta a progressão linear como anomalia — offsets de clock reais variam com ruído de rede e derivas térmicas, não com incrementos constantes. | Crítica |
| H2 | Múltiplos processos com comportamento idêntico | 20 processos filho executando o mesmo callback com o mesmo padrão de incremento. Um IDS com correlação entre fluxos detecta o comportamento sincronizado como ataque coordenado. | Alta |
| H3 | Saltos abruptos de offset | Incrementos >1s no offset entre iterações consecutivas acionam alarmes de integridade — protocolos de sincronismo (PTP, NTP) corrigem offsets gradualmente. | Alta |

## 3. Catálogo de Evasão

### H1: Offset linear determinístico

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | **Jitter Poisoning com crescimento logarítmico**: em vez de offset += 10s fixo, usar `offset += 10 * (1.05 ^ (iteration/10))`. O crescimento começa imperceptível (10μs na primeira iteração) e acelera gradualmente ao longo de centenas de iterações. O monitor de integridade vê uma "deriva térmica" lenta que se agrava — indistinguível de falha de hardware. Referência: MDPI Sensors (2023). |
| **Fragmentação/Timing** | Distribuir iterações em **taxa de telemetria realista** (50Hz = 20ms entre iterações). Robôs e drones publicam telemetria a 50Hz; o ataque se camufla como tráfego de sensor legítimo. |
| **Context Shifting** | **Envenenamento de filtro EMA**: o filtro de média móvel exponencial (EMA) usado no sincronismo XRCE segue `offset_new = α * measured + (1-α) * offset_old` com α típico de 0.125. Injetar medições fraudulentas que alternam entre valores altos e baixos (não monotônicos), fazendo o filtro convergir lentamente para um valor incorreto sem jamais disparar um alarme de salto. |

### H2: Múltiplos processos com comportamento idêntico

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Cada processo usa uma **seed de offset diferente** e uma **taxa de crescimento diferente**. Processo 1: cresc. logarítmico com base 1.05; Processo 2: cresc. linear com slope 0.5s/iter; Processo 3: random walk (±100ms). A diversidade de padrões impede correlação. |
| **Fragmentação/Timing** | Iniciar cada processo com **delay escalonado** (0s, 5s, 15s, 30s, 60s) para que os offsets divirjam em momentos diferentes. O IDS vê dessincronizações graduais ocorrendo em momentos distintos, não simultaneamente. |
| **Context Shifting** | Executar **5 fases de dessincronização distintas** sequencialmente: (1) Delay Attack PTP, (2) Filter Poisoning EMA, (3) FTSP Spoofing, (4) LIFESPAN + Time Desync, (5) Combined Attack (time desync + data injection). Cada fase opera com mecanismo de dessincronização diferente. |

### H3: Saltos abruptos de offset

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Limitar incremento máximo por iteração a ±50ms (threshold típico de PTP). Usar **random walk com drift**: `offset += random(-50ms, +50ms) + positive_drift`. O offset total cresce ao longo do tempo (+10s em 200+ iterações), mas nenhum incremento individual excede 50ms. |
| **Fragmentação/Timing** | **Delay Attack no PTP/IEEE 1588**: em vez de manipular o offset diretamente, introduzir atrasos assimétricos nos pacotes Sync e Delay_Req. O PTP assume que `delay_mestre→escravo == delay_escravo→mestre` — quebrando esta premissa, o offset calculado fica incorreto sem que o atacante precise modificar nenhum campo de timestamp. Referência: Yu et al. (2013). |
| **Context Shifting** | **FTSP Spoofing**: declarar-se como raiz da árvore de sincronismo (rootID=0) com número de sequência máximo (0x7FFFFFFF). O algoritmo FTSP de eleição de raiz seleciona o nó com menor rootID e, em caso de empate, maior sequence number — o atacante vence a eleição e passa a ditar o tempo global da rede. Referência: Song et al. (2005). |

## 4. Algoritmo de Adaptação

```
SE erro_detectado == "integrity:linear_offset_progression" ENTÃO
    APLICAR ofuscacao("jitter_logaritmico", formula="10 * 1.05^(i/10)")
    APLICAR context_shift("ema_poisoning", alpha=0.125, estrategia="medicoes_alternadas")

SE erro_detectado == "correlation:identical_process_behavior" ENTÃO
    APLICAR ofuscacao("diversificar_padroes", estrategias=["log","linear","random_walk"])
    APLICAR timing("inicio_escalonado", delays=[0,5,15,30,60])

SE erro_detectado == "integrity:abrupt_offset_jump" ENTÃO
    APLICAR ofuscacao("random_walk_with_drift", passo_maximo=50ms, drift=+5ms)
    APLICAR context_shift("ptp_delay_attack", assimetria=30%)

SE erro_detectado == "behavioral_anomaly:single_desync_technique" ENTÃO
    APLICAR context_shift("faseamento_5_estagios", fases=["delay_ptp","ema_poison","ftsp_spoof","lifespan","combined"])
    APLICAR timing("taxa_telemetria", frequencia=50Hz)

SE erro_detectado == "access_control:root_election_defense" ENTÃO
    APLICAR context_shift("ftsp_spoof", root_id=0, seq_number=0x7FFFFFFF)
    APLICAR timing("ftsp_announce_interval", valor=random(30,60))
```

## 5. Referências Acadêmicas

- Yu et al. (2013) — "On time desynchronization attack against IEEE 1588 protocol in power grid systems" — [DOI: 10.1109/energytech.2013.6645332]
- Song et al. (2005) — "Time synchronization attacks in sensor networks" — [DOI: 10.1145/1102219.1102238]
- MDPI Sensors (2023) — "Latency Reduction and Packet Synchronization in Low-Resource Devices Connected by DDS Networks in Autonomous UAVs" — [DOI: 10.3390/s23229269]
- SoK: UxVs Attack Surface (2024) — "The Cyber Attack Surface of Unmanned Vehicles (UxVs)" — ResearchGate
- Michaud et al. (2018) — "Attacking OMG DDS Based Real-Time Mission Critical Distributed Systems" — [DOI: 10.1109/malware.2018.8659368]

# Refinamento: MQTT Publisher Flood

## 1. Vetor Base

Inundação de mensagens PUBLISH contra um broker MQTT, visando saturar a largura de banda, a memória de buffer e a CPU do broker e de todos os assinantes. O atacante estabelece conexão MQTT e dispara milhares de mensagens em alta frequência, opcionalmente com payloads grandes (até 256MB) e flags de QoS elevado e retain ativado. O efeito colateral crítico em robótica é a sobrecarga de pipelines de processamento de percepção (visão computacional, lidar, áudio) nos nós assinantes.

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade |
|----|----------|----------------------|------------|
| H1 | Taxa anômala de PUBLISH/segundo | Heurística de volume: cliente publicando >100 msg/s é outlier estatístico comparado a dispositivos IoT legítimos (0.1-10 msg/s). IDS baseado em baseline de comportamento por client_id detecta o desvio. | Alta |
| H2 | Payloads de tamanho anômalo | Mensagens >1MB são raras em tráfego MQTT operacional (telemetria típica: 50-500 bytes). Payloads de 4MB+ são anomalia estatística que aciona threshold de tamanho máximo por mensagem. | Alta |
| H3 | Tópicos inexistentes ou aleatórios | Publicar em tópicos com nomes randomizados (`flood/534/2/145`) ou em namespaces não declarados é detectado por IDS com whitelist de tópicos ou por monitoramento de schema registry. | Média |

## 3. Catálogo de Evasão

### H1: Taxa anômala de PUBLISH/segundo

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Substituir Paho MQTT por **raw TCP sockets** com construção manual de pacotes PUBLISH. Raw sockets eliminam o overhead de loop e callback da biblioteca, permitindo controle preciso da taxa de envio e eliminando o fingerprint de rede do Paho. |
| **Fragmentação/Timing** | Distribuir PUBLISH com **jitter Gaussiano**: modelar intervalo entre mensagens como `N(μ=50ms, σ=15ms)`. Alternar entre rajadas curtas (20 msg em 200ms) e períodos de silêncio (2-5s). Este padrão é indistinguível de um sensor legítimo com rajadas de buffer flush. |
| **Context Shifting** | **SUBSCRIBE flood como camada de controle**: em vez de inundar com PUBLISH (plano de dados), inundar o broker com SUBSCRIBE e UNSUBSCRIBE em wildcard `#` em ciclo rápido (1ms). A latência de mensagens legítimas aumenta 60x (de 6.5ms para 400ms) sem que o atacante publique uma única mensagem de dados. Referência: Dikii et al. (2020). |

### H2: Payloads de tamanho anômalo

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Fragmentar payloads grandes em **múltiplas mensagens menores** de 512-1024 bytes, cada uma parecendo um chunk de telemetria legítima. Usar QoS 1 com packet_id sequencial para simular fragmentação de protocolo de aplicação. |
| **Fragmentação/Timing** | **SYN flood na camada de transporte**: complementar o ataque de aplicação (PUBLISH) com inundação de pacotes TCP SYN na porta 1883. A saturação da fila de half-open connections impede novos clientes de conectar e não é visível no plano de dados MQTT. Referência: Shea et al. (2017) — 300 MB/s contra Mosquitto. |
| **Context Shifting** | **Retain=True + QoS 2**: o broker é forçado a armazenar cada mensagem (retain) e executar handshake de 4 vias (QoS 2). O dano é cumulativo e persiste após o ataque parar. Cada mensagem de 1KB com retain=True ocupa armazenamento no broker que só é liberado com PUBLISH explícito de payload zero no mesmo tópico. |

### H3: Tópicos inexistentes ou aleatórios

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Usar **prefixos de namespaces legítimos** (`sensors/temperature/`, `telemetry/gps/`, `status/battery/`, `devices/`) concatenados com sufixos aleatórios curtos (4-8 caracteres hex). O IDS vê tráfego em namespaces esperados, mas o volume por tópico individual é baixo o suficiente para não acionar thresholds. |
| **Fragmentação/Timing** | Rotacionar tópicos a cada N mensagens (N=10-50) — simula sensor multi-stream legítimo publicando em subtópicos dinâmicos. |
| **Context Shifting** | Publicar em **tópicos críticos de percepção robótica** com dados que parecem frames de câmera/lidar corrompidos: `rt/frontvideostream`, `rt/audio_msg`, `rt/lidar_pointcloud`. O conteúdo é `os.urandom(10240)` — indistinguível de um sensor com falha de hardware. Referência: Unitree G1 Case Study (Alias Robotics). |

## 4. Algoritmo de Adaptação

```
SE erro_detectado == "rate_limit:publish_per_second" ENTÃO
    APLICAR timing("jitter_gaussiano", media=50ms, desvio=15ms)
    APLICAR context_shift("alternar_rajada_silencio", duracao_rajada=200ms, duracao_silencio=random(2,5))

SE erro_detectado == "signature_match:large_payload" ENTÃO
    APLICAR ofuscacao("fragmentar_payload", tamanho_chunk=512..1024)
    APLICAR context_shift("syn_flood", porta=1883)

SE erro_detectado == "anomaly:random_topics" ENTÃO
    APLICAR ofuscacao("prefixos_legitimos", namespaces=["sensors/","telemetry/","status/","devices/"])
    APLICAR timing("rotacionar_topico", frequencia=10..50)

SE erro_detectado == "behavioral_anomaly:single_client_flood" ENTÃO
    APLICAR context_shift("subscribe_flood", topico="#", intervalo=0.001)
    APLICAR context_shift("qos", valor=random_choice([0,1,2]))
    APLICAR ofuscacao("retain", valor=random_choice([True,False]))
```

## 5. Referências Acadêmicas

- Dikii et al. (2020) — "Detection of DoS attacks exploiting SUBSCRIBE messages of the MQTT protocol" — [DOI: 10.1080/1206212X.2020.1846945]
- Shea et al. (2017) — "Modelling and Evaluation of Malicious Attacks against the IoT MQTT Protocol" — [DOI: 10.1109/iThings-GreenCom-CPSCom-SmartData.2017.115]
- Calder et al. (2019) — "A Novel Approach to Resource Starvation Attacks on MQTT Brokers" — [DOI: 10.1109/icitisee48480.2019.9003770]
- Unitree G1 Humanoid Robot Security Assessment — Alias Robotics Case Study
- Chourasia et al. (2022) — "Smart defense against DDoS in IoT networks using supervised learning classifiers" — [DOI: 10.1016/j.compeleceng.2022.107726]

# Refinamento: MQTT QoS Amplification

## 1. Vetor Base

Amplificação de carga via abuso do handshake **QoS 2** do MQTT. O protocolo define que mensagens com QoS 2 exigem um handshake de 4 vias (PUBLISH → PUBREC → PUBREL → PUBCOMP) para garantir entrega "exatamente uma vez". O atacante envia o PUBLISH QoS 2, recebe o PUBREC do broker, mas **não envia o PUBREL** — interrompendo o handshake no meio. O broker é forçado a manter o estado da mensagem como "pendente" em memória (e potencialmente em disco para persistência), aguardando a conclusão do handshake. Multiplicado por milhares de mensagens órfãs, o consumo de RAM do broker cresce indefinidamente.

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade |
|----|----------|----------------------|------------|
| H1 | Pacotes CONNECT com remaining length malformado | A especificação MQTT §2.2.3 exige codificação de comprimento variável (1-4 bytes). Pacotes com remaining length codificado em 1 byte fixo (ex: `bytes([0x10, length])`) são sintaticamente inválidos e descartados pelo broker com CONNACK de erro ou TCP RST. Detectável por IDS como anomalia de protocolo. | Crítica |
| H2 | Conexões TCP órfãs sem tráfego | Múltiplas conexões TCP estabelecidas que enviam apenas 1 pacote PUBLISH e depois permanecem em silêncio por longos períodos (>60s) são anomalia comportamental. Um cliente MQTT legítimo troca PINGREQ/PINGRESP ou publica dados regularmente. | Alta |
| H3 | Client IDs com padrão previsível | IDs como `amplifier_0..1999`, `amp_client_12345` ou `ataque_X_` contêm prefixos constantes que são assinatura trivial. Um IDS com análise de entropia de client_id detecta o padrão de nomenclatura artificial. | Alta |

## 3. Catálogo de Evasão

### H1: Pacotes CONNECT com remaining length malformado

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | **Codificar remaining length corretamente** conforme MQTT §2.2.3: usar algoritmo de codificação de comprimento variável (1-4 bytes). Implementação de referência: ```python rl = remaining_length; rl_bytes = bytearray(); while True: byte = rl % 128; rl //= 128; if rl > 0: byte \|= 0x80; rl_bytes.append(byte); if rl == 0: break```. Este é o bug mais comum em implementações raw-socket de MQTT e a causa #1 de falha silenciosa. |
| **Fragmentação/Timing** | Não aplicável — correção arquitetural. |
| **Context Shifting** | Validar pacotes CONNECT contra um broker de teste antes de disparar contra o alvo real. Se CONNACK != 0x00, abortar e corrigir codificação. |

### H2: Conexões TCP órfãs sem tráfego

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Após enviar PUBLISH QoS 2 e receber PUBREC, **manter a conexão viva com PINGREQ** a cada `keep_alive/2` segundos. O broker responde com PINGRESP — a conexão parece ativa e legítima, mas o handshake QoS 2 permanece incompleto (sem PUBREL). |
| **Fragmentação/Timing** | **CONNECT flood prévio**: antes de iniciar as conexões QoS 2, enviar uma rajada de pacotes CONNECT sintaticamente válidos mas sem esperar CONNACK. Isso esgota temporariamente a fila de half-open connections do broker, fazendo com que as conexões QoS 2 seguintes sejam tratadas com menos escrutínio (o broker está sob carga). Referência: Carniani et al. (2019). |
| **Context Shifting** | **Alternar QoS 1 e QoS 2**: intercalar mensagens que completam o handshake (QoS 1: PUBLISH → PUBACK) com mensagens que não completam (QoS 2 sem PUBREL). O IDS que monitora apenas QoS 2 incompleto vê 50% de handshakes completos — a taxa de "anomalia" fica dentro do limiar. |

### H3: Client IDs com padrão previsível

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Gerar client IDs **totalmente aleatórios**: 6-10 caracteres de `string.ascii_letters + string.digits`, sem prefixo constante. Ex: `Xk9mP2wQ`. A cada execução, novo ID. |
| **Fragmentação/Timing** | Distribuir conexões em **lotes escalonados**: iniciar com 10% das conexões planejadas, esperar 30s, adicionar mais 20%, esperar 30s, etc. O crescimento gradual do número de clientes é indistinguível de um sistema real escalando horizontalmente. |
| **Context Shifting** | **Tráfego QoS 0 intermitente como disfarce**: entre rajadas de QoS 2, publicar mensagens QoS 0 com payload pequeno (50-200 bytes) em intervalos aleatórios. O IDS vê tráfego misto de cliente "normal" e não consegue isolar o comportamento malicioso. Referência: Chourasia et al. (2022). |

## 4. Algoritmo de Adaptação

```
SE erro_detectado == "protocol_anomaly:malformed_connect" ENTÃO
    APLICAR ofuscacao("mqtt_encode_remaining_length", algoritmo="varint_1a_4bytes")
    APLICAR context_shift("validar_contra_teste", broker_teste="localhost:1883")

SE erro_detectado == "behavioral_anomaly:orphan_connections" ENTÃO
    APLICAR context_shift("pingreq_keepalive", intervalo=keep_alive/2)
    APLICAR context_shift("connect_flood_previo", num_pacotes=200)
    APLICAR context_shift("qos_mix", ratio_qos2=0.7, ratio_qos1=0.3)

SE erro_detectado == "signature_match:client_id_pattern" ENTÃO
    APLICAR ofuscacao("client_id_aleatorio", charset="alphanumeric", tamanho=random(6,10))
    APLICAR timing("crescimento_gradual_conexoes", batches=[0.1,0.3,0.6,1.0], intervalos=[30,30,30])

SE erro_detectado == "rate_limit:connections_per_ip" ENTÃO
    APLICAR context_shift("traffico_qos0_disfarce", intervalo=random(1,3), payload_size=random(50,200))
    APLICAR timing("variação_keepalive", valores=[15,30,60,120])

SE erro_detectado == "heuristic:qos2_incomplete_ratio" ENTÃO
    APLICAR context_shift("session_expiry_mqtt5", expiry_hours=24)
    APLICAR context_shift("qos", sequencia=[2,2,2,1,0,2,1,0,2,2])
```

## 5. Referências Acadêmicas

- Carniani et al. (2019) — "Modeling and evaluation of a new IoT security system for mitigating DoS attacks to the MQTT broker" — [DOI: 10.1109/wcnc.2019.8885553]
- Dikii et al. (2020) — "Detection of DoS attacks exploiting SUBSCRIBE messages of the MQTT protocol" — [DOI: 10.1080/1206212X.2020.1846945]
- Chourasia et al. (2022) — "Smart defense against DDoS in IoT networks using supervised learning classifiers" — [DOI: 10.1016/j.compeleceng.2022.107726]
- Especificação MQTT 3.1.1 §2.2.3 — Remaining Length encoding
- Especificação MQTT 5.0 §3.1.2.11.2 — Session Expiry Interval

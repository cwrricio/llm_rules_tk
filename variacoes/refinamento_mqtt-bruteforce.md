# Refinamento: MQTT Brute Force

## 1. Vetor Base

Força bruta de credenciais contra brokers MQTT (Message Queuing Telemetry Transport) na porta 1883/TCP. O atacante envia pacotes CONNECT MQTT com combinações de username/password extraídas de um dicionário. O protocolo MQTT transmite credenciais em texto claro (sem TLS) e não possui mecanismo nativo de lockout após tentativas falhas. O efeito desejado é obter acesso de publish/subscribe ao broker, permitindo exfiltração de telemetria ou injeção de comandos em tópicos de controle.

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade |
|----|----------|----------------------|------------|
| H1 | Fingerprint de biblioteca Paho MQTT | O handshake TCP da biblioteca `paho-mqtt` possui window size, ordering e flags TCP características que diferem de implementações nativas. IDS com DPI (Deep Packet Inspection) identifica a biblioteca pela sequência de opções TCP. | Alta |
| H2 | Rajada de CONNECT em curto intervalo | Heurística de contagem: N tentativas de CONNECT com credenciais diferentes do mesmo IP em janela < 10s acionam threshold de brute force. Rate limiting de conexão no broker gera CONNACK com código 0x05 (não autorizado) ou TCP RST. | Alta |
| H3 | Credenciais hardcoded em dicionário estático | Assinatura de conteúdo: strings `admin/admin`, `root/root`, `guest/guest` e suas variantes são catalogadas em bases de assinatura de ataque (Snort, Suricata). Dicionários pré-compilados são detectáveis por hash do arquivo de wordlist. | Média |

## 3. Catálogo de Evasão

### H1: Fingerprint de biblioteca Paho MQTT

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Substituir `paho.mqtt.client` por **raw sockets** (`socket` + `struct` da stdlib Python). Construir o pacote CONNECT byte a byte conforme especificação MQTT 3.1.1 §3.1. O handshake TCP gerado por `socket.connect()` é indistinguível do tráfego de qualquer cliente MQTT nativo (Mosquitto, Eclipse, HiveMQ). Referência: abordagem validada no `MQTT_QOS_AMPLIFICATION.PY`. |
| **Fragmentação/Timing** | Não aplicável — a evasão é arquitetural (substituição de dependência), não temporal. |
| **Context Shifting** | Sniffing passivo prévio — capturar pacotes CONNECT de clientes legítimos na rede local (via Scapy ou raw socket com `SO_BINDTODEVICE`). Extrair username, password e client_id reais. Ataque subsequente usa credenciais capturadas: 1 tentativa bem-sucedida em vez de N tentativas de dicionário. Zero tráfego de ataque detectável. |

### H2: Rajada de CONNECT em curto intervalo

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Não armazenar dicionário estático — gerar credenciais proceduralmente via **Mangler**: para cada senha base, produzir mutações com sufixos comuns em IoT (`123`, `2024`, `!`, `@123`, `1`). O dicionário não existe como artefato; é gerado em runtime. Referência: Pretorius (2023) — IoT-Penn. |
| **Fragmentação/Timing** | **Rate limiting adaptativo**: iniciar com delay de 500ms entre tentativas. Se CONNACK retornar 0x00 (sucesso), reduzir delay em 20% (mínimo 10ms). Se retornar 0x05 (não autorizado) ou TCP RST, aumentar delay em 50% (máximo 2s). Se timeout >3 consecutivos, pausar thread por 30s. Este comportamento mimetiza um cliente com conectividade intermitente. |
| **Context Shifting** | Intercalar tentativas em **múltiplas portas** (1883, 8883/TLS, 17883/Unitree). Rotacionar IP de origem se disponível (múltiplas interfaces ou containers). Usar client_id que imita padrão de dispositivo real: `sensor_temp_001`, `controller_01`, `node_<randhex>`. |

### H3: Credenciais hardcoded em dicionário estático

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Embaralhar ordem do dicionário em cada execução com seed aleatória. Codificar strings de credenciais como `bytes` ou Base64 e decodificar em runtime para evitar strings literais no binário. Ex: `b64decode('YWRtaW4=')` em vez de `"admin"`. |
| **Fragmentação/Timing** | Distribuir tentativas de diferentes usuários em threads separadas com delays aleatórios (100-500ms) — o IDS vê tentativas esparsas de múltiplos "clientes" distintos, não rajada concentrada de um atacante. |
| **Context Shifting** | Complementar dicionário com **descoberta via Shodan API**: consultar brokers expostos e extrair credenciais padrão do banner (ex: `mosquitto version 2.0.11` → testar `mosquitto/mosquitto`). Referência: Ankarali et al. (2018) — 60% dos brokers públicos permitem conexão anônima ou usam credenciais padrão documentadas. |

## 4. Algoritmo de Adaptação

```
SE erro_detectado == "connection_refused" OU "connack_0x05" ENTÃO
    APLICAR context_shift("porta", [8883, 17883, 1884])
    APLICAR timing("delay_adaptativo", inicio=500ms, passo_reducao=0.8, passo_aumento=1.5)

SE erro_detectado == "signature_match:paho_mqtt" ENTÃO
    APLICAR ofuscacao("raw_sockets", camada="transporte")
    APLICAR ofuscacao("codificar_credenciais", encoding="base64_runtime_decode")

SE erro_detectado == "rate_limit:conn_per_minute" ENTÃO
    APLICAR timing("distribuicao_threads", num_threads=current*0.5, delay_entre_threads=random(100,500))
    APLICAR context_shift("client_id_pattern", padrao="sensor_<tipo>_<id>")

SE erro_detectado == "signature_match:wordlist_hash" ENTÃO
    APLICAR ofuscacao("mangle_senhas", sufixos=["123","2024","!","@","1"])
    APLICAR ofuscacao("embaralhar_ordem", seed=random)
    APLICAR context_shift("sniffing_passivo", duracao=30s)

SE erro_detectado == "behavioral_anomaly:burst" ENTÃO
    APLICAR timing("backoff_exponencial", base=1000ms, fator=2.0)
    APLICAR context_shift("intercalar_portas", portas=[1883,8883], peso=[0.7,0.3])
```

## 5. Referências Acadêmicas

- Yassein et al. (2017) — "Attack scenarios and security analysis of MQTT communication protocol in IoT system" — [DOI: 10.1109/eecsi.2017.8239179]
- Ankarali et al. (2018) — "Analysis of vulnerabilities in MQTT security using Shodan API" — [DOI: 10.1109/icacci.2018.8554472]
- Pretorius (2023) — "IoT-Penn: A Security Penetration Tester for MQTT" — [DOI: 10.1007/978-3-031-20160-8_9]
- Lonea et al. (2020) — "Automated security test generation for MQTT using attack patterns" — (1.804 testes automatizados)
- Especificação MQTT 3.1.1 — OASIS Standard — http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html

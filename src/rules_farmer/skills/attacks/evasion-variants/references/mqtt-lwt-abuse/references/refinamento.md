# Refinamento: MQTT LWT Abuse

## 1. Vetor Base

Exploração maliciosa do mecanismo **Last Will and Testament** (LWT) do protocolo MQTT. O atacante conecta-se ao broker, configura uma mensagem de testamento (will message) — payload que o broker publicará automaticamente se o cliente se desconectar inesperadamente — e força a desconexão abrupta (sem enviar DISCONNECT). O broker, ao detectar o timeout de keep-alive, publica a will message no tópico configurado. O ataque é eficaz porque a mensagem é publicada pelo IP do broker (confiável), não pelo IP do atacante.

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade |
|----|----------|----------------------|------------|
| H1 | Rajada de conexões com desconexão abrupta | Múltiplos clientes conectando e caindo sem DISCONNECT em janela < 10s acionam heurística de "LWT storm". O broker gera logs de "client disconnected unexpectedly" em volume anômalo. | Alta |
| H2 | Payload de will message com assinatura estática | Conteúdo fixo da will message (JSON com campos previsíveis, strings conhecidas como `"DEVICE_FAILURE"` ou `"INJECTED_MESSAGE"`) é catalogado por IDS com inspeção de payload MQTT. | Média |
| H3 | LWT publicado em tópico de controle crítico | Will message direcionada a tópicos como `cmd_vel`, `emergency_stop`, `cmd/disarm` constitui anomalia semântica — sensores legítimos publicam LWT em tópicos de status/alerta, não de comando. | Alta |

## 3. Catálogo de Evasão

### H1: Rajada de conexões com desconexão abrupta

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Não aplicável diretamente — a evasão aqui é comportamental, não sintática. |
| **Fragmentação/Timing** | **Water Torture**: substituir rajada única de N clientes por gotejamento contínuo de 1 cliente a cada 2-5 segundos, sustentado por longos períodos (horas). Cada ciclo: `connect → will_set → sleep(0.5) → loop_stop(force=True)`. O broker acumula carga de processamento de LWT gradualmente, sem disparar thresholds de rajada. Referência: McCarty & O'Reilly (2019) — brokers colapsam sob carga sustentada, não sob rajadas. |
| **Context Shifting** | **Identity Spoofing com client_id legítimo**: em vez de criar clientes com IDs aleatórios, conectar com o mesmo `client_id` de um dispositivo real (obtido via sniffing passivo). O broker desconecta o cliente original e publica o LWT que ELE (o cliente real) configurou — o atacante não precisa configurar will message própria. O tráfego de LWT resultante é 100% legítimo (configurado pelo dispositivo real). Referência: Pretorius (2023). |

### H2: Payload de will message com assinatura estática

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Substituir payloads JSON estruturados por **dados binários pseudoaleatórios** (`os.urandom(1024)`). Se o alvo espera JSON, intercalar payloads binários com payloads JSON de campos aleatórios: `{"sensor_<rand>": <randint>}` em vez de `{"device":"sensor_X","status":"DEVICE_FAILURE"}`. |
| **Fragmentação/Timing** | Variar tamanho do payload de will message a cada execução: usar distribuição de Pareto (power law) para tamanhos entre 64 bytes e 256MB (limite MQTT). 80% dos payloads pequenos (<1KB) para não chamar atenção; 20% massivos para causar dano real. |
| **Context Shifting** | Alternar entre tipos de conteúdo: `text/plain`, `application/json`, `application/octet-stream`, e conteúdo vazio (payload de 0 bytes). A variação de Content-Type dificulta a assinatura por padrão de formato. |

### H3: LWT publicado em tópico de controle crítico

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Mapear tópicos de controle para **aliases indiretos**: em vez de publicar em `cmd_vel`, configurar LWT em `status/controller_01/heartbeat`. Se o sistema usa bridge MQTT→ROS 2, um nó assinante pode reagir à ausência de heartbeat executando ações de controle — o efeito é o mesmo, mas o tópico é de status, não de comando. |
| **Fragmentação/Timing** | Publicar will message com **retain=True** e QoS 2 em tópico de comando. A mensagem persiste no broker mesmo após a publicação inicial; novos assinantes recebem o comando retido imediatamente ao se inscrever. O dano é prolongado sem tráfego adicional do atacante. |
| **Context Shifting** | **Botnet coordination via LWT**: múltiplos atacantes configuram will messages que publicam em um tópico de sincronização (`botnet/sync`). Quando todos desconectam, o broker publica N mensagens de sincronização que funcionam como sinal para fase 2 do ataque. Nenhum dos atacantes se comunica diretamente — a coordenação é inteiramente via broker. Referência: Andy et al. (2017). |

## 4. Algoritmo de Adaptação

```
SE erro_detectado == "rate_limit:lwt_storm" ENTÃO
    APLICAR timing("water_torture", intervalo=random(2,5), duracao=3600)
    APLICAR context_shift("client_id", strategy="identity_spoofing", source="sniffed")

SE erro_detectado == "signature_match:payload_content" ENTÃO
    APLICAR ofuscacao("payload_binario", gerador="os.urandom", tamanho_dist="pareto")
    APLICAR context_shift("content_type", tipos=["json","binario","vazio"], peso=[0.3,0.6,0.1])

SE erro_detectado == "anomaly:topic_control" ENTÃO
    APLICAR context_shift("topico", strategy="alias_indireto", mapeamento={"cmd_vel":"status/heartbeat"})
    APLICAR context_shift("retain", valor=True)
    APLICAR ofuscacao("qos", valor=2)

SE erro_detectado == "behavioral_anomaly:disconnect_pattern" ENTÃO
    APLICAR timing("keep_alive", valor=random(3,8))
    APLICAR context_shift("disconnect_method", metodo="loop_stop_force")
    APLICAR timing("reconnect_delay", valor=random(10,30))
```

## 5. Referências Acadêmicas

- McCarty & O'Reilly (2019) — "A Novel Approach to Resource Starvation Attacks on MQTT Brokers" — [DOI: 10.1109/icitisee48480.2019.9003770]
- Pretorius (2023) — "IoT-Penn: A Security Penetration Tester for MQTT in the IoT Environment" — [DOI: 10.1007/978-3-031-20160-8_9]
- Andy et al. (2017) — "Attack scenarios and security analysis of MQTT communication protocol in IoT system" — [DOI: 10.1109/eecsi.2017.8239179]
- Firdous et al. (2017) — "Modelling and Evaluation of Malicious Attacks against the IoT MQTT Protocol" — [DOI: 10.1109/iThings-GreenCom-CPSCom-SmartData.2017.115]
- Especificação MQTT 3.1.1 §3.1.2.5 — Last Will and Testament

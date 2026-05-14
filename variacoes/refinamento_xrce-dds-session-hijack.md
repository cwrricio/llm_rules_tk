# Refinamento: XRCE-DDS Session Hijack

## 1. Vetor Base

Sequestro de sessão XRCE-DDS através de força bruta contra chaves de sessão (`client_key`) do Agent. O atacante testa chaves candidatas hardcoded (7 valores como `0xAAAABBBB`, `0xDEADBEEF`) tentando estabelecer uma sessão XRCE com cada uma via `CREATE_SESSION`. Se uma chave for aceita, o atacante cria entidades na sessão hijackada e injeta mensagens maliciosas nos tópicos do domínio DDS. O ataque original testa as chaves sequencialmente com `sleep(2)` entre tentativas.

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade |
|----|----------|----------------------|------------|
| H1 | Força bruta de chaves de sessão | 7 tentativas de CREATE_SESSION com chaves diferentes do mesmo IP em sequência é padrão de brute force. O Agent pode logar "session creation failed" repetido e um IDS pode bloquear o IP após N falhas. | Alta |
| H2 | Chaves hardcoded extraíveis do binário | As 7 chaves estão em um array estático no código-fonte (`common_keys[]`). Um analista que obtiver o binário (via `strings` ou engenharia reversa) extrai todas as chaves e as adiciona à blacklist do IDS. | Média |
| H3 | Criação de entidades pós-hijack com nomes óbvios | Após hijack bem-sucedido, o atacante cria entidades com nomes como `HACKED_PARTICIPANT` e publica mensagens com `"INJECTED_MESSAGE"` — strings que são assinaturas imediatas. | Alta |

## 3. Catálogo de Evasão

### H1: Força bruta de chaves de sessão

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | **ARP Poisoning + MITM passivo**: em vez de adivinhar chaves, posicionar-se como homem-no-meio entre o cliente XRCE legítimo e o Agent via ARP spoofing (camada 2). Capturar o handshake CREATE_SESSION real, extraindo `client_key` e `session_id` do tráfego interceptado. Zero tentativas de brute force — uma única conexão com as credenciais capturadas. Referência: Drews et al. (2020). |
| **Fragmentação/Timing** | Se brute force for inevitável, distribuir tentativas no tempo com **intervalos longos e irregulares** (30-120s entre tentativas). Simular comportamento de cliente legítimo que perdeu a conexão e está tentando reconectar — não de atacante varrendo chaves. |
| **Context Shifting** | Expandir o dicionário de chaves com valores documentados na literatura e observados em campo: `0x00000000`, `0xFFFFFFFF`, `0x01010101`, `0xAABBCCDD`, `0x00C0FFEE`, `0xB16B00B5`. Priorizar chaves que correspondem a implementações específicas de vendor. |

### H2: Chaves hardcoded extraíveis do binário

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Não armazenar chaves no código. Gerar o dicionário de chaves **em runtime** a partir de uma função de derivação: `key_candidate(i) = (seed_base + i * prime) XOR 0xFFFFFFFF`. O dicionário não existe como artefato estático. |
| **Fragmentação/Timing** | Não aplicável — evasão arquitetural (dicionário procedural). |
| **Context Shifting** | **Sniffing de permission.xml**: durante o handshake DDS Security, os arquivos de permissão (`governance.xml`, `permissions.xml`) são transmitidos em texto claro (assinados, mas não criptografados). Capturar estes arquivos revela a topologia completa da aplicação (tópicos, domínios, permissões) e os certificados dos participantes, permitindo ataques direcionados sem brute force. Referência: White et al. (2019). |

### H3: Criação de entidades pós-hijack com nomes óbvios

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Usar **Node Name Spoofing**: ao criar o participante pós-hijack, usar nomes de nós legítimos do ecossistema ROS 2: `/ros_master_control`, `controller_server`, `camera_driver`. O Agent e os demais nós veem um participante com nome esperado. |
| **Fragmentação/Timing** | Após hijack, **não injetar mensagens imediatamente**. Manter a sessão em silêncio por 30-60s (período de "aquecimento" de cliente legítimo), depois começar a publicar com taxa gradualmente crescente. |
| **Context Shifting** | **Token replay com bypass de attestation**: se o sistema usa o mecanismo SERA para attestation de firmware, capturar um token de integridade de um dispositivo legítimo e reenviá-lo durante o handshake. Se o token não incluir nonce robusto ou timestamp, o replay é aceito e o cliente malicioso é admitido como autenticado. Referência: SERA Paper (IEEE). |

## 4. Algoritmo de Adaptação

```
SE erro_detectado == "rate_limit:session_creation_failed" ENTÃO
    APLICAR context_shift("arp_poisoning_mitm", interface="eth0")
    APLICAR context_shift("sniffing_passivo", duracao=60, filtro="port 8888")
    APLICAR timing("brute_force_delay", intervalo=random(30,120))

SE erro_detectado == "signature_match:hardcoded_keys" ENTÃO
    APLICAR ofuscacao("dicionario_procedural", gerador="key_derivation_function")
    APLICAR context_shift("sniff_permissions_xml", duracao=120)

SE erro_detectado == "signature_match:entity_names" ENTÃO
    APLICAR context_shift("node_name_spoofing", nomes=["controller_server","camera_driver","/ros_master_control"])
    APLICAR timing("post_hijack_warmup", duracao=random(30,60))

SE erro_detectado == "protocol_anomaly:missing_attestation" ENTÃO
    APLICAR context_shift("token_replay", source="captured_attestation_token")
    APLICAR context_shift("nonce_forgery", strategy="predictable_nonce")

SE erro_detectado == "behavioral_anomaly:post_hijack_burst" ENTÃO
    APLICAR timing("publicacao_gradual", inicio=1_msg_por_segundo, aceleracao=1.5x)
    APLICAR context_shift("exfiltration_mode", topicos=["sensors/*","telemetry/*"], duracao=300)
```

## 5. Referências Acadêmicas

- Drews et al. (2020) — "Security on ROS: analyzing and exploiting vulnerabilities of ROS-based systems" — [DOI: 10.1109/lars/sbr/wre51543.2020.9307107]
- White et al. (2019) — "Network Reconnaissance and Vulnerability Excavation of Secure DDS Systems" — [DOI: 10.1109/eurospw.2019.00013]
- Jeong et al. (2017) — "A Study on ROS Vulnerabilities and Countermeasure" — [DOI: 10.1145/3029798.3038437]
- SERA Paper — "Secure Micro XRCE-DDS Establishment With Remote Attestation for Micro-ROS" — IEEE Xplore
- Sandoval & Thulasiraman (2019) — "Cyber Security Assessment of ROS 2 for Aerial Networks" — [DOI: 10.1109/syscon.2019.8836824]

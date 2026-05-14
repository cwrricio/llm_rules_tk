# Refinamento: XRCE-DDS Malformed Inject

## 1. Vetor Base

Injeção de dados malformados em uma sessão XRCE-DDS ativa, visando causar crash ou comportamento indefinido no deserializador XCDR (eXtensible Common Data Representation) do Agent. O atacante estabelece uma sessão XRCE legítima, cria um DataWriter, e publica payloads serializados manualmente com anomalias semânticas: strings com comprimento declarado maior que o real, valores inteiros negativos, padrões de buffer overflow, e strings de formato (`%x%x%n`). O alvo é o parser Micro CDR, que gerencia a desserialização de todos os dados XRCE.

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade |
|----|----------|----------------------|------------|
| H1 | Strings de fuzzing clássicas | Payloads contendo `%x%x%x%x%n` (format string attack), `AAAA...` (buffer overflow marker), `0xDEADBEEF` (canary value) são assinaturas universais de fuzzing, catalogadas em todas as bases de regras IDS (Snort, Suricata, Zeek). | Crítica |
| H2 | Valores booleanos XCDR inválidos | Enviar valores diferentes de 0x00 ou 0x01 em campos booleanos XCDR (ex: 0x42, 0xFF) é uma anomalia de protocolo que o próprio parser Micro CDR pode logar ou rejeitar. A CVE-2025-63548 documenta que certas versões do Agent crasham com estes valores. | Alta |
| H3 | Sequência repetitiva de vetores de ataque | Executar 5 rounds idênticos, cada round contendo as mesmas 5 técnicas na mesma ordem, é um padrão de script de pentest. Um IDS com análise de correlação temporal detecta a repetição. | Média |

## 3. Catálogo de Evasão

### H1: Strings de fuzzing clássicas

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Substituir strings de fuzzing genéricas por **payloads semanticamente alinhados a CVEs documentados**. Em vez de `%x%x%n`, usar valores específicos que exploram bugs conhecidos: (a) booleanos fora do domínio {0,1} — CVE-2025-63548; (b) comprimento de string > payload real — CVE-2021-38445 (out-of-bounds read); (c) JSON injection em tópicos de API — CVE-2026-27509/27510. Payloads semânticos não têm strings de fuzzing clássicas e são indistinguíveis de dados malformados acidentais. |
| **Fragmentação/Timing** | Encapsular cada vetor de injeção em uma **mensagem XRCE completa e sintaticamente válida** (header RTPS + submessage DATA + serialização XCDR). O envelope externo é 100% conforme a especificação; apenas o conteúdo interno contém a anomalia. O IDS que inspeciona apenas a camada RTPS vê tráfego normal. |
| **Context Shifting** | Operar dentro de uma **sessão XRCE autenticada** criada com handshake completo (CREATE_SESSION → CREATE_PARTICIPANT → CREATE_TOPIC → CREATE_PUBLISHER → CREATE_DATAWRITER). Dados malformados injetados via DataWriter são indistinguíveis de um sensor com firmware corrompido publicando dados defeituosos. |

### H2: Valores booleanos XCDR inválidos

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Variar os valores booleanos inválidos entre execuções: usar sequência 0x02, 0x42, 0x80, 0xFF, 0xAA em ordem aleatória, não fixa. Intercalar com valores válidos (0x00, 0x01) para que o parser não rejeite o payload completo no primeiro campo. |
| **Fragmentação/Timing** | Distribuir as injeções de booleanos em **fases separadas** com pausas de 1-2s. Cada fase injeta um valor booleano diferente, parecendo incidentes distintos. |
| **Context Shifting** | Combinar booleanos inválidos com **corrupção de comprimento de string** no mesmo payload: declarar string de 50000 bytes mas fornecer apenas 4. O parser aloca 50000 bytes, copia 4, e tenta ler os 49996 bytes seguintes do buffer adjacente — out-of-bounds read determinístico. |

### H3: Sequência repetitiva de vetores de ataque

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Embaralhar a ordem dos vetores de injeção a cada execução. Usar seed baseada em timestamp para garantir ordem diferente a cada run. |
| **Fragmentação/Timing** | **Vetores faseados com pausas variáveis**: executar Vetor 1 (booleanos), pausa 1-3s, Vetor 2 (string corruption), pausa 2-5s, Vetor 3 (QoS LIFESPAN abuse), pausa 1-4s, etc. Cada vetor é um incidente de rede independente — o IDS não correlaciona eventos espaçados por segundos como ataque coordenado. |
| **Context Shifting** | Incluir vetores de **QoS manipulation** que não envolvem dados malformados: (a) `LIFESPAN=50ms` — dados expiram antes da entrega (Michaud et al. 2018, Método #4); (b) `OWNERSHIP_STRENGTH=100` — sequestra fluxo de dados de publicador legítimo (Método #2). Estes vetores operam na camada de configuração, não de dados, e são semanticamente distintos da injeção de payloads malformados. |

## 4. Algoritmo de Adaptação

```
SE erro_detectado == "signature_match:format_string" ENTÃO
    APLICAR ofuscacao("cve_aligned_payloads", cves=["CVE-2025-63548","CVE-2021-38445","CVE-2026-27509/27510"])
    APLICAR context_shift("xrce_session_auth", handshake="completo")

SE erro_detectado == "protocol_anomaly:xcdr_boolean" ENTÃO
    APLICAR ofuscacao("boolean_sequence", valores=[0x02,0x42,0x80,0xFF,0xAA], ordem="random")
    APLICAR context_shift("combined_payload", tecnicas=["boolean","string_length_corruption"])

SE erro_detectado == "behavioral_anomaly:repetitive_sequence" ENTÃO
    APLICAR timing("faseamento_com_pausas", pausas=[random(1000,3000),random(2000,5000),random(1000,4000)])
    APLICAR ofuscacao("embaralhar_vetores", seed=timestamp)

SE erro_detectado == "signature_match:paho_xrce_client" ENTÃO
    APLICAR context_shift("raw_rtps_sockets", camada="transporte")
    APLICAR ofuscacao("guid_dinamico", strategy="timestamp+rand")

SE erro_detectado == "access_control:topic_whitelist" ENTÃO
    APLICAR context_shift("qos_manipulation", vetores=["LIFESPAN=50ms","OWNERSHIP_STRENGTH=100"])
    APLICAR ofuscacao("datawriter_xml", campo="lifespan", valor=50000000)
```

## 5. Referências Acadêmicas

- CVE-2025-63548 — Eprosima Micro-XRCE-DDS-Agent v3.0.1 — Boolean handling crash
- CVE-2021-38445 — OpenDDS/Fast-DDS — parameterLength OOB write
- CVE-2026-27509 & CVE-2026-27510 — Unitree Go2 Robot RCE via API topics (Boschko Security)
- Michaud et al. (2018) — "Attacking OMG DDS Based Real-Time Mission Critical Distributed Systems" — [DOI: 10.1109/malware.2018.8659368]
- White et al. (2019) — "Network Reconnaissance and Vulnerability Excavation of Secure DDS Systems" — [DOI: 10.1109/eurospw.2019.00013]

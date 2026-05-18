# Refinamento: XRCE-DDS Entity Flood

## 1. Vetor Base

Inundação de entidades XRCE-DDS contra o Agent. O atacante estabelece uma sessão XRCE e cria milhares de entidades (Participant, Topic, Publisher, DataWriter) via `uxr_buffer_create_*_xml()`. Cada entidade aloca memória no Agent (structs de ProxyClient) e gera tráfego de descoberta RTPS no domínio DDS. O Agent tem tabelas de objetos limitadas — exaurir essas tabelas causa negação de serviço para clientes legítimos. O ataque original cria 5000 entidades estáticas em 10 threads simultâneas (500 por thread).

## 2. Hipóteses de Detecção

| ID | Hipótese | Mecanismo de Detecção | Severidade | Fingerprint de Regra |
|----|----------|----------------------|------------|---------------------|
| H1 | Criação estática sem deleção | Criar N entidades e mantê-las vivas é padrão de alocação monotônica. Taxa de CREATE_ENTITY superior a qualquer uso legítimo. | Alta | `content:"\|00 01\|",offset 0,depth 2; dsize:>20; detection_filter:track by_src, count 30, seconds 10` (session_id=0x00 + submsg CREATE=0x01) |
| H2 | XML de configuração presente | O ataque original usa `uxr_buffer_create_*_xml()` — os pacotes contêm XML literal. Clientes legítimos podem usar modo binário (CDR). | Média | `content:"\|3c\|",offset 4,depth 1; detection_filter:track by_src, count 20, seconds 30` (0x3C = '<' de abertura XML) |
| H3 | Única client_key por thread | Múltiplos CREATE do mesmo IP em alta frequência são anômalos para clientes normais. | Alta | `detection_filter:track by_src, count 50, seconds 30` (sem content isolado — combinar com fingerprint) |

**ATENÇÃO:** A regra `content:"xml"` captura qualquer pacote XRCE-DDS que contenha as letras "xml"
(como na tag `<xml>` ou string "xml_type"). Isso gera FALSO POSITIVO em operação normal.
Use um fingerprint mais específico: o byte `0x3C` ('<') em posição APÓS o header XRCE (offset≥4),
ou os bytes de submensagem CREATE_ENTITY (`0x01`) no campo submsg_id.

## 3. Catálogo de Evasão

### H1: Criação estática sem deleção

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | **Entity Churning**: em vez de apenas criar entidades, executar ciclos de CREATE → `uxr_run_session_time(5)` → DELETE → `uxr_run_session_time(5)`. Cada criação gera uma mensagem de Discovery RTPS no domínio DDS e cada deleção gera Undiscovery. O resultado é uma **Tempestade de Descoberta** que sobrecarrega o protocolo SPDP/EDP de todos os nós DDS, não apenas o Agent XRCE. Referência: Trend Micro (2022). |
| **Fragmentação/Timing** | Alternar entre **UXR_REUSE e UXR_REPLACE** a cada 3 iterações. `UXR_REUSE` força o Agent a manter entidades duplicadas em vez de sobrescrever, causando fragmentação de memória interna. `UXR_REPLACE` sobrescreve — a alternância gera comportamento imprevisível na gestão de heap. |
| **Context Shifting** | **Billion Laughs Attack via XML**: injetar XML de configuração com entidades aninhadas recursivamente (DOCTYPE com `<!ENTITY lolN "&lolN-1;&lolN-1;">`). O parser XML expande exponencialmente — 10 níveis de aninhamento geram 2^10 = 1024 expansões por referência, consumindo RAM massiva com payload de rede mínimo. Referência: CWE-776. |

### H2: XML de configuração repetitivo

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | Gerar nomes de entidade **dinâmicos por iteração**: incluir cycle_id e timestamp no nome (`churn_TID_CYCLE_TS`). Isso impede o caching de entidades por nome. |
| **Fragmentação/Timing** | Intercalar criação de diferentes tipos de entidade (Participant → Topic → Publisher → DataWriter) em ordem não determinística para evitar padrões de sequência fixa. |
| **Context Shifting** | Variar os parâmetros de QoS no XML: alternar entre `DURABILITY_VOLATILE` e `DURABILITY_TRANSIENT_LOCAL`, `RELIABILITY_BEST_EFFORT` e `RELIABILITY_RELIABLE`. A variação de QoS impede fingerprinting do XML. |

### H3: Única client_key por thread

| Técnica | Instrução de Transformação |
|---------|---------------------------|
| **Ofuscação** | **Forjar múltiplas client_keys**: para cada sessão, usar uma session_key diferente (ex: `0xDD000000 + (thread_id * 100) + key_idx`). Cada client_key distinta cria um novo ProxyClient na tabela do Agent — 10 threads × 10 keys = 100 ProxyClients distintos, cada um com sua própria quota de entidades. Referência: CVE-2025-63548 — falta de validação de quotas por cliente. |
| **Fragmentação/Timing** | Distribuir as client_keys no tempo — criar uma nova sessão a cada 5 segundos com key diferente, mantendo as sessões anteriores vivas. O Agent acumula ProxyClients gradualmente. |
| **Context Shifting** | Combinar client_keys forjadas com **entity churning** — cada ProxyClient executa seu próprio ciclo de create/delete em paralelo. O Agent gerencia N clientes simultâneos, cada um parecendo um cliente legítimo com muitas entidades efêmeras. |

## 4. Algoritmo de Adaptação

```
SE erro_detectado == "quota:entities_per_client" ENTÃO
    APLICAR context_shift("entity_churning", ciclos_por_sessao=50)
    APLICAR timing("uxr_run_session_time", timeout=5)

SE erro_detectado == "signature_match:xml_pattern" ENTÃO
    APLICAR ofuscacao("xml_bomb", profundidade=10)
    APLICAR ofuscacao("nomes_dinamicos", template="churn_TID_CYCLE_TS")
    APLICAR context_shift("qos_params", durabilidade=[VOLATILE,TRANSIENT_LOCAL], confiabilidade=[BEST_EFFORT,RELIABLE])

SE erro_detectado == "quota:proxyclient_limit" ENTÃO
    APLICAR context_shift("client_keys_forjadas", num_keys=100, distribuicao="por_thread")
    APLICAR timing("criacao_sessoes_gradual", intervalo=5s)

SE erro_detectado == "behavioral_anomaly:discovery_storm" ENTÃO
    APLICAR timing("churn_slow_start", inicio=1_ciclo_por_minuto, aceleracao=1.2x)
    APLICAR context_shift("modo_misto", sequencia=[REPLACE,REPLACE,REUSE])
```

## 5. Referências Acadêmicas

- Trend Micro (2022) — "Critically Underrated: Studying the Data Distribution Service (DDS) Protocol" — Análise de segurança RTPS
- CVE-2025-63548 — Eprosima Micro-XRCE-DDS-Agent v3.0.1 — Falta de validação de quotas
- CWE-776 — Improper Restriction of Recursive Entity References in DTDs ('XML Bomb')
- Documentação Micro-XRCE-DDS — eProsima — Object Creation Modes (UXR_REUSE vs UXR_REPLACE)
- Sandoval & Thulasiraman (2019) — "Cyber Security Assessment of ROS 2 for Aerial Networks" — [DOI: 10.1109/syscon.2019.8836824]

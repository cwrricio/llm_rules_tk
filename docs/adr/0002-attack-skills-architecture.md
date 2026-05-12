# Attack Skills como Arquitetura para Simulação de Ataques

O Agente Atacante precisa simular diversos tipos de ataques usando diferentes ferramentas. Optamos por modelar cada tipo de ataque como uma **Skill** (no padrão Agno) em vez de manter um catálogo estático de ferramentas que o agente consulta.

## Problema

A arquitetura anterior usava um "Attack Tool Catalog" — um registro estático mapeando tipos de ataques para ferramentas específicas (ex: port scan → nmap, flood → hping3). O agente consultava esse catálogo de forma procedural. Essa abordagem tem limitações:

1. **Baixa flexibilidade**: Adicionar um novo tipo de ataque requer mudança no código do catálogo
2. **Documentação espalhada**: A lógica de qual ferramenta usar e como invocá-la fica distribuída entre o agente e o catálogo
3. **Escala limitada**: Conforme novos tipos de ataque são adicionados, o catálogo cresce sem estrutura clara
4. **Alinhamento fraco com Agno**: O framework Agno foi escolhido precisamente para lidar com capacidades modulares via Skills, mas não estaríamos aproveitando esse recurso

## Considered Options

- **Catálogo estático em código** — mantém registro de ferramentas e o agente seleciona via lógica procedural. Descartado: baixa escalabilidade e documentação espalhada.
- **Skills como pacotes modulares** — cada tipo de ataque é um diretório auto-contido com SKILL.md (instruções), scripts/ (executáveis), e references/ (documentação). Agno carrega skills automaticamente via LocalSkills, agente raciocina via LLM sobre qual skill invocar. Escolhido.
- **Microserviços separados** — cada tipo de ataque expõe uma REST API própria. Descartado: adiciona infraestrutura sem necessidade no escopo inicial; skills já resolvem modularidade.

## Consequences

### Positivas

1. **Escalabilidade**: Adicionar um novo tipo de ataque é apenas criar um novo diretório com SKILL.md + scripts/main.py + references/. Não requer mudança no código do agente.
2. **Documentação centralizada**: Cada skill é autodocumentada. SKILL.md descreve quando usar, references/ detalha argumentos, scripts/ implementa. Agente lê a documentação de referência antes de invocar.
3. **Raciocínio do LLM**: O agente usa seu próprio raciocínio (via Agno) para escolher qual skill é apropriada baseado na intenção do operador e na regra gerada — em vez de seguir regras hardcoded.
4. **Alinhamento com Agno**: Aproveita o sistema de skills nativo do Agno, reduzindo complexidade em como o agente descobrem e usam capacidades.

### Negativas

1. **Inversão de controle**: O script main.py de cada skill recebe argumentos posicionais (não keywords). A ordem dos argumentos é contrato entre a documentação de referência e o script. Se a documentação e o script desincronizarem, o comportamento quebra. Mitigado: testes unitários para cada skill verificam que main.py processa argumentos na ordem documentada.
2. **Invocação via bash**: O agente invoca skills executando `python3 scripts/main.py [args]` via bash. Isso é mais lento que uma função Python direta, mas é necessário para manter skills como pacotes isolados. Mitigado: skills são invocadas uma ou poucas vezes por experimento, overhead é negligenciável.
3. **Erro de mapping**: Se a intenção do operador não mapear para nenhuma skill disponível, o agente deve ser capaz de gerar um erro claro. O sistema não pode invocar ferramentas indefinidamente. Mitigado: instruções do Agente Atacante pedem explicitamente que o agente consulte skills disponíveis antes de tentar executar algo; se não conseguir mapear, retorna erro estruturado (satisfaz US15).

## Decisões Subordinadas

1. **Estrutura de diretórios**: Cada skill tem SKILL.md, scripts/, references/. Não há diretório tools/ separado — módulos auxiliares vivem em scripts/. (Mantém estrutura simples e alinhada com padrão Agno.)
2. **Argumentos posicionais**: scripts/main.py recebe argumentos via sys.argv em ordem documentada (sem --flags). Garante invocação simples enquanto mantém documentação como fonte de verdade.
3. **Retorno JSON**: Cada main.py retorna {"fired": bool, "pcap_path": str, "diagnosis": str, "ids_logs": str} na stdout. Agente faz parse e envia ao Orquestrador via REST.

## Impacto no Roadmap

- **Curto prazo**: Criar primeira skill de ataque (ex: attack-reconnaissance) como prototipo para validar a arquitetura.
- **Médio prazo**: Expandir catálogo de skills conforme novos tipos de ataque são identificados em testes.
- **Longo prazo**: Skills podem ser compartilhadas entre experimentos, reutilizadas, e até versionadas independentemente.

# REST como protocolo de comunicação entre entidades

O sistema distribui seus componentes em até 4 entidades que podem rodar em hosts separados. Optamos por REST/HTTP como protocolo de comunicação entre elas em vez de chamadas diretas no mesmo processo ou filas de mensagens.

Chamadas diretas seriam mais simples, mas acoplariam todos os componentes ao mesmo host — inviabilizando o objetivo de distribuir o Agente Atacante na mesma rede que o alvo (Entidade 3 → Entidade 4). Filas de mensagens (Redis, RabbitMQ) foram descartadas por adicionarem infraestrutura sem benefício real no contexto de pesquisa: o loop é sequencial por natureza e não precisa de desacoplamento temporal.

## Considered Options

- **Chamadas diretas (mesmo processo)** — descartado: impede a topologia distribuída necessária para o Agente Atacante gerar tráfego real contra o alvo.
- **Fila de mensagens** — descartado: adiciona infraestrutura (broker) sem justificativa; o loop já é sequencial e o Orquestrador coordena a ordem.
- **REST/HTTP** — escolhido: suporta hosts separados, sem dependência de broker, e é consistente com a interface já exposta ao operador.

## Consequences

A Entidade 2 (IDS) precisa expor uma API REST própria para que a Entidade 1 possa injetar regras, validar sintaxe e ler alertas remotamente — em vez de acessar os arquivos do IDS diretamente. Isso adiciona um componente de serviço à Entidade 2, mas é necessário para manter a topologia distribuída viável.

Não há autenticação entre os serviços. A decisão foi explícita: o sistema assume que opera em rede isolada, e a responsabilidade pelo isolamento é do operador (ver `system_overview.md` — Pressupostos e Restrições). Qualquer introdução futura de autenticação (ex: API keys) não exige mudança arquitetural — apenas adição de middleware nas APIs existentes.

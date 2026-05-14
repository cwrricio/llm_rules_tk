# SSH como protocolo de comunicação entre entidades

O sistema distribui seus componentes em 4 entidades em hosts separados. Optamos por **SSH via paramiko** como protocolo de comunicação entre Entity 1 e as entidades remotas (Entity 2 e Entity 3), em vez de REST/HTTP com serviços dedicados.

Esta decisão substitui a decisão original de REST/HTTP. A revisão ocorreu após clarificar o modelo operacional: Entity 2 e Entity 3 são máquinas de pesquisa pré-configuradas que já exigem acesso SSH para setup e administração. Implantar serviços FastAPI nessas máquinas adicionaria infraestrutura sem benefício real no contexto de pesquisa.

## Considered Options

- **REST/HTTP com FastAPI** — descartado (revisão da decisão original): exigia implantar e manter serviços FastAPI na Entity 2 (IDS) e na Entity 3 (Attacker). O argumento original era consistência com a interface do operador e suporte a hosts separados — ambos satisfeitos por SSH sem a carga de serviços adicionais.
- **SSH via paramiko** — escolhido: Entity 1 usa `paramiko.SSHClient` para executar comandos remotos e `paramiko.SFTPClient` para transferir arquivos (SCP). Não requer serviços nas máquinas remotas além de chaves SSH configuradas. Mais controlável em testes: a conexão é configurada explicitamente via código, sem dependência de `~/.ssh/config`.
- **Subprocess SSH** — descartado: dependeria do binário `ssh` no PATH e de configuração no `~/.ssh/config`. Mais frágil em ambientes de teste.
- **Filas de mensagens** — descartado (mantém decisão original): adiciona infraestrutura sem benefício; o loop é sequencial por natureza.

## Consequences

- **Entity 1** usa `paramiko.SSHClient` para executar comandos remotos na Entity 2 e Entity 3, e `paramiko.SFTPClient` para recuperar PCAPs da Entity 3 via SCP.
- **Entity 2 (IDS)** não expõe REST API. O IDS Rule Validator, IDS Rule Injector e IDS Monitor executam comandos via SSH na Entity 2 (ex: escrever arquivo de regras, reiniciar container Docker do Snort, ler log de alertas).
- **Entity 3 (Attacker)** não expõe REST API. O executor de ataques inicia containers Docker via SSH na Entity 3 e recupera PCAPs via SCP.
- A **Orchestrator REST API** (`POST /experiments`, `GET /experiments/{id}`) permanece como FastAPI na Entity 1 — é a interface do operador e não é afetada por esta decisão.
- **Autenticação**: conexões SSH usam chaves públicas. O operador deve configurar as chaves antes de iniciar o sistema.
- **IDS Management API e Attacker API do PRD**: esses serviços descritos no PRD original não existem na implementação. As abstrações (IDS Rule Validator, IDS Rule Injector, IDS Monitor, executor de ataques) são implementadas diretamente com SSH.

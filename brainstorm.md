Pergunta 1: Qual é o objetivo de pesquisa do sistema?
  
  O overview descreve o que o sistema faz, mas não por que ele existe como objeto de pesquisa. Há duas direções bem distintas:

  - (A) Verificar se agentes de IA conseguem gerar regras de IDS corretas a partir de linguagem natural — o foco é na
  qualidade da tradução intent → regra.
  - (B) Verificar se o ciclo de feedback entre agentes converge para regras robustas — o foco é na dinâmica do loop
  agente-testador-agente.
  - (C) Ambos, com métricas separadas para cada.

  Minha recomendação: (C), mas com hipóteses explícitas para cada dimensão — caso contrário o sistema vira um demonstrador sem
   conclusão avaliável.

  Qual é o objetivo de pesquisa central?

<!--------------->

 - (C) Ambos, com métricas separadas para cada.



<!--------------->
 ---
  Pergunta 2: Como você vai medir "qualidade da regra
  ---
  Pergunta 2: Como você vai medir "qualidade da regra gerada"
  (eixo A)?

  Algumas opções:

  - (A) Taxa de detecção — a regra detecta o ataque simulado
  original? (binário: sim/não)
  - (B) Precisão + revocação — a regra detecta variantes do
  ataque sem gerar falsos positivos para tráfego legítimo?
  - (C) Número de iterações até convergência — quantos ciclos
  o loop de feedback precisou para chegar a uma regra eficaz?
  - (D) Qualidade estrutural da regra — a regra é
  sintaticamente correta, usa os campos corretos do protocolo,
   evita padrões muito genéricos?

  Minha recomendação: (B) + (C) juntos — taxa de detecção
  sozinha é trivial de maximizar (basta uma regra que captura
  tudo), e número de iterações sozinho não diz se a regra
  final é boa. A combinação dos dois dá uma imagem mais
  honesta.

  Quais métricas você quer capturar?




<!--------------->




Todas são validas.

<!--------------->

  Pergunta 3: O que concretamente o "agente atacante" executa para simular um ataque?

  O overview diz que o agente "inicia um ataque simulado com características ABC", mas não especifica como. As opções têm
  implicações arquiteturais grandes:
  
  - (A) Tráfego de rede sintético — o agente gera pacotes com scapy ou similar que correspondem às características da intenção
   original (ex: pacotes com um determinado payload, porta, flag TCP). Simples, controlável, sem precisar de exploits reais.
  - (B) Ferramentas de ataque reais — o agente invoca nmap, hping3, metasploit etc. contra o host-alvo. Mais realista, mas
  exige ambiente isolado e levanta questões de segurança.
  - (C) Replay de tráfego capturado — o agente usa PCAPs de ataques conhecidos (ex: datasets como CICIDS) e os reproduz. Boa
  para benchmarking reproduzível.
  - (D) Combinação — sintético para testes rápidos, real/replay para validação final.

  Minha recomendação: (A) para o protótipo inicial — é mais fácil de controlar, não requer isolamento de rede robusto, e o
  agente pode variar os parâmetros de forma programática para testar robustez. (B) e (C) podem ser adicionados depois como
  backends intercambiáveis.
  
  Como o agente atacante vai gerar o tráfego de teste?

<!-------------->

- (B) Ferramentas de ataque reais — o agente invoca nmap, hping3, metasploit etc. contra o host-alvo. Mais realista, mas
  exige ambiente isolado e levanta questões de segurança. - Mas é importante resaltar que diferentes ataques exigem o uso de diferentes ferramentas. Então o sistema deveria ser flexivel em relação a isso.

<!-------------->

Pergunta 4: Como o ambiente de execução do agente atacante é
   isolado do resto da rede?

  Com ferramentas reais como Metasploit, um erro de
  configuração pode afetar hosts fora do testbed. As opções
  principais:

  - (A) Rede virtual isolada (ex: Linux network namespaces,
  VirtualBox host-only, libvirt NAT) — as 4 entidades se
  comunicam numa rede privada sem roteamento externo. Simples
  de configurar, suficiente para protótipo.
  - (B) VMs ou containers com firewall explícito — cada
  entidade roda em VM/container, e um firewall no host
  bloqueia tráfego que sai do testbed. Mais seguro, mais
  complexo.
  - (C) Ambiente físico dedicado — máquinas físicas separadas,
   switch sem uplink para a internet. Mais seguro de todos,
  mas menos prático para desenvolvimento.
  - (D) A ser definido / não é escopo do projeto agora — o
  projeto define o sistema, e o ambiente é responsabilidade do
   operador.

  Minha recomendação: (A) para desenvolvimento e testes, com
  documentação clara dos requisitos de isolamento. O sistema
  em si não precisa implementar o isolamento — mas o overview
  deveria declarar explicitamente que o sistema pressupõe um
  ambiente de rede isolado.

  Como o isolamento de rede vai funcionar?


<!-------------->

(D) A ser definido / não é escopo do projeto agora 
<!-------------->
Pergunta 5: Como o Agente Atacante sabe se o IDS disparou a 
  regra durante o ataque simulado?
  
  O overview diz que o agente "monitora o IDS para verificar
  se a regra foi acionada corretamente", mas não especifica o
  mecanismo. As opções:

  - (A) Leitura dos logs do Snort — o agente acessa o arquivo
  de alertas do Snort (ex: /var/log/snort/alert) após o ataque
   e verifica se houve um alerta com o sid da regra injetada.
  Simples, sem dependência de API.
  - (B) Polling via API do IDS — se o IDS tiver API (ex:
  Suricata tem EVE JSON), o agente consulta via HTTP/socket.
  Mais estruturado, mais fácil de parsear.
  - (C) Monitoramento em tempo real de arquivo — o agente faz
  tail -f ou usa inotify no arquivo de log durante a execução
  do ataque. Mais responsivo, mas mais complexo.
  - (D) Depende do IDS — cada IDS tem seu mecanismo; o sistema
   abstrai isso numa interface comum (IDSMonitor).

  Minha recomendação: (D) com implementação inicial via (A)
  para o Snort — é o caminho mais simples para começar e já
  prepara a abstração necessária para suportar outros IDS no
  futuro, o que está alinhado com o objetivo de ser agnóstico
  ao IDS.

  Como o agente vai monitorar o IDS?

<!-------------->
- (A) Leitura dos logs do Snort — o agente acessa o arquivo
  de alertas do Snort (ex: /var/log/snort/alert) após o ataque
   e verifica se houve um alerta com o sid da regra injetada.
  Simples, sem dependência de API. 

  Atualize um detalhe em relação a pergunta anterior antes de continuarmos.
    É importante observar que o nome do arquivo deve ser parametrizavel. De modo que, monitoremos diferentes arquivos conforme o IDS de escolha.
<!-------------->
Pergunta 6: Qual é a condição de parada do loop de feedback?
  
  O loop pode rodar indefinidamente se não houver um critério
  explícito de encerramento. As opções:

  - (A) Número máximo de iterações — o loop para após N
  tentativas, independente do resultado. Simples, previsível,
  evita loops infinitos.
  - (B) Regra eficaz contra todas as variantes testadas — o
  loop para quando a regra detecta o ataque original e um
  conjunto definido de variantes sem falsos positivos.
  - (C) Combinação: (B) com fallback de (A) — o loop encerra
  com sucesso quando a regra converge, ou com falha após N
  iterações sem convergência.
  - (D) Decisão do agente — o próprio agente decide quando
  parou de melhorar, sem critério fixo.

  Minha recomendação: (C) — é a única opção que garante
  terminação e captura o resultado (convergiu ou não). O
  número máximo de iterações N deve ser configurável. (D) é
  arriscado porque LLMs podem ser otimistas sobre sua própria
  performance.

  Qual é a condição de parada?

<!-------------->
 - (C) Combinação: (B) com fallback de (A) — o loop encerra
  com sucesso quando a regra converge, ou com falha após N
  iterações sem convergência.

<!-------------->
Pergunta 7: O que exatamente o Agente Atacante comunica ao 
  Agente de Regras quando a regra falha?
  
  O overview diz que o agente "analisa o motivo pelo qual a
  regra falhou e sugere melhorias", mas não especifica o
  conteúdo dessa comunicação. É uma decisão crítica porque
  define o que o Agente de Regras recebe como input para
  revisar a regra.

  - (A) Diagnóstico em linguagem natural — o agente descreve
  em texto por que acredita que a regra não disparou (ex: "a
  regra filtra pela porta 80 mas o ataque usou a porta 8080").
   O Agente de Regras interpreta isso para ajustar.
  - (B) Dados brutos do ataque + log do IDS — o agente passa o
   tráfego gerado e o log (sem alertas) diretamente ao Agente
  de Regras, que analisa a divergência sozinho.
  - (C) Estrutura semi-formal — o agente produz um objeto com
  campos definidos: { campo_divergente, valor_gerado, 
  valor_esperado_pela_regra, sugestão }. Mais previsível de
  parsear.
  - (D) Combinação de (A) + (B) — diagnóstico em linguagem
  natural acompanhado dos dados brutos como evidência.

  Minha recomendação: (D) — o diagnóstico em linguagem natural
   aproveita a capacidade de raciocínio do LLM, e os dados
  brutos servem como evidência verificável para o Agente de
  Regras não depender apenas da interpretação do Agente
  Atacante.

  O que o Agente Atacante comunica ao Agente de Regras?


<!-------------->
Seria interessante gerar uma estrutura bem definida com os seguintes campos:
  1. Diagnostico linguagem natural
  2. Dados brutos do ataque 
  3. Logs do IDS

  Quero que a proxima pergunta seja justamente uma definição do que seria "dados brutos do ataque"

<!-------------->
  Pergunta 8: O que são os "dados brutos do ataque"?

  Quando o Agente Atacante invoca uma ferramenta como nmap ou
  hping3, o que exatamente ele captura e repassa como
  raw_attack_data?

  - (A) Comando executado + output da ferramenta — ex: o
  comando nmap -sS -p 8080 192.168.1.2 e o stdout/stderr
  resultante. Simples de capturar, mas não captura o tráfego
  de rede em si.
  - (B) PCAP do tráfego gerado — captura os pacotes
  efetivamente enviados via tcpdump ou scapy durante o ataque.
   Máximo de detalhe, mas mais pesado e requer privilégios de
  captura de rede.
  - (C) Combinação: (A) + metadados do tráfego — comando +
  output da ferramenta + campos chave do tráfego (IPs, portas,
   protocolo, flags, payload relevante) sem o PCAP completo.
  - (D) Depende da ferramenta — cada ferramenta expõe dados
  diferentes; o sistema captura o que estiver disponível.

  Minha recomendação: (C) — o comando e seu output já dizem ao
   Agente de Regras o que foi tentado, e os metadados do
  tráfego dizem o que saiu na rede. O PCAP completo é overkill
   para o protótipo e adiciona complexidade sem benefício
  claro para o raciocínio do LLM.

  O que compõe os dados brutos do ataque?

<!-------------->

- (B) PCAP do tráfego gerado — captura os pacotes
  efetivamente enviados via tcpdump ou scapy durante o ataque.
   Máximo de detalhe, mas mais pesado e requer privilégios de
  captura de rede.

<!-------------->
Pergunta 9: Como o Agente de Regras injeta a regra gerada no
   IDS?
  
  O overview menciona que o agente "injeta a regra criada no
  IDS", mas não especifica o mecanismo. Para o Snort, as
  opções práticas são:

  - (A) Escrita direta no arquivo de regras — o agente escreve
   a nova regra em um arquivo .rules dedicado (ex:
  ai_generated.rules) e envia um sinal SIGHUP ou reinicia o
  processo do Snort para recarregar as regras.
  - (B) API de gestão do IDS — alguns IDS têm APIs REST para
  hot-reload de regras. O Snort 3 tem suporte experimental a
  isso; Suricata tem a suricatasc socket API.
  - (C) Abstração similar ao IDS Monitor — uma interface
  IDSRuleInjector com implementações por IDS, para manter a
  agnósticidade.

  Minha recomendação: (C) com implementação inicial via (A) —
  escrever num arquivo dedicado e recarregar o Snort é simples
   e confiável para o protótipo, e a abstração já prepara o
  suporte a outros IDS. Um arquivo dedicado (ex:
  ai_generated.rules) evita contaminar as regras existentes do
   IDS.

  Como a regra é injetada no IDS?

<!-------------->
(C) com implementação inicial via (A) —
  escrever num arquivo dedicado e recarregar o Snort é simples
   e confiável para o protótipo, e a abstração já prepara o
  suporte a outros IDS. Um arquivo dedicado (ex:
  ai_generated.rules) evita contaminar as regras existentes do
   IDS.
<!-------------->
 Pergunta 10: Como o sistema gerencia os SIDs das regras 
  geradas?

  No Snort, cada regra precisa de um sid (Signature ID) único.
   Se o agente gerar duas regras com o mesmo sid, o Snort vai
  rejeitar ou sobrescrever silenciosamente. Isso é um detalhe
  técnico crítico que o overview não menciona.

  - (A) Range reservado fixo — o sistema usa um range de SIDs
  reservado para regras geradas por IA (ex:
  9.000.000–9.999.999, que é o range recomendado para regras
  locais pelo Snort). O sistema incrementa sequencialmente
  dentro desse range.
  - (B) Gerado pelo LLM — o agente escolhe o SID. Arriscado:
  LLMs tendem a repetir valores como 1000001 sem garantia de
  unicidade.
  - (C) Gerado pelo sistema com registro — o sistema mantém um
   contador persistente e atribui SIDs automaticamente,
  independente do que o LLM sugere. A regra gerada pelo LLM
  tem o SID substituído antes da injeção.

  Minha recomendação: (C) — o LLM não deve ser responsável por
   garantir unicidade de identificadores. O sistema atribui o
  SID e registra o mapeamento sid → intenção do operador para
  rastreabilidade.

  Como os SIDs das regras geradas são gerenciados?

<!-------------->
(C) — o LLM não deve ser responsável por
   garantir unicidade de identificadores. O sistema atribui o
  SID e registra o mapeamento sid → intenção do operador para
  rastreabilidade.
<!-------------->
 Pergunta 11: Como o Agente Atacante decide qual ferramenta 
  usar para simular um ataque?

  O operador envia uma intenção em linguagem natural (ex:
  "bloquear tráfego com características ABC"). O Agente de
  Regras traduz isso em uma regra Snort. Mas o Agente Atacante
   precisa saber como gerar tráfego com aquelas
  características — e com múltiplas ferramentas disponíveis,
  algo precisa fazer essa escolha.

  - (A) O próprio LLM decide — o Agente Atacante recebe a
  intenção do operador e a regra gerada, e raciocina sobre
  qual ferramenta é mais adequada para gerar o tráfego
  correspondente.
  - (B) O operador especifica a ferramenta — junto com a
  intenção, o operador indica qual ferramenta usar para o
  teste (ex: "use nmap para testar").
  - (C) Catálogo de ferramentas com mapeamento por tipo de 
  ataque — o sistema mantém um mapeamento estático (ex: port
  scan → nmap, flood → hping3, exploits → metasploit) que o
  agente consulta.
  - (D) Combinação de (A) + (C) — o catálogo restringe as
  opções disponíveis, e o LLM escolhe entre elas com base na
  intenção.

  Minha recomendação: (D) — deixar o LLM escolher livremente
  entre todas as ferramentas instaladas é imprevisível e
  difícil de auditar. Um catálogo definido torna o
  comportamento do agente previsível e testável, enquanto o
  LLM ainda tem flexibilidade para raciocinar dentro das
  opções disponíveis.

  Como o Agente Atacante seleciona a ferramenta de ataque?
<!-------------->
(D) — deixar o LLM escolher livremente entre todas as ferramentas instaladas é imprevisível e difícil de
   auditar. Um catálogo definido torna o comportamento do agente previsível e testável, enquanto o LLM ainda tem flexibilidade
   para raciocinar dentro das opções disponíveis.

   É importante implementar um fallback de modo que uma intent que não se traduz para nenhum item do catalogo, não gere nenhuma execução inválida. 

<!-------------->
 Pergunta 12: O que são as "variantes" do ataque usadas para testar robustez da regra?
  
  Na condição de convergência definimos que a regra precisa detectar "o ataque original e um conjunto de variantes".
  Precisamos definir o que é uma variante.

  - (A) Variações de parâmetros da ferramenta — o mesmo ataque com parâmetros diferentes: outra porta, outro IP de origem,
  outro payload, outro TTL. Ex: se o ataque original foi nmap -p 80, uma variante é nmap -p 8080.
  - (B) Evasões técnicas conhecidas — fragmentação de pacotes, timing lento, encoding alternativo — técnicas clássicas de
  evasão de IDS. Mais realista, mas exige conhecimento prévio do catálogo de evasões.
  - (C) Geradas pelo LLM — o Agente Atacante raciocina sobre quais variantes fariam sentido dado o ataque e a regra, e as gera
   de forma autônoma.
  - (D) Combinação de (A) + (C) — variações de parâmetros são geradas sistematicamente, e o LLM também pode propor variantes
  mais criativas baseadas no contexto.

  Minha recomendação: (D) — variações de parâmetros são baratas de gerar e cobrem os casos óbvios. Deixar o LLM propor
  variantes adicionais aproveita o raciocínio do modelo para cobrir casos que um script fixo não anteciparia, sem depender
  exclusivamente de um catálogo de evasões pré-definido.

  O que constitui uma variante de ataque?

<!-------------->
  - (A) Variações de parâmetros da ferramenta — o mesmo ataque com parâmetros diferentes: outra porta, outro IP de origem, outro payload, outro TTL. Ex: se o
  ataque original foi nmap -p 80, uma variante é nmap -p 8080.

<!-------------->
 Pergunta 13: A regra gerada pelo LLM é validada sintaticamente antes de ser injetada no IDS?

  LLMs cometem erros de sintaxe em regras Snort — parênteses desbalanceados, opções inválidas, valores fora do range. Injetar uma regra inválida faz o Snort
  falhar no reload, quebrando o loop silenciosamente.

  - (A) Não — o Snort valida ao recarregar — se a regra for inválida, o Snort retorna erro no reload e o sistema captura isso como falha.
  - (B) Sim — validação sintática antes da injeção — o sistema roda snort -T (modo de teste) contra a regra gerada antes de injetá-la. Regras inválidas são
  rejeitadas e o erro é devolvido ao Agente de Regras como parte do feedback.
  - (C) Sim — validação por parser próprio — o sistema implementa um parser de regras Snort para validar sem depender do binário do Snort.

  Minha recomendação: (B) — snort -T é o validador canônico e gratuito. É mais confiável que um parser próprio (C) e mais seguro que descobrir o erro só no
  reload (A). O erro de validação entra no loop de feedback como mais um sinal para o Agente de Regras corrigir a regra.

  A regra é validada antes da injeção?

<!-------------->
  - (B) Sim — validação sintática antes da injeção — o sistema roda snort -T (modo de teste) contra a regra gerada antes de injetá-la. Regras inválidas são
  rejeitadas e o erro é devolvido ao Agente de Regras como parte do feedback.

  Porém a implementação disso deve ser agnóstica ao IDS.
<!-------------->
  Pergunta 14: Como os resultados dos experimentos são persistidos?

  As métricas que definimos (taxa de detecção, precisão/recall, iterações até convergência, qualidade estrutural) precisam ser armazenadas para análise
  posterior. Onde e como?

  - (A) Arquivos JSON/CSV por experimento — cada execução gera um arquivo com todas as métricas, regras geradas, payloads de feedback e PCAPs referenciados.
  Simples, sem dependência de banco de dados.
  - (B) Banco de dados relacional (ex: SQLite) — métricas estruturadas em tabelas, com relacionamentos entre experimento → iterações → regras → resultados.
  Mais fácil de consultar e agregar.
  - (C) Banco de dados de documentos (ex: MongoDB, TinyDB) — documentos flexíveis que acomodam o payload de feedback sem schema rígido.
  - (D) A ser definido — não é escopo agora, o foco é o loop funcionar primeiro.

  Minha recomendação: (A) para o protótipo — sem dependência de infraestrutura extra, fácil de inspecionar manualmente, e suficiente para análise em Python
  com pandas. SQLite (B) pode ser adicionado depois se a escala de experimentos exigir consultas mais complexas.

  Como os resultados são armazenados?
<!-------------->
 (A) Arquivos JSON/CSV por experimento — cada execução gera um arquivo com todas as métricas, regras geradas, payloads de feedback e PCAPs referenciados.
  Simples, sem dependência de banco de dados.

<!-------------->
  Pergunta 15: Como o Agente de Regras e o Agente Atacante se comunicam?
  
  O overview descreve dois agentes que trocam informações, mas não define o canal de comunicação. Isso é especialmente relevante porque as 4 entidades podem
  estar em hosts diferentes.

  - (A) Chamadas diretas no mesmo processo — os dois agentes rodam no mesmo processo Python na Entidade 1. A comunicação é via objetos Python. Simples, mas os
   agentes ficam acoplados ao mesmo host.
  - (B) API REST entre entidades — cada agente expõe endpoints HTTP. O Agente de Regras chama o Agente Atacante via HTTP e vice-versa. Permite que as
  entidades fiquem em hosts diferentes.
  - (C) Fila de mensagens (ex: Redis, RabbitMQ) — os agentes publicam e consomem mensagens de uma fila. Desacopla tempo de execução, mas adiciona
  infraestrutura.
  - (D) Orquestrador central — um processo coordenador na Entidade 1 gerencia o loop, passando mensagens entre os agentes. Os agentes são workers sem
  conhecimento um do outro.

  Minha recomendação: (D) com comunicação via (A) para o protótipo — um orquestrador central que controla o loop é mais simples de testar e debugar. A
  separação em hosts diferentes pode ser endereçada depois introduzindo (B) como transporte, sem mudar a lógica dos agentes.

  Como os agentes se comunicam?

<!-------------->
 - (B) API REST entre entidades — cada agente expõe endpoints HTTP. O Agente de Regras chama o Agente Atacante via HTTP e vice-versa. Permite que as
  entidades fiquem em hosts diferentes.
<!-------------->
  Pergunta 16: Quem orquestra o loop de feedback?
  
  Com dois agentes se comunicando via HTTP, alguém precisa ser o dono do estado do loop — saber em qual iteração estamos, quando parar, e o que fazer a
  seguir. As opções:

  - (A) O Agente de Regras orquestra — após injetar a regra, ele chama o Agente Atacante e aguarda o resultado. Se a regra falhar, ele recebe o feedback e
  repete. O Agente Atacante é um worker sem estado de loop.
  - (B) O Agente Atacante orquestra — ele recebe a intenção, solicita uma regra ao Agente de Regras, testa, e se falhar envia feedback e solicita nova regra.
  O Agente de Regras é um worker sem estado de loop.
  - (C) Orquestrador separado (Entidade 1) — um terceiro componente coordena o loop, chamando cada agente na sequência certa. Os agentes são stateless e
  focados em sua tarefa específica.
  - (D) Operador inicia, agentes se chamam mutuamente — o operador dispara para o Agente de Regras, que chama o Agente Atacante, que chama de volta o Agente
  de Regras em loop, sem coordenador central.

  Minha recomendação: (C) — um orquestrador separado mantém o estado do loop centralizado, torna cada agente mais simples e testável isoladamente, e é mais
  fácil de monitorar e depurar. (D) cria dependência circular entre agentes que complica o tratamento de erros.

  Quem controla o loop?
<!-------------->
- (C) Orquestrador separado (Entidade 1) — um terceiro componente coordena o loop, chamando cada agente na sequência certa. Os agentes são stateless e
  focados em sua tarefa específica.
<!-------------->
  Pergunta 17: Qual componente roda em qual entidade?
  
  Com orquestrador, Agente de Regras e Agente Atacante definidos, precisamos mapear cada um às 4 entidades do overview. Uma proposta natural dado o que
  definimos:

  ┌────────────┬────────────────────────────────────────────────────────────────────────────────────────┐
  │  Entidade  │                                      Componentes                                       │
  ├────────────┼────────────────────────────────────────────────────────────────────────────────────────┤
  │ Entidade 1 │ Orquestrador + Agente de Regras + interface do operador                                │
  ├────────────┼────────────────────────────────────────────────────────────────────────────────────────┤
  │ Entidade 2 │ Snort (IDS) — acessado remotamente pelo IDS Rule Injector e IDS Monitor da Entidade 1  │
  ├────────────┼────────────────────────────────────────────────────────────────────────────────────────┤
  │ Entidade 3 │ Agente Atacante — precisa estar na mesma rede que a Entidade 4 para gerar tráfego real │
  ├────────────┼────────────────────────────────────────────────────────────────────────────────────────┤
  │ Entidade 4 │ Host alvo — recebe o tráfego de ataque da Entidade 3                                   │
  └────────────┴────────────────────────────────────────────────────────────────────────────────────────┘

  Isso significa que o IDS Rule Injector e o IDS Monitor da Entidade 1 acessam os arquivos da Entidade 2 remotamente (ex: via SSH, NFS, ou a Entidade 2 expõe
  uma API simples para isso).

  Esse mapeamento faz sentido para o seu cenário? Ou o Agente de Regras deveria rodar na Entidade 2 junto com o IDS para ter acesso local aos arquivos?
<!-------------->
 Pergunta 18: Como o operador submete a intenção ao sistema?
  
  O overview descreve o operador enviando "um texto em linguagem natural com a sua intenção de regra". Precisamos definir a interface concreta.

  - (A) CLI — o operador executa um comando como rules-farmer run "Quero bloquear tráfego com características ABC". Simples, sem UI, fácil de automatizar e
  testar.
  - (B) API REST — o operador (ou outro sistema) faz um POST /experiments com a intenção no body. Permite integração com outras ferramentas e acesso remoto.
  - (C) Interface web — um dashboard onde o operador digita a intenção e acompanha o progresso do loop em tempo real.
  - (D) Arquivo de configuração — o operador define um arquivo YAML/JSON com a intenção e parâmetros do experimento (N máximo de iterações, ferramentas
  permitidas etc.) e executa o sistema apontando para ele.

  Minha recomendação: (A) para o protótipo — CLI é o caminho mais rápido para ter o loop funcional e testável. (B) é o próximo passo natural depois,
  especialmente porque o Orquestrador já expõe REST para os outros componentes.

  Como o operador interage com o sistema?

<!-------------->
  - (B) API REST — o operador (ou outro sistema) faz um POST /experiments com a intenção no body. Permite integração com outras ferramentas e acesso remoto.

<!-------------->
  Pergunta 19: Como as APIs REST entre entidades são autenticadas?
  
  Com quatro entidades em hosts potencialmente diferentes, as APIs expostas precisam de algum nível de controle de acesso — especialmente a API do Agente
  Atacante, que invoca ferramentas como Metasploit.

  - (A) Sem autenticação — as APIs são acessíveis apenas dentro da rede isolada do testbed. Confiança no isolamento de rede.
  - (B) API keys estáticas — cada serviço recebe uma chave configurável. Simples de implementar, suficiente para um ambiente de pesquisa.
  - (C) mTLS — autenticação mútua por certificados. Robusto, mas complexo de configurar.
  - (D) A ser definido — não é escopo do protótipo.

  Minha recomendação: (B) — API keys estáticas são suficientes para um ambiente de pesquisa controlado, adicionam uma camada mínima de proteção sem overhead
  operacional significativo, e são triviais de implementar em FastAPI.

  Como as APIs são autenticadas?
<!-------------->
- (A) Sem autenticação — as APIs são acessíveis apenas dentro da rede isolada do testbed. Confiança no isolamento de rede.

<!-------------->
  Pergunta 20: O que o operador pode configurar por experimento no POST /experiments?
  
  Além da intenção em linguagem natural, o operador pode querer controlar parâmetros do experimento. Quais campos fazem sentido no body da requisição?

  Minha proposta de campos:

  {
    "intent": "Bloquear tráfego com características ABC",
    "max_iterations": 5,
    "allowed_tools": ["nmap", "hping3"],
    "variant_count": 3
  }

  - intent — obrigatório, a intenção em linguagem natural
  - max_iterations — opcional, N máximo de iterações (fallback global configurável)
  - allowed_tools — opcional, subconjunto do catálogo de ferramentas permitidas para esse experimento
  - variant_count — opcional, quantas variantes do ataque testar na fase de robustez

  Esses campos fazem sentido? Falta algum? Algum deveria ser removido?

<!-------------->
Faz sentido.
<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

<!-------------->

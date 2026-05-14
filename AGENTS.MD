## Workflow de TDD

Para qualquer implementação nova ou correção de bug:

1. Antes de alterar código de produção, criar ou atualizar testes.
2. Executar os testes e verificar que falham quando aplicável.
3. Implementar a menor alteração possível.
4. Executar novamente os testes.
5. Só refatorar depois dos testes passarem.
6. Sempre reportar comandos executados e resultados.

## Grill me with docs

Quando o usuário pedir "grill me", o Codex deve:

1. Ler README.md, AGENTS.md, docs/ e testes relevantes.
2. Fazer perguntas críticas antes de implementar.
3. Identificar ambiguidades, riscos e requisitos ocultos.
4. Relacionar cada pergunta com arquivos do projeto quando possível.
5. Não alterar código até que as perguntas principais sejam respondidas.
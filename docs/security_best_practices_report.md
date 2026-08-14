# Relatório de boas práticas de segurança

## Resumo

O projeto é adequado para estudo local, mas não deve ser exposto diretamente à internet. As maiores prioridades são proteger as rotas que executam processos do sistema, restringir CORS e adicionar controles de produção antes de qualquer deploy público.

## Alta prioridade

### SEC-001 — Rotas de ferramentas sem autenticação real

- Severidade: Alta
- Localização: `api/main.py:117-196`, rotas `/sherlock`, `/nmap` e `/security-sweep`.
- Evidência: as rotas executam `subprocess.run(...)` após validação de formato; `authorized: true` é apenas uma declaração enviada pelo cliente e não substitui identidade/autorização.
- Impacto: qualquer pessoa que consiga alcançar a API pode iniciar processos longos e fazer o servidor consultar alvos escolhidos.
- Medida: manter a API presa a `127.0.0.1` no desenvolvimento; em ambiente compartilhado, adicionar autenticação, autorização por usuário, rate limit, fila de tarefas e uma allowlist de alvos. A confirmação de permissão não substitui autenticação.
- Mitigação atual: as rotas Nmap exigem `authorized: true` no backend e todos os processos têm timeout.

### SEC-002 — CORS amplo

- Severidade: Alta em deploy público; Média em desenvolvimento local.
- Localização: `api/main.py:21-26`.
- Evidência: origens, métodos e cabeçalhos eram aceitos de forma ampla.
- Impacto: qualquer site aberto no navegador poderia tentar chamar a API; CORS não é autenticação.
- Medida: usar uma allowlist de origens conhecidas e manter a API em host local durante o estudo.
- Mitigação aplicada: origens limitadas a `http://127.0.0.1:3000` e `http://localhost:3000`.

## Média prioridade

### SEC-003 — Execução síncrona de processos longos

- Severidade: Média.
- Localização: `api/main.py:117-182`.
- Evidência: Sherlock e Nmap rodam dentro do handler HTTP, com timeout de até 120 segundos.
- Impacto: requisições simultâneas podem consumir workers e causar indisponibilidade.
- Medida: adicionar rate limit, limitar concorrência, usar fila de tarefas e retornar um ID para consultar o resultado; manter limites de tempo e saída.

### SEC-004 — Documentação OpenAPI padrão

- Severidade: Média em produção.
- Localização: `api/main.py:13`.
- Evidência: `FastAPI()` mantém `/docs`, `/redoc` e `/openapi.json` ativos.
- Impacto: revela rotas e formatos para qualquer visitante.
- Medida: desativar ou proteger esses endpoints em produção.

### SEC-005 — Handlers inline e `innerHTML` no frontend

- Severidade: Média/baixa no estado atual.
- Localização: `index.html:19-21,79,92,114,124`; `script.js:225-228`.
- Evidência: o HTML usa `onclick`/`onsubmit` e a troca de idioma usa `innerHTML`.
- Impacto: dificulta uma CSP estrita e aumenta o risco caso traduções passem a vir de fonte externa.
- Medida: trocar handlers inline por `addEventListener` e usar `textContent` para traduções sem HTML; se HTML for necessário, usar uma allowlist pequena e CSP.

## Baixa prioridade

### SEC-006 — Divulgação de endereços IP

- Severidade: Baixa em ambiente local.
- Localização: `api/main.py:85-91`.
- Evidência: `/ip` retorna IP do cliente, IP da máquina e IP público.
- Impacto: expõe dados de rede desnecessários se a rota for publicada.
- Medida: proteger a rota, retornar apenas o dado necessário e evitar exibir IP público em produção sem finalidade clara.

## Próximas medidas recomendadas

1. Adicionar autenticação e rate limiting antes de permitir acesso fora da máquina local.
2. Usar allowlist de alvos para Nmap em vez de aceitar qualquer hostname/CIDR.
3. Desativar docs e reload em produção.
4. Migrar os handlers inline e substituir `innerHTML` por `textContent`.
5. Executar processos em fila isolada, com limite de concorrência e tamanho máximo de saída.

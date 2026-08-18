# Segurança — notas rápidas

Projeto ok para lab local. Não publique direto na internet sem hardening.

## Alta

**Rotas de ferramenta sem auth real** (`api/main.py`, `/sherlock`, `/nmap`, etc.)

`authorized: true` vem do browser — não é autenticação. Quem alcançar a API pode disparar subprocessos.

→ Dev: bind em `127.0.0.1`. Produção: auth, rate limit, fila, allowlist de alvos.

**CORS** — origens limitadas a `127.0.0.1:3000` e `localhost:3000`. CORS não substitui auth.

## Média

- Processos síncronos no handler (timeout até 120s) — risco de saturar workers.
- `/docs` e `/openapi.json` abertos — desligar em produção.
- Handlers inline + `innerHTML` no front — dificulta CSP.

## Baixa

- `/ip` expõe IP cliente, máquina e público — ok no lab, evitar em prod.

## Antes de expor

1. Auth + rate limit
2. Allowlist de alvos Nmap
3. Desligar docs/reload
4. Fila para subprocessos
5. CSP + `textContent` no i18n

# SQLMap — alvos locais

Não há CRUD vulnerável neste repo. Só login FastAPI + SQLAlchemy (auth normal, senha com hash).

Use SQLMap em lab local ou com autorização por escrito.

## URLs

| Onde | URL |
|------|-----|
| FastAPI direto | `http://127.0.0.1:8000/login` |
| Via front | `http://127.0.0.1:3000/api/backend/login` |
| Via NGINX | `https://127.0.0.1:8443/api/backend/login` |

Demo: `demo` / `DemoPass123!`

## Lab SQLMap (GET vulneravel)

```text
http://127.0.0.1:8000/lab/user?id=1
```

Via front:

```text
http://127.0.0.1:3000/api/backend/lab/user?id=1
```

Propositalmente inseguro — só lab local. SQLite em `data/app.db`, usuario demo id `1`.

```bash
python osint/sqlmap/sqlmap.py -u "http://127.0.0.1:8000/lab/user?id=1" --batch -v
```

## Login (seguro)

GET `/login` não tem parâmetros na URL — aviso do SQLMap é normal.

Endpoint do form:

```text
http://127.0.0.1:8000/auth/login/form
```

Flags na UI:

```text
--data "username=demo&password=DemoPass123!" -vv --level=2
```

Backend já manda `-v` e `--batch`.

CLI:

```bash
python osint/sqlmap/sqlmap.py \
  -u "http://127.0.0.1:8000/auth/login/form" \
  --data "username=demo&password=DemoPass123!" \
  --batch -v
```

Via proxy do front, troque o host por `http://127.0.0.1:3000/api/backend/...`.

## O que esperar

- Login **não** é vulnerável de propósito — SQLMap deve conectar e não achar injeção.
- `Connection refused` = serviço parado.
- Erro de proxy na UI = reinicie com `./run.sh`.

## Lab completo (futuro)

Para prática real: DVWA, WebGoat ou um CRUD mínimo com `?id=1`. Ainda não existe aqui.

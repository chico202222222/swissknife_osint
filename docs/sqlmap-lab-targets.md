# Alvos locais para SQLMap

Este projeto **nao inclui um CRUD vulneravel dedicado**. O que existe hoje e a pagina de **login com FastAPI + SQLAlchemy** (auth segura, senha com hash). O placeholder `http://127.0.0.1:8080/login` na UI foi pensado para um lab futuro.

Use SQLMap **somente** em alvos locais ou com autorizacao explicita por escrito.

## Links disponiveis hoje

| Acesso | URL |
|--------|-----|
| Direto no FastAPI | `http://127.0.0.1:8000/login` |
| Via frontend (recomendado) | `http://127.0.0.1:3000/api/backend/login` |
| Com NGINX HTTPS ativo | `https://127.0.0.1:8443/api/backend/login` |

O botao **Login (SQL)** no topo da UI abre:

```text
http://127.0.0.1:3000/api/backend/login
```

Usuario demo criado no startup:

- **Usuario:** `demo`
- **Senha:** `DemoPass123!`

## Como usar no SQLMap (UI ou CLI)

A pagina de login em GET **nao expoe parametros na URL** (`?id=1`, etc.). O SQLMap pode avisar que nao ha parametros GET — isso e esperado.

Para testar o **formulario POST** de login, use o endpoint:

```text
http://127.0.0.1:8000/auth/login/form
```

### Via UI (campo de flags extras)

Exemplo de flags:

```text
--data "username=demo&password=DemoPass123!" -vv --level=2
```

O backend ja envia `-v` e `--batch` por padrao.

### Via CLI

```bash
python osint/sqlmap/sqlmap.py \
  -u "http://127.0.0.1:8000/auth/login/form" \
  --data "username=demo&password=DemoPass123!" \
  --batch -v
```

Via proxy do frontend:

```bash
python osint/sqlmap/sqlmap.py \
  -u "http://127.0.0.1:3000/api/backend/auth/login/form" \
  --data "username=demo&password=DemoPass123!" \
  --batch -v
```

## O que esperar

- O login atual **nao e vulneravel de proposito**. O SQLMap deve conectar e analisar, mas nao deve encontrar injecao SQL real.
- Se o alvo nao estiver no ar, a saida mostra `Connection refused` — isso indica servico indisponivel, nao falha da UI.
- Se a UI mostrar erro de proxy (`This backend route is not exposed...`), reinicie o stack: `./run.sh`.

## NGINX (porta 8080 / 8443)

Com o proxy HTTPS local ativo (ver `activate_nginx.txt` na raiz do repo):

- `http://localhost:8080` redireciona para HTTPS
- Frontend: `https://localhost:8443`
- Login via NGINX: `https://localhost:8443/api/backend/login`

A porta `8080` so entra em cena quando o NGINX esta rodando; ela nao hospeda um CRUD separado neste repositorio.

## Lab de injecao SQL completo (futuro)

Para pratica real de SQL injection, seria necessario um app de lab dedicado, por exemplo:

- DVWA
- OWASP WebGoat
- Um CRUD local minimo com parametros na URL, ex.: `http://127.0.0.1:8080/vulnerables.php?id=1`

Isso ainda **nao esta implementado** neste projeto.

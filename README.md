# suica-opsec-kit

Painel local para estudar OPSEC. A UI bloqueia os campos até você aceitar a política de privacidade.

## Uso

O uso é livre para todos, porém todos os repositórios e ferramentas usados estão protegidos atrás de suas licenças.

## Ferramentas

| Ferramenta | O que faz |
|------------|-----------|
| Sherlock / Blackbird | Busca de username em fontes públicas |
| Nmap | Scan de portas em alvo autorizado. *IMPORTANTE:* Nmap é rastreável |
| TShark | Captura HTTP/TLS no loopback (`tools/tshark/bin/tshark`) |
| SQLMap | Teste local com flags extras |
| Login (SQL) | FastAPI + SQLAlchemy — `/api/backend/login` → `/dashboard` |
| Password resilience | Avalia senha de teste (não faz login) |
| ExifTool | Metadados e GPS da foto |
| Wireless | Inventário read-only (airmon-ng / networksetup / netsh) |
| VLAN lab | Lista VLANs e gera plano dry-run |

Não ativa monitor mode, não faz brute force e não mexe na sua Wi-Fi. TShark só captura loopback após você marcar autorização.

## Stack

```text
Browser → Node :3000 (front + POST /api/exif)
       → FastAPI :8000 (/api/backend/*)
NGINX :8443 (opcional, HTTPS local)
```

## Setup

Clone as ferramentas OSINT:


```bash
mkdir -p osint
git clone https://github.com/p1ngul1n0/blackbird.git osint/blackbird
git clone https://github.com/sherlock-project/sherlock.git osint/sherlock
git clone https://github.com/sqlmapproject/sqlmap.git osint/sqlmap

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
npm install
./setup_tools.sh
```

macOS: `brew install python node nginx nmap wireshark aircrack-ng openssl`

Ubuntu: `sudo apt install python3 python3-venv python3-pip nodejs npm nginx nmap tshark aircrack-ng openssl git`

Detalhes por OS: [DEPENDENCIES.md](DEPENDENCIES.md)

## Rodar

```bash
./run.sh
```

Front: `http://127.0.0.1:3000` — API: `http://127.0.0.1:8000`

Porta ocupada: `lsof -nP -iTCP:3000 -sTCP:LISTEN`

## HTTPS (dev)

```bash
npm run nginx:cert && npm run nginx:render
nginx -t -c "$PWD/deploy/runtime/nginx-https.conf"
nginx -c "$PWD/deploy/runtime/nginx-https.conf"
```

Abra `https://localhost:8443`. Certificado autoassinado — só para lab.

Passo a passo: [activate_nginx.txt](activate_nginx.txt)

## Privacidade

- Foto fica no `localStorage` até você rodar o ExifTool; o servidor apaga o upload depois.
- Sherlock, Blackbird, Nmap e SQLMap podem deixar rastro no IP/horário.
- Checkbox de autorização ≠ permissão legal. Use só alvos seus ou autorizados.

## Testes

Com `./run.sh` ativo:

```bash
.venv/bin/python tests/smoke_webapp.py
npm test
```

## Layout

```text
api/       FastAPI
src/       HTML, CSS, JS
osint/     Sherlock, Blackbird, SQLMap (clone local)
tools/     Nmap e TShark locais
server.js  Node + ExifTool
docs/      Notas de lab
```

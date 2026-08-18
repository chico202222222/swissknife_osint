# Dependências

Python na `:8000`, Node na `:3000`. ExifTool vem do npm (`exiftool-vendored`).

## Clones locais (não versionados)

```bash
mkdir -p osint
git clone https://github.com/p1ngul1n0/blackbird.git osint/blackbird
git clone https://github.com/sherlock-project/sherlock.git osint/sherlock
git clone https://github.com/sqlmapproject/sqlmap.git osint/sqlmap
```

SQLMap só em alvos autorizados. Binários locais: `tools/nmap/bin/`, `tools/tshark/bin/` (via `./setup_tools.sh`).

## Python + Node (todos os OS)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
npm install
```

Windows: `.venv\Scripts\Activate.ps1` e `python` no lugar de `python3`.

## Por sistema

**macOS**

```bash
brew install python node nginx nmap wireshark aircrack-ng openssl
```

Sem `airmon-ng` funcional no Wi-Fi nativo — o app usa `networksetup` (read-only).

**Ubuntu/Debian**

```bash
sudo apt install python3 python3-venv python3-pip nodejs npm nginx nmap tshark aircrack-ng openssl git
```

`airmon-ng` só lista adaptadores. Sem `start`, sem captura.

**Windows**

```powershell
winget install Python.Python.3.13 OpenJS.NodeJS.LTS Git.Git Insecure.Nmap
```

Inventário Wi-Fi via `netsh wlan show interfaces`.

## HTTPS local

```bash
./deploy/generate-local-cert.sh
node deploy/render-nginx-https.mjs
nginx -t -c "$PWD/deploy/runtime/nginx-https.conf"
nginx -c "$PWD/deploy/runtime/nginx-https.conf"
```

Abra `https://localhost:8443`. Em produção, configure `SERVER_NAME`, certificados reais, etc., antes do `render`.

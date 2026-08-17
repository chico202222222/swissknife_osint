# Dependencias por sistema operacional

O projeto usa Python/FastAPI na porta 8000, Node.js na porta 3000 e NGINX como proxy HTTPS. O ExifTool e fornecido pelo pacote npm `exiftool-vendored`.

## Repositorios locais externos

Este projeto depende de duas ferramentas OSINT clonadas em `osint/` para funcionar corretamente em um ambiente local de desenvolvimento. Elas nao sao armazenadas no repositorio principal e devem ser carregadas por cada usuario com os comandos abaixo:

```bash
mkdir -p osint

git clone https://github.com/p1ngul1n0/blackbird.git osint/blackbird
git clone https://github.com/sherlock-project/sherlock.git osint/sherlock
git clone https://github.com/sqlmapproject/sqlmap.git osint/sqlmap *AVISO* nao use sem autorização.
```

Se quiser manter a estrutura do projeto sem mostrar esses diretorios em `git status`, o arquivo [.gitignore](.gitignore) ja ignora `osint/blackbird/` e `osint/sherlock/`.

## Comum a todos os sistemas

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m playwright install chromium
npm install
```

No Windows PowerShell, ative o ambiente com `.venv\Scripts\Activate.ps1` e use `python` no lugar de `python3`.

## macOS

```bash
xcode-select --install
brew install python node nginx nmap aircrack-ng openssl
```

O Homebrew instala Aircrack-ng no macOS, mas nao fornece `airmon-ng`. A aplicacao usa `networksetup -listallhardwareports` como inventario somente-leitura e informa que modo monitor nao e suportado por esse fluxo.

## Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nodejs npm nginx nmap aircrack-ng openssl git
```

No Linux, a aplicacao executa `airmon-ng` sem argumentos para listar adaptadores. Ela nao chama `airmon-ng start`, nao altera interfaces e nao captura pacotes.

## Windows

Instale Python, Node.js, Git e Nmap pelos instaladores oficiais ou pelo `winget`. Para NGINX, use o pacote oficial para Windows ou WSL2; para producao, prefira NGINX em Linux/WSL.

```powershell
winget install Python.Python.3.13
winget install OpenJS.NodeJS.LTS
winget install Git.Git
winget install Insecure.Nmap
```

`airmon-ng` nao e nativo do Windows. A aplicacao usa `netsh wlan show interfaces` como inventario somente-leitura. Adaptadores USB com modo monitor devem ser usados em uma VM/WSL com suporte real de driver e autorizacao apropriada.

## HTTPS local

```bash
./deploy/generate-local-cert.sh
node deploy/render-nginx-https.mjs
nginx -t -c "$PWD/deploy/runtime/nginx-https.conf"
nginx -c "$PWD/deploy/runtime/nginx-https.conf"
```

Abra `https://localhost:8443`. O certificado e autoassinado e deve ser aceito apenas para desenvolvimento LOCAL. Em producao, defina `SERVER_NAME`, `HTTPS_ORIGIN`, `SSL_CERTIFICATE` e `SSL_CERTIFICATE_KEY` com valores reais antes de renderizar.

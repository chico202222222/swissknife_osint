# suica-opsec-kit

Homelab web local para estudar OPSEC, validar entradas e executar ferramentas de diagnostico em ambientes simulados ou expressamente autorizados. A interface exige a aceitacao da politica de privacidade antes de liberar qualquer campo protegido.

## Ferramentas

- **Sherlock** e **Blackbird**: pesquisa de nomes de usuario em fontes publicas.
- **Nmap**: inventario limitado de portas e servicos de um alvo autorizado.
- **Password resilience**: avaliacao local da estrutura de uma senha de teste, sem tentativa de login.
- **ExifTool**: leitura local de metadados, incluindo latitude, longitude, altitude e URL de mapa quando a foto possui GPS.
- **Wireless status**: inventario somente-leitura dos adaptadores; usa `airmon-ng` no Linux, `networksetup` no macOS e `netsh` no Windows.
- **VLAN lab**: inventaria VLANs locais, valida interface e VLAN ID (`1–4094`) e gera um plano de configuracao sem executar comandos.

O projeto nao ativa modo monitor, nao captura pacotes, nao executa ataques de forca bruta e nao tenta acessar redes Wi-Fi.

`airmon-ng` nao configura VLANs. No Linux, o plano VLAN usa a sintaxe do `iproute2`; no macOS e Windows, o card informa as limitacoes da plataforma e do driver. O modo e sempre `dry-run` para nao interromper a conectividade do servidor.

## Arquitetura

```text
Navegador
  -> NGINX HTTPS :8443 (opcional)
     -> Node.js :3000       frontend, Zod e POST /api/exif
     -> FastAPI :8000       demais rotas /api/backend/*
```

O Node encontra `src/index.html` automaticamente. Tanto `/` quanto `/src/` carregam a aplicacao, e caminhos antigos sob `/src/*` sao normalizados.

## Dependencias

### Comuns

- Git e curl
- Python 3.11 ou mais recente, `venv` e `pip`
- Node.js 20 LTS ou mais recente e npm
- Nmap
- NGINX e OpenSSL para o proxy HTTPS
- Chromium instalado pelo Playwright para o smoke test

As dependencias Python estao em `requirements.txt`: FastAPI, Uvicorn, Playwright, Sherlock e dependencias do Blackbird. As dependencias Node estao em `package.json`: Zod, Formidable e `exiftool-vendored`. O executavel ExifTool e fornecido pelo pacote npm, portanto nao precisa de instalacao global.

### macOS

```bash
xcode-select --install
brew install python node nginx nmap aircrack-ng openssl git
```

O pacote Aircrack-ng do macOS nao oferece um fluxo funcional de `airmon-ng` para a interface Wi-Fi nativa. Por isso o app usa `networksetup -listallhardwareports` apenas para inventario.

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nodejs npm nginx nmap aircrack-ng openssl git curl
```

No Linux, o app chama `airmon-ng` sem subcomandos apenas para listar interfaces. Alguns sistemas exigem privilegios para exibir todos os detalhes, mas o servidor nao deve ser iniciado como root.

### Windows

```powershell
winget install Python.Python.3.13
winget install OpenJS.NodeJS.LTS
winget install Git.Git
winget install Insecure.Nmap
```

Use NGINX no WSL2 ou a distribuicao oficial para Windows. `airmon-ng` nao e nativo; o app usa `netsh wlan show interfaces` para inventario somente-leitura.

Mais observacoes por plataforma estao em [DEPENDENCIES.md](DEPENDENCIES.md).

## Instalacao

Antes de instalar as dependencias do projeto, carregue as ferramentas OSINT locais usadas por este repositorio:

```bash
cd suica-opsec-kit
mkdir -p osint
git clone https://github.com/p1ngul1n0/blackbird.git osint/blackbird
git clone https://github.com/sherlock-project/sherlock.git osint/sherlock

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
npm install
chmod +x run.sh setup_tools.sh
./setup_tools.sh
```

No PowerShell, ative o ambiente com `.venv\Scripts\Activate.ps1` e use `python` no lugar de `python3`.

## Execucao

Inicie FastAPI e Node juntos:

```bash
./run.sh
```

Abra `http://127.0.0.1:3000`. A API direta fica em `http://127.0.0.1:8000`.

Para executar separadamente:

```bash
# terminal 1
.venv/bin/uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload

# terminal 2
node server.js
```

Se uma porta estiver ocupada, identifique o processo antes de iniciar outra instancia:

```bash
lsof -nP -iTCP:3000 -sTCP:LISTEN
lsof -nP -iTCP:8000 -sTCP:LISTEN
```

## HTTPS com NGINX

Para desenvolvimento local:

```bash
npm run nginx:cert
npm run nginx:render
nginx -t -c "$PWD/deploy/runtime/nginx-https.conf"
nginx -c "$PWD/deploy/runtime/nginx-https.conf"
```

Abra `https://localhost:8443`. `http://localhost:8080` redireciona para HTTPS. O certificado gerado e autoassinado e serve apenas para desenvolvimento.

Em uma implantacao real, configure `SERVER_NAME`, `HTTPS_ORIGIN`, `SSL_CERTIFICATE` e `SSL_CERTIFICATE_KEY` antes de executar `npm run nginx:render`. Nao exponha diretamente as portas 3000 e 8000 na rede publica.

## Privacidade e autorizacao

- A foto selecionada fica no `localStorage` do navegador e e enviada ao Node local somente ao executar o ExifTool.
- O upload temporario e apagado do servidor depois da analise.
- Coordenadas GPS podem revelar o local exato da captura. O app apenas as exibe e gera a URL; nao abre o mapa nem faz geocodificacao automaticamente.
- Sherlock e Blackbird consultam terceiros, e Nmap conecta ao alvo. Essas atividades podem ser registradas e correlacionadas com seu IP e horario.
- Use nomes, hosts e redes proprios ou com autorizacao explicita. A confirmacao na interface nao substitui autorizacao legal.
- Senhas digitadas no avaliador nao sao usadas em login e nao sao persistidas pela aplicacao.

Para remover a foto persistida depois do teste, limpe os dados locais do site no navegador.

## Testes

Com os servidores ativos:

```bash
.venv/bin/python tests/smoke_webapp.py
npm test
```

O smoke test cobre bloqueio pela politica, validacao Zod, password resilience, upload ExifTool, resposta GPS, inventario wireless, troca de idioma e rotas `/`, `/src/index.html` e `/privacy`.

## Estrutura

```text
api/                 backend FastAPI
deploy/              templates e scripts NGINX/HTTPS
docs/                documentacao de seguranca
osint/               copias locais de Sherlock e Blackbird
src/                 index.html, CSS e JavaScript do frontend
tests/               smoke tests Playwright
tools/               validadores e ferramentas locais
server.js            servidor Node e endpoint ExifTool
run.sh               inicializacao coordenada dos servidores
```

## Encerramento

Use `Ctrl+C` no terminal do `run.sh`. Para encerrar uma instancia NGINX iniciada com a configuracao local:

```bash
nginx -s stop -c "$PWD/deploy/runtime/nginx-https.conf"
```

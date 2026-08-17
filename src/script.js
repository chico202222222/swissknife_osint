import { z } from "/__vendor/zod/index.js";

const locale = {
    en: {
        eyebrow: "FastAPI demo",
        title: "Random number board",
        description: "I am testing how JavaScript can call FastAPI routes and trigger backend functions.",
        numbersLabel: "Live result",
        numbersTitle: "Number from GET /",
        refresh: "Refresh",
        openLoginPage: "Login (SQL)",
        status: 'GET / returns <code>{"message": number}</code>',
        ipTitle: "Connection info",
        clientIp: "Client IP",
        machineIp: "Machine IP",
        publicIp: "Public IP",
        browserLabel: "Browser signal",
        runSignal: "Run signal",
        curlTitle: "Curl checks",
        browserResult: "Backend ran",
        unknown: "Not found",
        apiErrorTitle: "API error",
        apiErrorHint: "Check that FastAPI is running and reachable through /api/backend.",
        sherlockLabel: "Username search",
        sherlockTitle: "Run Sherlock",
        sherlockDescription: "Search public username profiles.",
        usernameLabel: "Username",
        runSherlock: "Search",
        sherlockWaiting: "Results will appear here.",
        blackbirdLabel: "Username search",
        blackbirdTitle: "Run Blackbird",
        blackbirdDescription: "Search public username profiles across social platforms.",
        runBlackbird: "Search",
        blackbirdWaiting: "Results will appear here.",
        nmapLabel: "Network scan",
        nmapTitle: "Run Nmap",
        nmapDescription: "Scan the top 100 ports of an authorized target.",
        nmapWarning: "ONLY SCAN IF YOU HAVE PERMISSION!",
        targetLabel: "Target",
        runNmap: "Scan",
        nmapWaiting: "Results will appear here.",
        permissionLabel: "I have permission to scan this target.",
        runSecurity: "Security sweep",
        flagsLabel: "Extra flags",
        flagsOptional: "Optional",
        nmapFlagsLabel: "Scan options",
        nmapFlagsHint: "Click to toggle options. Verbose (-v) is enabled by default.",
        nmapFlagOpen: "Open only",
        nmapFlagFast: "Fast (-F)",
        nmapFlagService: "Service versions (-sV)",
        nmapFlagScripts: "Default scripts (-sC)",
        nmapFlagOs: "OS detection (-O)",
        nmapFlagAggressive: "Aggressive (-A)",
        nmapFlagTimingFast: "Faster timing (-T4)",
        nmapFlagReason: "Show reason (--reason)",
        blackbirdFlagsHint: "Example: --timeout 5 (verbose is enabled by default)",
        sherlockFlagsHint: "Example: --site GitHub (verbose is enabled by default)",
        tsharkFlagsHint: "Example: -V -c 20",
        sqlmapLabel: "SQL injection lab",
        sqlmapTitle: "Run SQLMap",
        sqlmapDescription: "Run SQLMap against an authorized web target with verbose output.",
        targetUrlLabel: "Target URL",
        runSqlmap: "Run SQLMap",
        sqlmapWarning: "DANGEROUS TOOL: ONLY USE ON YOUR OWN LOCAL LAB OR WITH EXPLICIT WRITTEN PERMISSION.",
        sqlmapPermissionLabel: "I have permission to test this web application with SQLMap.",
        sqlmapWaiting: "SQLMap output will appear here.",
        sqlmapFlagsHint: "Example: --data \"username=demo&password=DemoPass123!\" -vv --level=2",
        tsharkLabel: "Packet inspection",
        tsharkTitle: "Run TShark",
        tsharkDescription: "Capture loopback HTTP traffic or TLS handshakes from local lab ports such as NGINX on 8443.",
        tsharkProfileLabel: "Profile",
        tsharkProfileHttp: "HTTP packets",
        tsharkProfileTls: "TLS handshake (NGINX)",
        tsharkPortLabel: "Local port",
        runTshark: "Capture",
        tsharkWarning: "LOOPBACK ONLY: capture stays on this machine and requires local authorization.",
        tsharkPermissionLabel: "I am authorized to capture traffic on this local interface.",
        tsharkWaiting: "Captured packet fields will appear here.",
        resilienceLabel: "Local security check",
        resilienceTitle: "Password resilience",
        resilienceDescription: "Evaluate a test password locally without login attempts.",
        testPasswordLabel: "Test password",
        runResilience: "Evaluate",
        resilienceWaiting: "The local assessment will appear here.",
        resilienceResult: "Resilience",
        passwordPermissionLabel: "I am authorized to assess this test password.",
        authorizationRequired: "Confirm authorization before running this check.",
        exifLabel: "Local image metadata",
        exifTitle: "Run ExifTool",
        exifDescription: "Read metadata from an image using the local JavaScript server.",
        imageLabel: "Image",
        runExif: "Read metadata",
        exifWaiting: "ExifTool metadata will appear here.",
        exifCoordinatesFound: "GPS coordinates found in the image metadata.",
        exifCoordinatesMissing: "GPS coordinates are not present in this image.",
        imageStored: "Image saved in this browser. Ready for local analysis.",
        imageTooLarge: "Choose an image up to 2 MB.",
        imageInvalid: "Choose a JPEG, PNG, WebP, TIFF, HEIC or HEIF image.",
        wirelessLabel: "Wireless adapter audit",
        wirelessTitle: "Airmon-ng status",
        wirelessDescription: "List local wireless adapters with the safe command for this operating system.",
        runWireless: "Inspect adapters",
        wirelessWaiting: "Wireless adapter information will appear here.",
        viewVlans: "View VLANs",
        vlanInventoryWaiting: "Local VLANs will appear here.",
        vlanInterfaceLabel: "Local interface",
        vlanIdLabel: "VLAN ID",
        createVlanPlan: "Generate plan",
        vlanPermissionLabel: "I am authorized to configure this local interface.",
        vlanWaiting: "The VLAN plan will appear here. No command will be executed.",
        privacyGateLabel: "Privacy gate",
        privacyTitle: "Privacy policy",
        privacySummary: "Read how this demo handles data before typing.",
        openPrivacyGuide: "Open privacy guide",
        acceptPrivacy: "Accept policy",
        closePrivacyGuide: "Back",
        privacyGuideLabel: "Data guide",
        privacyGuideTitle: "Privacy guide",
        privacyGuideUseTitle: "What is used",
        privacyGuideUseText: "Usernames, network targets, target URLs, packet captures and a test password are sent to the local FastAPI backend only when you run the related tool. SQLMap runs locally with verbose output when you confirm authorization.",
        privacyGuideStorageTitle: "What is not stored",
        privacyGuideStorageText: "Usernames, targets and test passwords are not saved by the application. Results appear only on this session screen.",
        privacyGuideLocalTitle: "Local photo storage",
        privacyGuideLocalText: "The selected photo stays in this browser localStorage and is sent only to the local server. The server temporary file is deleted after ExifTool runs. GPS coordinates, when present, can reveal the exact capture location; they are displayed locally without automatic map requests.",
        privacyGuideTraceTitle: "Network traceability",
        privacyGuideTraceText: "Sherlock and Blackbird query external services, Nmap connects to the target, and TShark reads loopback traffic from local lab ports. Those systems may record your IP, time, searched username and connection source.",
        privacyGuidePermissionTitle: "Your responsibility",
        privacyGuidePermissionText: "Use Sherlock, Blackbird, Nmap and SQLMap only on accounts, hosts and networks you are authorized to check. Use TShark only on loopback lab ports you control.",
        privacyGuideWirelessTitle: "Wireless diagnostics",
        privacyGuideWirelessText: "The wireless check only lists local adapters. The VLAN tool generates a dry-run plan and executes no command. It does not enable monitor mode, capture packets or change your connection.",
        privacyRequired: "Accept the privacy policy before typing.",
        privacyAccepted: "Privacy policy accepted. You can type now.",
        fieldValid: "Data is valid.",
        fieldInvalid: "Data is not valid.",
        fieldRequired: "Fill this field.",
    },
    pt: {
        eyebrow: "Demo FastAPI",
        title: "Painel de numeros aleatorios",
        description: "Estou testando como o JavaScript chama rotas do FastAPI e dispara funcoes no backend.",
        numbersLabel: "Resultado ao vivo",
        numbersTitle: "Numero da rota GET /",
        refresh: "Atualizar",
        openLoginPage: "Login (SQL)",
        status: 'GET / retorna <code>{"message": number}</code>',
        ipTitle: "Informacoes da conexao",
        clientIp: "IP do cliente",
        machineIp: "IP da maquina",
        publicIp: "IP publico",
        browserLabel: "Sinal do navegador",
        runSignal: "Executar sinal",
        curlTitle: "Testes com curl",
        browserResult: "Backend executou",
        unknown: "Nao encontrado",
        apiErrorTitle: "Erro na API",
        apiErrorHint: "Confira se o FastAPI esta rodando e acessivel via /api/backend.",
        sherlockLabel: "Busca por usuario",
        sherlockTitle: "Executar Sherlock",
        sherlockDescription: "Procure perfis publicos por nome de usuario.",
        usernameLabel: "Nome de usuario",
        runSherlock: "Buscar",
        sherlockWaiting: "Os resultados aparecerao aqui.",
        blackbirdLabel: "Busca por usuario",
        blackbirdTitle: "Executar Blackbird",
        blackbirdDescription: "Procure perfis publicos por nome de usuario em plataformas sociais.",
        runBlackbird: "Buscar",
        blackbirdWaiting: "Os resultados aparecerao aqui.",
        nmapLabel: "Varredura de rede",
        nmapTitle: "Executar Nmap",
        nmapDescription: "Analise as 100 portas principais de um alvo autorizado.",
        nmapWarning: "SO FACA A VARREDURA SE TIVER PERMISSAO!",
        targetLabel: "Alvo",
        runNmap: "Analisar",
        nmapWaiting: "Os resultados aparecerao aqui.",
        permissionLabel: "Tenho permissao para analisar este alvo.",
        runSecurity: "Varredura de seguranca",
        flagsLabel: "Flags extras",
        flagsOptional: "Opcional",
        nmapFlagsLabel: "Opcoes de scan",
        nmapFlagsHint: "Clique para alternar opcoes. Verbose (-v) ja vem ativado.",
        nmapFlagOpen: "So portas abertas",
        nmapFlagFast: "Rapido (-F)",
        nmapFlagService: "Versoes de servico (-sV)",
        nmapFlagScripts: "Scripts padrao (-sC)",
        nmapFlagOs: "Deteccao de SO (-O)",
        nmapFlagAggressive: "Agressivo (-A)",
        nmapFlagTimingFast: "Timing mais rapido (-T4)",
        nmapFlagReason: "Mostrar motivo (--reason)",
        blackbirdFlagsHint: "Exemplo: --timeout 5 (verbose ativado por padrao)",
        sherlockFlagsHint: "Exemplo: --site GitHub (verbose ativado por padrao)",
        tsharkFlagsHint: "Exemplo: -V -c 20",
        sqlmapLabel: "Lab de injecao SQL",
        sqlmapTitle: "Executar SQLMap",
        sqlmapDescription: "Executa SQLMap em um alvo web autorizado com saida verbosa.",
        targetUrlLabel: "URL alvo",
        runSqlmap: "Executar SQLMap",
        sqlmapWarning: "FERRAMENTA PERIGOSA: USE SOMENTE NO SEU LAB LOCAL OU COM PERMISSAO EXPLICITA POR ESCRITO.",
        sqlmapPermissionLabel: "Tenho permissao para testar esta aplicacao web com SQLMap.",
        sqlmapWaiting: "A saida do SQLMap aparecera aqui.",
        sqlmapFlagsHint: "Exemplo: --data \"username=demo&password=DemoPass123!\" -vv --level=2",
        tsharkLabel: "Inspecao de pacotes",
        tsharkTitle: "Executar TShark",
        tsharkDescription: "Capture trafego HTTP ou handshakes TLS no loopback, incluindo NGINX na porta 8443.",
        tsharkProfileLabel: "Perfil",
        tsharkProfileHttp: "Pacotes HTTP",
        tsharkProfileTls: "Handshake TLS (NGINX)",
        tsharkPortLabel: "Porta local",
        runTshark: "Capturar",
        tsharkWarning: "SOMENTE LOOPBACK: a captura fica nesta maquina e exige autorizacao local.",
        tsharkPermissionLabel: "Tenho autorizacao para capturar trafego nesta interface local.",
        tsharkWaiting: "Os campos dos pacotes capturados aparecerao aqui.",
        resilienceLabel: "Verificacao local de seguranca",
        resilienceTitle: "Resiliencia de senha",
        resilienceDescription: "Avalie uma senha de teste localmente, sem tentativas de login.",
        testPasswordLabel: "Senha de teste",
        runResilience: "Avaliar",
        resilienceWaiting: "A avaliacao local aparecera aqui.",
        resilienceResult: "Resiliencia",
        passwordPermissionLabel: "Tenho autorizacao para avaliar esta senha de teste.",
        authorizationRequired: "Confirme a autorizacao antes de executar esta verificacao.",
        exifLabel: "Metadados locais de imagem",
        exifTitle: "Executar ExifTool",
        exifDescription: "Leia metadados de uma imagem usando o servidor JavaScript local.",
        imageLabel: "Imagem",
        runExif: "Ler metadados",
        exifWaiting: "Os metadados do ExifTool aparecerao aqui.",
        exifCoordinatesFound: "Coordenadas GPS encontradas nos metadados da imagem.",
        exifCoordinatesMissing: "Esta imagem nao possui coordenadas GPS.",
        imageStored: "Imagem salva neste navegador. Pronta para analise local.",
        imageTooLarge: "Escolha uma imagem de ate 2 MB.",
        imageInvalid: "Escolha uma imagem JPEG, PNG, WebP, TIFF, HEIC ou HEIF.",
        wirelessLabel: "Auditoria de adaptador wireless",
        wirelessTitle: "Status do Airmon-ng",
        wirelessDescription: "Liste adaptadores wireless locais com o comando seguro deste sistema operacional.",
        runWireless: "Inspecionar adaptadores",
        wirelessWaiting: "As informacoes dos adaptadores wireless aparecerao aqui.",
        viewVlans: "Ver VLANs",
        vlanInventoryWaiting: "As VLANs locais aparecerao aqui.",
        vlanInterfaceLabel: "Interface local",
        vlanIdLabel: "VLAN ID",
        createVlanPlan: "Gerar plano",
        vlanPermissionLabel: "Tenho autorizacao para configurar esta interface local.",
        vlanWaiting: "O plano VLAN aparecera aqui. Nenhum comando sera executado.",
        privacyGateLabel: "Controle de privacidade",
        privacyTitle: "Politica de privacidade",
        privacySummary: "Antes de digitar, leia como os dados sao usados nesta demo.",
        openPrivacyGuide: "Abrir guia de privacidade",
        acceptPrivacy: "Aceitar politica",
        closePrivacyGuide: "Voltar",
        privacyGuideLabel: "Guia de dados",
        privacyGuideTitle: "Guia de privacidade",
        privacyGuideUseTitle: "O que e usado",
        privacyGuideUseText: "Nomes de usuario, alvos de rede, URLs alvo, capturas de pacotes e uma senha de teste sao enviados ao backend FastAPI local apenas ao executar a ferramenta relacionada. O SQLMap roda localmente com saida verbosa quando voce confirma a autorizacao.",
        privacyGuideStorageTitle: "O que nao e guardado",
        privacyGuideStorageText: "Nomes de usuario, alvos e senhas de teste nao sao salvos pela aplicacao. Resultados aparecem apenas na tela desta sessao.",
        privacyGuideLocalTitle: "Armazenamento local da foto",
        privacyGuideLocalText: "A foto selecionada fica no localStorage deste navegador e e enviada apenas ao servidor local. O arquivo temporario do servidor e apagado depois do ExifTool. Coordenadas GPS, quando presentes, podem revelar o local exato da captura; elas sao exibidas localmente sem requisicoes automaticas ao mapa.",
        privacyGuideTraceTitle: "Rastreabilidade de rede",
        privacyGuideTraceText: "Sherlock e Blackbird consultam servicos externos, Nmap conecta ao alvo e o TShark le trafego loopback de portas locais do lab. Esses sistemas podem registrar seu IP, horario, usuario pesquisado e origem da conexao.",
        privacyGuidePermissionTitle: "Sua responsabilidade",
        privacyGuidePermissionText: "Use Sherlock, Blackbird, Nmap e SQLMap somente em contas, hosts e redes que voce tem autorizacao para verificar. Use o TShark apenas em portas loopback do seu lab.",
        privacyGuideWirelessTitle: "Diagnostico wireless",
        privacyGuideWirelessText: "A verificacao wireless apenas lista adaptadores locais. A ferramenta VLAN gera um plano sem executar comandos. Ela nao ativa modo monitor, nao captura pacotes e nao altera sua conexao.",
        privacyRequired: "Aceite a politica de privacidade antes de digitar.",
        privacyAccepted: "Politica de privacidade aceita. Voce ja pode digitar.",
        fieldValid: "Os dados sao validos.",
        fieldInvalid: "Os dados nao sao validos.",
        fieldRequired: "Preencha este campo.",
    },
};

let language = "pt";

function resolveApiUrl() {
    if (window.location.protocol === "file:") {
        return "http://127.0.0.1:8000";
    }

    return `${window.location.origin}/api/backend`;
}

const apiUrl = resolveApiUrl();
const nmapFlagOptions = [
    { flag: "--open", labelKey: "nmapFlagOpen" },
    { flag: "-F", labelKey: "nmapFlagFast" },
    { flag: "-sV", labelKey: "nmapFlagService" },
    { flag: "-sC", labelKey: "nmapFlagScripts" },
    { flag: "-O", labelKey: "nmapFlagOs" },
    { flag: "-A", labelKey: "nmapFlagAggressive" },
    { flag: "-T4", labelKey: "nmapFlagTimingFast" },
    { flag: "--reason", labelKey: "nmapFlagReason" },
];
// Lab port allowlist — re-enable when done testing other local services (e.g. local AI uvicorn):
// const allowedTsharkPorts = [3000, 8000, 8080, 8443];
const optionalFlagPattern = /^(?!.*[\r\n;|`$()<>])[\s\S]+$/;
const protectedInputIds = ["sherlock-username", "sherlock-flags", "nmap-target", "sqlmap-target", "sqlmap-flags", "blackbird-username", "blackbird-flags", "password-audit", "exif-image", "vlan-interface", "vlan-id", "tshark-port", "tshark-flags"];
const allowedImageTypes = ["image/jpeg", "image/png", "image/webp", "image/tiff", "image/heic", "image/heif"];
const maxImageSize = 2 * 1024 * 1024;
const exifStorageKey = "localExifImage";
const validationSchemas = {
    "sherlock-username": z.string().trim().regex(/^[A-Za-z0-9_.-]{1,50}$/),
    "sherlock-flags": z.string().max(240).refine((value) => value === "" || optionalFlagPattern.test(value.trim())),
    "nmap-target": z.string().trim().regex(/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,252}$/),
    "nmap-flags": z.string().max(240).refine((value) => value === "" || optionalFlagPattern.test(value.trim())),
    "sqlmap-target": z.string().trim().url().regex(/^https?:\/\//),
    "sqlmap-flags": z.string().max(240).refine((value) => value === "" || optionalFlagPattern.test(value.trim())),
    "blackbird-username": z.string().trim().regex(/^[A-Za-z0-9_.-]{1,50}$/),
    "blackbird-flags": z.string().max(240).refine((value) => value === "" || optionalFlagPattern.test(value.trim())),
    "password-audit": z.string().min(8).max(128),
    "exif-image": z.instanceof(File)
        .refine((file) => allowedImageTypes.includes(file.type))
        .refine((file) => file.size <= maxImageSize),
    "vlan-interface": z.string().trim().regex(/^[A-Za-z0-9_.:-]{1,32}$/),
    "vlan-id": z.coerce.number().int().min(1).max(4094),
    // "tshark-port": z.coerce.number().int().refine((port) => allowedTsharkPorts.includes(port)),
    "tshark-port": z.coerce.number().int().min(1).max(65535),
    "tshark-flags": z.string().max(240).refine((value) => value === "" || optionalFlagPattern.test(value.trim())),
};
let lastFocusedElement = null;

function apiFetch(path, options = {}) {
    return fetch(`${apiUrl}${path}`, {
        ...options,
        credentials: "include",
    });
}

function hasAcceptedPrivacy() {
    return document.querySelector("#privacy-accept")?.checked || false;
}

function setValidationMessage(input, message, isValid) {
    const messageElement = document.querySelector(`#${input.id}-validation`);
    messageElement.textContent = message;
    messageElement.classList.toggle("valid", isValid);
    messageElement.classList.toggle("invalid", !isValid);
}

function validateInput(input) {
    if (!hasAcceptedPrivacy()) {
        setValidationMessage(input, locale[language].privacyRequired, false);
        return false;
    }

    const value = input.type === "file"
        ? input.files?.[0]
        : input.id === "password-audit"
            ? input.value
            : input.value.trim();

    if (!value) {
        if (input.id.endsWith("-flags")) {
            setValidationMessage(input, locale[language].flagsOptional, true);
            return true;
        }
        setValidationMessage(input, locale[language].fieldRequired, false);
        return false;
    }

    const schema = validationSchemas[input.id];
    const isValid = schema ? schema.safeParse(value).success : input.checkValidity();
    setValidationMessage(input, isValid ? locale[language].fieldValid : locale[language].fieldInvalid, isValid);
    return isValid;
}

function syncNmapFlagsInput() {
    const flagsInput = document.querySelector("#nmap-flags");
    const chips = document.querySelectorAll("#nmap-flag-chips .flag-chip.selected");
    if (!flagsInput) return;

    flagsInput.value = [...chips].map((chip) => chip.dataset.flag).join(" ");
    validateInput(flagsInput);
}

function renderNmapFlagOptions() {
    const container = document.querySelector("#nmap-flag-chips");
    if (!container) return;

    const selected = new Set(
        [...container.querySelectorAll(".flag-chip.selected")].map((chip) => chip.dataset.flag),
    );
    const enabled = hasAcceptedPrivacy();

    container.innerHTML = nmapFlagOptions.map(({ flag, labelKey }) => {
        const isSelected = selected.has(flag);
        const label = locale[language][labelKey];
        return `<button type="button" class="flag-chip${isSelected ? " selected" : ""}" data-flag="${flag}" aria-pressed="${isSelected}"${enabled ? "" : " disabled"}>${label}</button>`;
    }).join("");
}

function handleNmapFlagClick(event) {
    const chip = event.target.closest(".flag-chip");
    if (!chip || chip.disabled) return;

    chip.classList.toggle("selected");
    chip.setAttribute("aria-pressed", String(chip.classList.contains("selected")));
    syncNmapFlagsInput();
}

function resetNmapFlagOptions() {
    document.querySelectorAll("#nmap-flag-chips .flag-chip").forEach((chip) => {
        chip.classList.remove("selected");
        chip.setAttribute("aria-pressed", "false");
    });
    syncNmapFlagsInput();
}

function updatePrivacyState() {
    const accepted = hasAcceptedPrivacy();
    const privacyStatus = document.querySelector("#privacy-status");
    const acceptButton = document.querySelector("#privacy-accept-button");

    privacyStatus.textContent = accepted ? locale[language].privacyAccepted : locale[language].privacyRequired;
    privacyStatus.classList.toggle("valid", accepted);
    privacyStatus.classList.toggle("invalid", !accepted);
    acceptButton.disabled = accepted;
    acceptButton.textContent = accepted ? locale[language].privacyAccepted : locale[language].acceptPrivacy;

    protectedInputIds.forEach((id) => {
        const input = document.querySelector(`#${id}`);
        if (!input) return;
        input.disabled = !accepted;

        if (!accepted) {
            if (id === "tshark-port") {
                input.value = "3000";
            } else if (id.endsWith("-flags")) {
                input.value = "";
            } else {
                input.value = "";
            }
        }

        validateInput(input);
    });

    if (!accepted) {
        resetNmapFlagOptions();
    }
    renderNmapFlagOptions();

    const tsharkProfile = document.querySelector("#tshark-profile");
    if (tsharkProfile) {
        tsharkProfile.disabled = !accepted;
    }

    document.querySelectorAll("[data-requires-privacy]").forEach((element) => {
        element.disabled = !accepted;
    });
}

function openPrivacyGuide() {
    const guide = document.querySelector("#privacy-guide");
    lastFocusedElement = document.activeElement;
    guide.hidden = false;
    document.body.classList.add("modal-open");
    guide.querySelector("button").focus();
}

function closePrivacyGuide() {
    const guide = document.querySelector("#privacy-guide");
    guide.hidden = true;
    document.body.classList.remove("modal-open");

    if (lastFocusedElement) {
        lastFocusedElement.focus();
    }
}

function acceptPrivacy() {
    document.querySelector("#privacy-accept").checked = true;
    updatePrivacyState();
    closePrivacyGuide();
}

function runSqlmap(event) {
    event.preventDefault();
    const targetInput = document.querySelector("#sqlmap-target");
    const flagsInput = document.querySelector("#sqlmap-flags");
    const output = document.querySelector("#sqlmap-output");
    if (!validateInput(targetInput) || !validateInput(flagsInput)) return;
    if (!document.querySelector("#sqlmap-permission").checked) {
        output.textContent = locale[language].authorizationRequired;
        return;
    }

    const target = targetInput.value.trim();
    const flags = flagsInput.value.trim();
    output.textContent = "Running SQLMap...";

    apiFetch("/sqlmap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            target,
            flags,
            accepted_policy: true,
            authorized: true,
        }),
    })
        .then(async (response) => {
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
            output.textContent = data.output || "No results returned.";
            clearApiError();
        })
        .catch((error) => {
            output.textContent = error.message || "SQLMap could not run.";
            showApiError("POST /sqlmap", error);
        });
}

async function runTsharkInspect(event) {
    event.preventDefault();
    const portInput = document.querySelector("#tshark-port");
    const flagsInput = document.querySelector("#tshark-flags");
    const output = document.querySelector("#tshark-output");
    if (!validateInput(portInput) || !validateInput(flagsInput)) return;
    if (!document.querySelector("#tshark-permission").checked) {
        output.textContent = locale[language].authorizationRequired;
        return;
    }

    const profile = document.querySelector("#tshark-profile").value;
    const port = Number(portInput.value);
    const flags = flagsInput.value.trim();
    output.textContent = "Running TShark...";

    try {
        const response = await apiFetch("/tshark-inspect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                profile,
                port,
                flags,
                accepted_policy: true,
                authorized: true,
            }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);

        output.textContent = data.output || "No packets returned.";
        clearApiError();
    } catch (error) {
        output.textContent = error.message;
        showApiError("POST /tshark-inspect", error);
    }
}

function showApiError(route, error) {
    const box = document.querySelector("#api-error");
    document.querySelector("#api-error-message").textContent = `${route}: ${error.message}`;
    document.querySelector("#api-error-details").textContent = `${apiUrl} — ${locale[language].apiErrorHint}`;
    box.hidden = false;
}

function clearApiError() {
    document.querySelector("#api-error").hidden = true;
}

async function fetchData() {
    const messageCard = document.querySelector(".colspan");

    try {
        const response = await apiFetch("/");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const { message } = await response.json();
        messageCard.textContent = message;
        clearApiError();
    } catch (error) {
        showApiError("GET /", error);
    }
}

async function fetchIp() {
    try {
        const response = await apiFetch("/ip");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        document.querySelector("#user-ip").textContent = data.user_ip || locale[language].unknown;
        document.querySelector("#machine-ip").textContent = data.machine_ip || locale[language].unknown;
        document.querySelector("#public-ip").textContent = data.public_ip || locale[language].unknown;
        clearApiError();
    } catch (error) {
        document.querySelector("#user-ip").textContent = locale[language].unknown;
        document.querySelector("#machine-ip").textContent = locale[language].unknown;
        document.querySelector("#public-ip").textContent = locale[language].unknown;
        showApiError("GET /ip", error);
    }
}

function getBrowserOs() {
    const text = `${navigator.userAgent} ${navigator.platform}`.toLowerCase();

    if (text.includes("mac")) return "mac";
    if (text.includes("win")) return "windows";
    return "linux";
}

async function sendBrowserSignal() {
    try {
        const response = await apiFetch("/browser-action", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                browser_os: getBrowserOs(),
            }),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        const result = document.querySelector("#browser-result");
        const detail = data.output ? ` (${data.output})` : "";
        result.textContent = `${locale[language].browserResult}: ${data.message}${detail}`;
        clearApiError();
    } catch (error) {
        showApiError("POST /browser-action", error);
    }
}

async function runSherlock(event) {
    event.preventDefault();
    const usernameInput = document.querySelector("#sherlock-username");
    const flagsInput = document.querySelector("#sherlock-flags");
    if (!validateInput(usernameInput) || !validateInput(flagsInput)) return;

    const username = usernameInput.value.trim();
    const flags = flagsInput.value.trim();
    const output = document.querySelector("#sherlock-output");
    output.textContent = "Running Sherlock...";

    try {
        const response = await apiFetch("/sherlock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, flags }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);

        output.textContent = data.output || "No results returned.";
        clearApiError();
    } catch (error) {
        output.textContent = "Sherlock could not run.";
        showApiError("POST /sherlock", error);
    }
}

async function runBlackbird(event) {
    event.preventDefault();
    const usernameInput = document.querySelector("#blackbird-username");
    const flagsInput = document.querySelector("#blackbird-flags");
    if (!validateInput(usernameInput) || !validateInput(flagsInput)) return;

    const username = usernameInput.value.trim();
    const flags = flagsInput.value.trim();
    const output = document.querySelector("#blackbird-output");
    output.textContent = "Running Blackbird...";

    try {
        const response = await apiFetch("/blackbird", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, flags }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);

        output.textContent = data.output || "No results returned.";
        clearApiError();
    } catch (error) {
        output.textContent = "Blackbird could not run.";
        showApiError("POST /blackbird", error);
    }
}

async function runNmap(event) {
    event.preventDefault();
    const targetInput = document.querySelector("#nmap-target");
    const flagsInput = document.querySelector("#nmap-flags");
    if (!validateInput(targetInput) || !validateInput(flagsInput)) return;

    const target = targetInput.value.trim();
    const flags = flagsInput.value.trim();
    const authorized = document.querySelector("#security-permission").checked;
    const output = document.querySelector("#nmap-output");
    output.textContent = "Running Nmap...";

    try {
        const response = await apiFetch("/nmap", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target, authorized, flags }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);

        output.textContent = data.output || "No results returned.";
        clearApiError();
    } catch (error) {
        output.textContent = "Nmap could not run.";
        showApiError("POST /nmap", error);
    }
}

async function runSecuritySweep() {
    const targetInput = document.querySelector("#nmap-target");
    const flagsInput = document.querySelector("#nmap-flags");
    if (!validateInput(targetInput) || !validateInput(flagsInput)) return;

    const target = targetInput.value.trim();
    const flags = flagsInput.value.trim();
    const authorized = document.querySelector("#security-permission").checked;
    const output = document.querySelector("#nmap-output");
    output.textContent = "Running security sweep...";

    try {
        const response = await apiFetch("/security-sweep", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target, authorized, flags }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);

        output.textContent = data.output || "No results returned.";
        clearApiError();
    } catch (error) {
        output.textContent = "Security sweep could not run.";
        showApiError("POST /security-sweep", error);
    }
}

async function runPasswordResilience(event) {
    event.preventDefault();
    const passwordInput = document.querySelector("#password-audit");
    if (!validateInput(passwordInput)) return;

    const authorized = document.querySelector("#password-permission").checked;
    const output = document.querySelector("#password-audit-output");
    if (!authorized) {
        output.textContent = locale[language].authorizationRequired;
        return;
    }
    output.textContent = "Evaluating password resilience...";

    try {
        const response = await apiFetch("/password-resilience", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: passwordInput.value, authorized }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);

        const passedChecks = Object.entries(data.checks)
            .filter(([, passed]) => passed)
            .map(([check]) => check)
            .join(", ");
        output.textContent = `${locale[language].resilienceResult}: ${data.rating} (${data.score}/5)\n${passedChecks}`;
        clearApiError();
    } catch (error) {
        output.textContent = error.message;
        showApiError("POST /password-resilience", error);
    }
}

function fileToDataUrl(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(reader.error);
        reader.readAsDataURL(file);
    });
}

async function storeExifImage(input) {
    const output = document.querySelector("#exif-output");
    const file = input.files?.[0];

    if (!validateInput(input)) {
        if (file?.size > maxImageSize) output.textContent = locale[language].imageTooLarge;
        else if (file && !allowedImageTypes.includes(file.type)) output.textContent = locale[language].imageInvalid;
        return;
    }

    try {
        const dataUrl = await fileToDataUrl(file);
        localStorage.setItem(exifStorageKey, JSON.stringify({
            name: file.name,
            type: file.type,
            size: file.size,
            dataUrl,
        }));
        output.textContent = locale[language].imageStored;
    } catch (error) {
        output.textContent = `localStorage: ${error.message}`;
    }
}

async function runExifTool(event) {
    event.preventDefault();
    const input = document.querySelector("#exif-image");
    const output = document.querySelector("#exif-output");
    if (!validateInput(input)) return;

    try {
        await storeExifImage(input);
        const storedImage = JSON.parse(localStorage.getItem(exifStorageKey));
        const blob = await fetch(storedImage.dataUrl).then((response) => response.blob());
        const image = new File([blob], storedImage.name, { type: storedImage.type });
        const formData = new FormData();
        formData.append("image", image);
        output.textContent = "Running ExifTool...";

        const response = await fetch("/api/exif", {
            method: "POST",
            headers: { "X-Privacy-Accepted": "true" },
            body: formData,
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);

        const gpsStatus = data.coordinates.available
            ? locale[language].exifCoordinatesFound
            : locale[language].exifCoordinatesMissing;
        output.textContent = `GPS: ${gpsStatus}\n${JSON.stringify(data, null, 2)}`;
        clearApiError();
    } catch (error) {
        output.textContent = error.message;
        showApiError("POST /api/exif", error);
    }
}

async function runWirelessStatus() {
    const output = document.querySelector("#wireless-output");
    if (!hasAcceptedPrivacy()) {
        output.textContent = locale[language].privacyRequired;
        return;
    }

    output.textContent = "Inspecting wireless adapters...";
    try {
        const response = await apiFetch("/wireless-status", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ accepted_policy: true }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);

        output.textContent = [
            `platform: ${data.platform}`,
            `tool: ${data.tool}`,
            `available: ${data.available}`,
            `monitor_mode_supported: ${data.monitor_mode_supported}`,
            data.note || "",
            "",
            data.output || "No adapters returned.",
        ].filter((line, index, lines) => line || lines[index - 1]).join("\n");
        clearApiError();
    } catch (error) {
        output.textContent = error.message;
        showApiError("POST /wireless-status", error);
    }
}

async function createVlanPlan(event) {
    event.preventDefault();
    const interfaceInput = document.querySelector("#vlan-interface");
    const vlanInput = document.querySelector("#vlan-id");
    const output = document.querySelector("#vlan-output");

    if (!validateInput(interfaceInput) || !validateInput(vlanInput)) return;
    if (!document.querySelector("#vlan-permission").checked) {
        output.textContent = locale[language].authorizationRequired;
        return;
    }

    output.textContent = "Generating VLAN dry-run plan...";
    try {
        const response = await apiFetch("/vlan-plan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                interface: interfaceInput.value.trim(),
                vlan_id: Number(vlanInput.value),
                accepted_policy: true,
                authorized: true,
            }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);

        output.textContent = [
            `platform: ${data.platform}`,
            `mode: ${data.mode}`,
            `supported: ${data.supported}`,
            `interface: ${data.interface}`,
            `vlan_interface: ${data.vlan_interface}`,
            `vlan_id: ${data.vlan_id}`,
            data.note,
            "",
            ...(data.commands.length ? data.commands : ["No commands available for this platform."]),
        ].join("\n");
        clearApiError();
    } catch (error) {
        output.textContent = error.message;
        showApiError("POST /vlan-plan", error);
    }
}

async function viewVlans() {
    const output = document.querySelector("#vlan-inventory-output");
    if (!hasAcceptedPrivacy()) {
        output.textContent = locale[language].privacyRequired;
        return;
    }

    output.textContent = "Inspecting local VLANs...";
    try {
        const response = await apiFetch("/vlan-inventory", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ accepted_policy: true }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);

        output.textContent = [
            `platform: ${data.platform}`,
            `tool: ${data.tool}`,
            `available: ${data.available}`,
            "",
            data.output,
        ].join("\n");
        clearApiError();
    } catch (error) {
        output.textContent = error.message;
        showApiError("POST /vlan-inventory", error);
    }
}

function setLanguage(newLanguage) {
    language = newLanguage;
    document.documentElement.lang = newLanguage === "pt" ? "pt-BR" : "en";

    document.querySelectorAll("[data-i18n]").forEach((element) => {
        const key = element.dataset.i18n;
        const translation = locale[language][key];
        if (translation != null) {
            element.innerHTML = translation;
        }
    });

    document.querySelectorAll("button[data-help-pt]").forEach((button) => {
        button.dataset.help = newLanguage === "pt" ? button.dataset.helpPt : button.dataset.helpEn;
    });

    updatePrivacyState();
    fetchIp();
    sendBrowserSignal();
    renderNmapFlagOptions();
}

window.fetchData = fetchData;
window.setLanguage = setLanguage;
window.sendBrowserSignal = sendBrowserSignal;
window.validateInput = validateInput;
window.updatePrivacyState = updatePrivacyState;
window.openPrivacyGuide = openPrivacyGuide;
window.closePrivacyGuide = closePrivacyGuide;
window.acceptPrivacy = acceptPrivacy;
window.runSherlock = runSherlock;
window.runBlackbird = runBlackbird;
window.runNmap = runNmap;
window.runSecuritySweep = runSecuritySweep;
window.runSqlmap = runSqlmap;
window.runTsharkInspect = runTsharkInspect;
window.runPasswordResilience = runPasswordResilience;
window.storeExifImage = storeExifImage;
window.runExifTool = runExifTool;
window.runWirelessStatus = runWirelessStatus;
window.createVlanPlan = createVlanPlan;
window.viewVlans = viewVlans;

document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !document.querySelector("#privacy-guide").hidden) {
        closePrivacyGuide();
    }
});

document.querySelector("#nmap-flag-chips")?.addEventListener("click", handleNmapFlagClick);
setLanguage(language);
fetchData();

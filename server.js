const http = require("http");
const fs = require("fs");
const path = require("path");
const { formidable } = require("formidable");
const { exiftool } = require("exiftool-vendored");

const host = process.env.FRONTEND_HOST || "127.0.0.1";
const port = Number.parseInt(process.env.FRONTEND_PORT || "3000", 10);
const backendHost = process.env.BACKEND_HOST || "127.0.0.1";
const backendPort = Number.parseInt(process.env.BACKEND_PORT || "8000", 10);

const contentTypes = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
};

const root = path.join(__dirname, "src");
const rootRoutePrefix = `/${path.basename(root)}`;
const indexPath = path.join(root, "index.html");
const zodRoot = path.join(__dirname, "node_modules", "zod");
const allowedImageTypes = new Set(["image/jpeg", "image/png", "image/webp", "image/tiff", "image/heic", "image/heif"]);
const BACKEND_PROXY_PATHS = new Set([
    "/",
    "/ip",
    "/browser-action",
    "/sherlock",
    "/blackbird",
    "/nmap",
    "/security-sweep",
    "/password-resilience",
    "/wireless-status",
    "/vlan-plan",
    "/vlan-inventory",
    "/tshark-inspect",
    "/sqlmap",
    "/login",
    "/auth/login",
    "/auth/login/form",
    "/auth/register",
    "/auth/me",
    "/auth/logout",
    "/ip_win",
    "/ip_linux",
    "/ip_mac",
]);

function isBackendProxyAllowed(pathname) {
    return BACKEND_PROXY_PATHS.has(pathname.split("?")[0]);
}

function readRequestBody(request) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        request.on("data", (chunk) => chunks.push(chunk));
        request.on("end", () => resolve(Buffer.concat(chunks)));
        request.on("error", reject);
    });
}

function proxyBackendRequest(request, response, backendPath) {
    return new Promise(async (resolve) => {
        const body = request.method === "GET" || request.method === "HEAD"
            ? undefined
            : await readRequestBody(request);

        const headers = { ...request.headers, host: `${backendHost}:${backendPort}` };
        headers["x-forwarded-prefix"] = "/api/backend";
        delete headers.connection;
        delete headers["content-length"];

        const proxyRequest = http.request(
            {
                hostname: backendHost,
                port: backendPort,
                method: request.method,
                path: backendPath,
                headers,
            },
            (proxyResponse) => {
                const responseHeaders = { ...proxyResponse.headers };
                delete responseHeaders["transfer-encoding"];
                response.writeHead(proxyResponse.statusCode || 502, responseHeaders);
                proxyResponse.pipe(response);
                proxyResponse.on("end", resolve);
            },
        );

        proxyRequest.on("error", (error) => {
            sendJson(response, 502, { detail: `Backend unavailable: ${error.message}` });
            resolve();
        });

        if (body?.length) {
            proxyRequest.write(body);
        }

        proxyRequest.end();
    });
}

function sendJson(response, statusCode, body) {
    response.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
    });
    response.end(JSON.stringify(body));
}

function normalizeCoordinate(value) {
    const coordinate = typeof value === "number" ? value : Number.parseFloat(value);
    return Number.isFinite(coordinate) ? coordinate : null;
}

function getExifCoordinates(metadata) {
    const latitude = normalizeCoordinate(metadata.GPSLatitude);
    const longitude = normalizeCoordinate(metadata.GPSLongitude);
    const altitude = normalizeCoordinate(metadata.GPSAltitude);
    const available = latitude !== null && longitude !== null;

    return {
        available,
        latitude,
        longitude,
        altitude,
        mapUrl: available
            ? `https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}#map=16/${latitude}/${longitude}`
            : null,
    };
}

async function handleExifUpload(request, response) {
    if (request.headers["x-privacy-accepted"] !== "true") {
        sendJson(response, 403, { detail: "Accept the privacy policy before processing an image." });
        return;
    }

    const form = formidable({
        maxFileSize: 2 * 1024 * 1024,
        maxFiles: 1,
        allowEmptyFiles: false,
    });
    let uploadedFile;

    try {
        const [, files] = await form.parse(request);
        uploadedFile = Array.isArray(files.image) ? files.image[0] : files.image;

        if (!uploadedFile || !allowedImageTypes.has(uploadedFile.mimetype)) {
            sendJson(response, 400, { detail: "Send a JPEG, PNG, WebP, TIFF, HEIC or HEIF image up to 2 MB." });
            return;
        }

        const metadata = await exiftool.read(uploadedFile.filepath);
        [
            "SourceFile",
            "Directory",
            "FileName",
            "FileModifyDate",
            "FileAccessDate",
            "FileInodeChangeDate",
            "FilePermissions",
        ].forEach((field) => delete metadata[field]);
        sendJson(response, 200, {
            filename: uploadedFile.originalFilename,
            coordinates: getExifCoordinates(metadata),
            metadata,
        });
    } catch (error) {
        const statusCode = error.code === 1009 ? 413 : 500;
        const detail = statusCode === 413 ? "The image exceeds the 2 MB limit." : `ExifTool could not process the image: ${error.message}`;
        sendJson(response, statusCode, { detail });
    } finally {
        if (uploadedFile?.filepath) {
            fs.promises.unlink(uploadedFile.filepath).catch(() => {});
        }
    }
}

function getRequestedPath(pathname) {
    if (pathname === "/") {
        return `/${path.basename(indexPath)}`;
    }

    if (pathname === rootRoutePrefix || pathname === `${rootRoutePrefix}/`) {
        return `/${path.basename(indexPath)}`;
    }

    if (pathname.startsWith(`${rootRoutePrefix}/`)) {
        return pathname.slice(rootRoutePrefix.length);
    }

    return pathname;
}

function getCanonicalPath(pathname) {
    if (
        pathname === rootRoutePrefix ||
        pathname === `${rootRoutePrefix}/` ||
        pathname === `${rootRoutePrefix}/index.html`
    ) {
        return "/";
    }

    if (pathname.startsWith(`${rootRoutePrefix}/`)) {
        return pathname.slice(rootRoutePrefix.length);
    }

    return null;
}

function sendFile(request, response, filePath) {
    const isFrontendFile = filePath === root || filePath.startsWith(`${root}${path.sep}`);
    const isZodFile = filePath === zodRoot || filePath.startsWith(`${zodRoot}${path.sep}`);
    if (!isFrontendFile && !isZodFile) {
        response.writeHead(403);
        response.end("Forbidden");
        return;
    }

    fs.stat(filePath, (statError, stats) => {
        if (statError) {
            response.writeHead(statError.code === "ENOENT" ? 404 : 500);
            response.end(statError.code === "ENOENT" ? "Not found" : "Server error");
            return;
        }

        if (stats.isDirectory()) {
            response.writeHead(403, { "X-Content-Type-Options": "nosniff" });
            response.end("Directory browsing is disabled.");
            return;
        }

        fs.readFile(filePath, (error, file) => {
            if (error) {
                response.writeHead(error.code === "ENOENT" ? 404 : 500);
                response.end(error.code === "ENOENT" ? "Not found" : "Server error");
                return;
            }

            const headers = {
                "Content-Type": contentTypes[path.extname(filePath)] || "application/octet-stream",
                "X-Content-Type-Options": "nosniff",
                "Content-Length": file.length,
            };
            response.writeHead(200, headers);
            response.end(request.method === "HEAD" ? undefined : file);
        });
    });
}

http.createServer(async (request, response) => {
    let pathname;

    try {
        pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
    } catch {
        response.writeHead(400);
        response.end("Bad request");
        return;
    }

    if (pathname === "/api/backend" || pathname.startsWith("/api/backend/")) {
        const backendPath = pathname.slice("/api/backend".length) || "/";
        if (!isBackendProxyAllowed(backendPath)) {
            sendJson(response, 403, { detail: "This backend route is not exposed through the frontend proxy." });
            return;
        }
        await proxyBackendRequest(request, response, backendPath);
        return;
    }

    if (request.method === "POST" && pathname === "/api/exif") {
        await handleExifUpload(request, response);
        return;
    }

    if ((request.method === "GET" || request.method === "HEAD") && pathname === "/healthz") {
        response.writeHead(200, {
            "Content-Type": "text/plain; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
            "Content-Length": 3,
        });
        response.end(request.method === "HEAD" ? undefined : "ok\n");
        return;
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
        response.writeHead(405, {
            "Allow": "GET, HEAD, POST",
            "X-Content-Type-Options": "nosniff",
        });
        response.end("Method not allowed");
        return;
    }

    const canonicalPath = getCanonicalPath(pathname);
    if (canonicalPath) {
        response.writeHead(302, { Location: canonicalPath });
        response.end();
        return;
    }

    if (pathname === "/__vendor/zod" || pathname.startsWith("/__vendor/zod/")) {
        const zodPath = pathname.slice("/__vendor/zod".length) || "/index.js";
        const zodFilePath = path.resolve(zodRoot, `.${zodPath}`);
        sendFile(request, response, zodFilePath);
        return;
    }

    const requestedPath = getRequestedPath(pathname);
    const filePath = path.resolve(root, `.${requestedPath}`);

    if (!path.extname(requestedPath) && !fs.existsSync(filePath)) {
        sendFile(request, response, indexPath);
        return;
    }

    sendFile(request, response, filePath);
}).listen(port, host, () => {
    console.log(`Frontend: http://${host}:${port}`);
    console.log(`Serving files from: ${root}`);
    console.log(`Index file: ${indexPath}`);
});

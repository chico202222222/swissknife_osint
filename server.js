const http = require("http");
const fs = require("fs");
const path = require("path");
const { formidable } = require("formidable");
const { exiftool } = require("exiftool-vendored");

const port = 3000;
const ignoredDirectories = new Set([".git", ".venv", "node_modules", "osint", "tools"]);

const contentTypes = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
};

function findFrontendRoot(startDirectory) {
    const queue = [startDirectory];

    while (queue.length > 0) {
        const currentDirectory = queue.shift();
        const entries = fs.readdirSync(currentDirectory, { withFileTypes: true });
        const hasIndex = entries.some((entry) => entry.isFile() && entry.name === "index.html");

        if (hasIndex) {
            return currentDirectory;
        }

        entries.forEach((entry) => {
            if (!entry.isDirectory() || ignoredDirectories.has(entry.name)) return;
            queue.push(path.join(currentDirectory, entry.name));
        });
    }

    throw new Error("Could not find index.html for the frontend.");
}

const root = findFrontendRoot(__dirname);
const rootRoutePrefix = `/${path.basename(root)}`;
const indexPath = path.join(root, "index.html");
const zodRoot = path.join(__dirname, "node_modules", "zod");
const allowedImageTypes = new Set(["image/jpeg", "image/png", "image/webp", "image/tiff", "image/heic", "image/heif"]);

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

function sendFile(response, filePath) {
    const isFrontendFile = filePath === root || filePath.startsWith(`${root}${path.sep}`);
    const isZodFile = filePath === zodRoot || filePath.startsWith(`${zodRoot}${path.sep}`);
    if (!isFrontendFile && !isZodFile) {
        response.writeHead(403);
        response.end("Forbidden");
        return;
    }

    fs.readFile(filePath, (error, file) => {
        if (error) {
            response.writeHead(error.code === "ENOENT" ? 404 : 500);
            response.end(error.code === "ENOENT" ? "Not found" : "Server error");
            return;
        }

        response.writeHead(200, {
            "Content-Type": contentTypes[path.extname(filePath)] || "application/octet-stream",
            "X-Content-Type-Options": "nosniff",
        });
        response.end(file);
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

    if (request.method === "POST" && pathname === "/api/exif") {
        await handleExifUpload(request, response);
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
        sendFile(response, zodFilePath);
        return;
    }

    const requestedPath = getRequestedPath(pathname);
    const filePath = path.resolve(root, `.${requestedPath}`);

    if (!path.extname(requestedPath) && !fs.existsSync(filePath)) {
        sendFile(response, indexPath);
        return;
    }

    sendFile(response, filePath);
}).listen(port, "127.0.0.1", () => {
    console.log(`Frontend: http://127.0.0.1:${port}`);
    console.log(`Serving files from: ${root}`);
    console.log(`Index file: ${indexPath}`);
});

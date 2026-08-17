import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const deployDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.dirname(deployDirectory);
const runtimeDirectory = path.join(deployDirectory, "runtime");
const values = {
    PROJECT_DIR: projectDirectory,
    SERVER_NAME: process.env.SERVER_NAME || "localhost",
    FRONTEND_PORT: process.env.FRONTEND_PORT || "3000",
    HTTP_PORT: process.env.HTTP_PORT || "8080",
    HTTPS_PORT: process.env.HTTPS_PORT || "8443",
    HTTPS_ORIGIN: process.env.HTTPS_ORIGIN || `https://${process.env.SERVER_NAME || "localhost"}:${process.env.HTTPS_PORT || "8443"}`,
    SSL_CERTIFICATE: process.env.SSL_CERTIFICATE || path.join(deployDirectory, "certs", "localhost.crt"),
    SSL_CERTIFICATE_KEY: process.env.SSL_CERTIFICATE_KEY || path.join(deployDirectory, "certs", "localhost.key"),
};

let configuration = fs.readFileSync(path.join(deployDirectory, "nginx-https.conf.template"), "utf8");
for (const [name, value] of Object.entries(values)) {
    configuration = configuration.replaceAll(`\${${name}}`, value);
}

fs.mkdirSync(runtimeDirectory, { recursive: true });
const outputPath = path.join(runtimeDirectory, "nginx-https.conf");
fs.writeFileSync(outputPath, configuration);
console.log(outputPath);

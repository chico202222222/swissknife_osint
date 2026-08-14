#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
certificate_dir="$project_dir/deploy/certs"
certificate="$certificate_dir/localhost.crt"
certificate_key="$certificate_dir/localhost.key"
openssl_bin="${OPENSSL_BIN:-$(command -v openssl)}"

mkdir -p "$certificate_dir"

"$openssl_bin" req \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -sha256 \
    -days 365 \
    -keyout "$certificate_key" \
    -out "$certificate" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$certificate_key"
echo "Certificate: $certificate"
echo "Private key: $certificate_key"

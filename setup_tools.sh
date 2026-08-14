#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"

pip_bin=".venv/bin/pip"
if [[ ! -x ".venv/bin/python" ]]; then
    echo "Missing .venv. Run: python3 -m venv .venv"
    exit 1
fi

mkdir -p tools/nmap/bin osint

if [[ ! -d "osint/sherlock/sherlock_project" ]]; then
    temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT
    curl -L --fail --silent --show-error \
        https://github.com/sherlock-project/sherlock/archive/refs/tags/v0.16.1.tar.gz \
        -o "$temp_dir/sherlock.tar.gz"
    tar -xzf "$temp_dir/sherlock.tar.gz" -C "$temp_dir"
    mv "$temp_dir"/sherlock-0.16.1 osint/sherlock
fi

"$pip_bin" install -e osint/sherlock

if [[ ! -x "tools/nmap/bin/nmap" ]]; then
    nmap_path="$(command -v nmap || true)"

    if [[ -z "$nmap_path" && "$(uname -s)" == "Darwin" && -x "$(command -v brew || true)" ]]; then
        brew install nmap
        nmap_path="$(command -v nmap)"
    fi

    if [[ -z "$nmap_path" && "$(uname -s)" == "Linux" && -x "$(command -v apt-get || true)" ]]; then
        sudo apt-get update
        sudo apt-get install -y nmap
        nmap_path="$(command -v nmap)"
    fi

    if [[ -n "$nmap_path" ]]; then
        cp "$nmap_path" tools/nmap/bin/nmap
        chmod +x tools/nmap/bin/nmap
    else
        echo "Nmap was not found and no supported package manager is available."
        echo "Install Nmap manually, then run this script again."
        exit 1
    fi
fi

echo "Sherlock ready: .venv/bin/sherlock"
echo "Nmap ready: tools/nmap/bin/nmap"

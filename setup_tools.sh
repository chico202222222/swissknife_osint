#!/usr/bin/env bash
set -euo pipefail
echo "Starting"
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"

pip_bin=".venv/bin/pip"
if [[ ! -x ".venv/bin/python" ]]; then
    echo "Missing .venv. Run: python3 -m venv .venv"
    exit 1
fi

mkdir -p tools/nmap/bin tools/tshark/bin osint

if [[ ! -d "osint/sherlock/sherlock_project" ]]; then
    temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT
    curl -L --fail --silent --show-error \
        https://github.com/sherlock-project/sherlock/archive/refs/tags/v0.16.1.tar.gz \
        -o "$temp_dir/sherlock.tar.gz"
    tar -xzf "$temp_dir/sherlock.tar.gz" -C "$temp_dir"
    mv "$temp_dir"/sherlock-0.16.1 osint/sherlock
fi

if [[ ! -f "osint/sqlmap/sqlmap.py" ]]; then
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git osint/sqlmap
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

if [[ ! -x "tools/tshark/bin/tshark" ]]; then
    tshark_path="$(command -v tshark || true)"

    if [[ -z "$tshark_path" && "$(uname -s)" == "Darwin" && -x "$(command -v brew || true)" ]]; then
        brew install wireshark
        tshark_path="$(command -v tshark || true)"
    fi

    if [[ -z "$tshark_path" && "$(uname -s)" == "Linux" && -x "$(command -v apt-get || true)" ]]; then
        sudo apt-get update
        sudo apt-get install -y tshark
        tshark_path="$(command -v tshark || true)"
    fi

    if [[ -n "$tshark_path" ]]; then
        cat > tools/tshark/bin/tshark <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$tshark_path" "\$@"
EOF
        chmod +x tools/tshark/bin/tshark
    else
        echo "TShark was not found and no supported package manager is available."
        echo "Install Wireshark/TShark manually, then run this script again."
        exit 1
    fi
fi

if ! tools/tshark/bin/tshark -v >/dev/null 2>&1; then
    echo "TShark validation failed: tools/tshark/bin/tshark -v"
    exit 1
fi

echo "Sherlock ready: .venv/bin/sherlock"
echo "Nmap ready: tools/nmap/bin/nmap"
echo "TShark ready: tools/tshark/bin/tshark"
echo "SQLMap ready: osint/sqlmap/sqlmap.py"

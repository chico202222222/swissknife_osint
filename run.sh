#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"

if [[ ! -x ".venv/bin/uvicorn" ]]; then
    echo "Missing .venv/bin/uvicorn. Create the venv and install requirements first."
    exit 1
fi

api_pid=""
frontend_pid=""
frontend_port="${FRONTEND_PORT:-3000}"

if curl -fsS "http://127.0.0.1:8000/" >/dev/null 2>&1; then
    echo "FastAPI is already running on http://127.0.0.1:8000"
else
    ".venv/bin/uvicorn" api.main:app --host 127.0.0.1 --port 8000 --reload &
    api_pid=$!
    sleep 1

    if ! kill -0 "$api_pid" 2>/dev/null; then
        echo "Could not start FastAPI on http://127.0.0.1:8000."
        echo "Check whether another process is using port 8000: lsof -nP -iTCP:8000 -sTCP:LISTEN"
        exit 1
    fi
fi

if curl -fsS "http://127.0.0.1:${frontend_port}/healthz" >/dev/null 2>&1; then
    echo "Frontend is already running on http://127.0.0.1:${frontend_port}"
else
    FRONTEND_PORT="$frontend_port" node server.js &
    frontend_pid=$!
    sleep 1

    if ! kill -0 "$frontend_pid" 2>/dev/null; then
        echo "Could not start the frontend on http://127.0.0.1:${frontend_port}."
        echo "Check whether another process is using port ${frontend_port}: lsof -nP -iTCP:${frontend_port} -sTCP:LISTEN"
        exit 1
    fi
fi

cleanup() {
    [[ -n "$api_pid" ]] && kill "$api_pid" 2>/dev/null || true
    [[ -n "$frontend_pid" ]] && kill "$frontend_pid" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

echo "FastAPI: http://127.0.0.1:8000"
echo "Frontend: http://127.0.0.1:${frontend_port}"

if [[ -n "$frontend_pid" ]]; then
    wait "$frontend_pid"
elif [[ -n "$api_pid" ]]; then
    wait "$api_pid"
fi

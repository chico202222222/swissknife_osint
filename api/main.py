import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
from contextlib import asynccontextmanager
from uuid import uuid4
from random import randint
from pathlib import Path
from typing import Literal
from urllib.request import urlopen

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel

from .auth import router as auth_router, seed_demo_user
from .database import init_db

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    seed_demo_user()
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "dev-local-session-key-change-in-prod"),
    https_only=False,
    same_site="lax",
)

app.include_router(auth_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "http://127.0.0.1:3001",
        "http://localhost:3001",
    ],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def visitor_cookie_middleware(request: Request, call_next):
    visitor_id = request.cookies.get("visitor_id")
    request.state.visitor_id = visitor_id or uuid4().hex

    response = await call_next(request)
    if not visitor_id:
        secure_cookie = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        response.set_cookie(
            key="visitor_id",
            value=request.state.visitor_id,
            max_age=60 * 60 * 24 * 30,
            httponly=True,
            samesite="lax",
            secure=secure_cookie,
        )

    return response


class BrowserSignal(BaseModel):
    browser_os: Literal["mac", "windows", "linux"]


class SherlockRequest(BaseModel):
    username: str
    flags: str = ""


class BlackbirdRequest(BaseModel):
    username: str
    flags: str = ""


class NmapRequest(BaseModel):
    target: str
    authorized: bool = False
    flags: str = ""


class SecuritySweepRequest(BaseModel):
    target: str
    authorized: bool
    flags: str = ""


class PasswordAuditRequest(BaseModel):
    password: str
    authorized: bool = False


class WirelessStatusRequest(BaseModel):
    accepted_policy: bool = False


class VlanPlanRequest(BaseModel):
    interface: str
    vlan_id: int
    accepted_policy: bool = False
    authorized: bool = False


class TsharkInspectRequest(BaseModel):
    profile: Literal["http", "tls"]
    port: int
    accepted_policy: bool = False
    authorized: bool = False
    flags: str = ""


class SqlmapRequest(BaseModel):
    target: str
    accepted_policy: bool = False
    authorized: bool = False
    flags: str = ""


# Lab port allowlist — re-enable when done testing other local services (e.g. local AI uvicorn):
# ALLOWED_TSHARK_PORTS = {3000, 8000, 8080, 8443}
TSHARK_CAPTURE_SECONDS = 3
TSHARK_MAX_PACKETS = 40
MAX_FLAG_LENGTH = 240
MAX_FLAG_TOKENS = 16
INVALID_FLAG_TOKEN = re.compile(r"[\r\n\0;|`$()<>]")
MAX_FLAG_TOKEN_LENGTH = 120
BLOCKED_FLAGS = {
    "nmap": {"-i", "-e", "-o", "-oA", "-oN", "-oX", "--datadir", "--resume", "--iflist"},
    "blackbird": {"--username", "-u", "--help", "-h"},
    "tshark": {"-i", "-w", "-W", "-F", "-b", "-P"},
    "sherlock": set(),
    "sqlmap": set(),
}
SQLMAP_TIMEOUT_SECONDS = 300


def get_data():
    return randint(1, 100)


def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3)
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def normalize_process_output(output):
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output


def get_process_output(result):
    return normalize_process_output(result.stdout) + normalize_process_output(result.stderr)


def parse_extra_flags(raw: str, tool: str):
    flags = raw.strip()
    if not flags:
        return []

    if len(flags) > MAX_FLAG_LENGTH:
        raise HTTPException(status_code=400, detail="Flags are too long.")

    try:
        tokens = shlex.split(flags)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=f"Invalid flags syntax: {error}") from error

    if len(tokens) > MAX_FLAG_TOKENS:
        raise HTTPException(status_code=400, detail="Too many flag tokens.")

    blocked = BLOCKED_FLAGS[tool]
    for token in tokens:
        if not token or len(token) > MAX_FLAG_TOKEN_LENGTH or INVALID_FLAG_TOKEN.search(token):
            raise HTTPException(status_code=400, detail=f"Unsupported flag token: {token}")
        base = token.split("=", 1)[0]
        if token in blocked or base in blocked:
            raise HTTPException(status_code=400, detail=f"Flag not allowed for {tool}: {token}")

    return tokens


def find_tool(name):
    local_tools = {
        "nmap": PROJECT_ROOT / "tools" / "nmap" / "bin" / "nmap",
        "sherlock": PROJECT_ROOT / ".venv" / "bin" / "sherlock",
        "blackbird": PROJECT_ROOT / "osint" / "blackbird" / "blackbird.py",
        "sqlmap": PROJECT_ROOT / "osint" / "sqlmap" / "sqlmap.py",
    }
    local_path = local_tools[name]

    if local_path.is_file():
        if name in {"blackbird", "sqlmap"}:
            return [sys.executable, str(local_path)], local_path.parent
        return [str(local_path)], None

    if name == "sherlock" and (PROJECT_ROOT / "osint" / "sherlock").is_dir():
        return [sys.executable, "-m", "sherlock_project"], PROJECT_ROOT / "osint" / "sherlock"

    system_path = shutil.which(name)
    return ([system_path], None) if system_path else (None, None)


def get_machine_ip():
    machine_ip = run_command(["ipconfig", "getifaddr", "en0"])

    if not machine_ip:
        machine_ip = run_command(["ipconfig", "getifaddr", "en1"])

    if not machine_ip:
        machine_ip = run_command(["hostname", "-I"]).split(" ")[0]

    return machine_ip


def get_public_ip():
    try:
        with urlopen("https://api.ipify.org?format=json", timeout=3) as response:
            data = json.loads(response.read().decode())
            return data["ip"]
    except Exception:
        return ""


def run_browser_function(browser_os):
    if browser_os == "windows":
        return run_command(["hostname"])

    return run_command(["uname", "-s"])


def get_wireless_status():
    system = platform.system().lower()

    if system == "linux":
        command = shutil.which("airmon-ng")
        if not command:
            return {
                "platform": "linux",
                "tool": "airmon-ng",
                "available": False,
                "monitor_mode_supported": True,
                "output": "airmon-ng was not found. Install the aircrack-ng package.",
            }
        result = subprocess.run([command], capture_output=True, text=True, timeout=10)
        return {
            "platform": "linux",
            "tool": "airmon-ng",
            "available": True,
            "monitor_mode_supported": True,
            "output": get_process_output(result).strip(),
        }

    if system == "darwin":
        command = shutil.which("networksetup") or "/usr/sbin/networksetup"
        result = subprocess.run([command, "-listallhardwareports"], capture_output=True, text=True, timeout=10)
        return {
            "platform": "macos",
            "tool": "networksetup",
            "available": result.returncode == 0,
            "monitor_mode_supported": False,
            "output": get_process_output(result).strip(),
            "note": "airmon-ng is not provided on macOS; this is a read-only adapter inventory.",
        }

    if system == "windows":
        command = shutil.which("netsh") or "netsh"
        result = subprocess.run([command, "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=10)
        return {
            "platform": "windows",
            "tool": "netsh wlan",
            "available": result.returncode == 0,
            "monitor_mode_supported": False,
            "output": get_process_output(result).strip(),
            "note": "airmon-ng is not native to Windows; this is a read-only WLAN inventory.",
        }

    return {
        "platform": system or "unknown",
        "tool": "none",
        "available": False,
        "monitor_mode_supported": False,
        "output": "This operating system is not supported.",
    }


def get_vlan_plan(interface, vlan_id):
    system = platform.system().lower()
    vlan_interface = f"{interface}.{vlan_id}"

    if system == "linux":
        commands = [
            ["ip", "link", "add", "link", interface, "name", vlan_interface, "type", "vlan", "id", str(vlan_id)],
            ["ip", "link", "set", vlan_interface, "up"],
        ]
        return {
            "platform": "linux",
            "supported": shutil.which("ip") is not None,
            "mode": "dry-run",
            "interface": interface,
            "vlan_interface": vlan_interface,
            "vlan_id": vlan_id,
            "commands": [" ".join(command) for command in commands],
            "note": "Plan only: no command was executed. Airmon-ng does not configure VLANs; Linux iproute2 does.",
        }

    note = (
        "macOS VLANs must be configured with networksetup or System Settings on a compatible Ethernet interface."
        if system == "darwin"
        else "Windows VLAN support depends on the network adapter driver and its PowerShell/vendor configuration."
    )
    return {
        "platform": "macos" if system == "darwin" else system or "unknown",
        "supported": False,
        "mode": "dry-run",
        "interface": interface,
        "vlan_interface": vlan_interface,
        "vlan_id": vlan_id,
        "commands": [],
        "note": note,
    }


def get_vlan_inventory():
    system = platform.system().lower()

    if system == "linux":
        command = shutil.which("ip")
        if not command:
            return {"platform": "linux", "tool": "iproute2", "available": False, "output": "The ip command was not found."}
        result = subprocess.run(
            [command, "-d", "link", "show", "type", "vlan"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = get_process_output(result).strip()
        return {
            "platform": "linux",
            "tool": "ip -d link show type vlan",
            "available": result.returncode == 0,
            "output": output or "No VLAN interfaces are currently configured.",
        }

    if system == "darwin":
        command = shutil.which("networksetup") or "/usr/sbin/networksetup"
        result = subprocess.run([command, "-listVLANs"], capture_output=True, text=True, timeout=10)
        return {
            "platform": "macos",
            "tool": "networksetup -listVLANs",
            "available": result.returncode == 0,
            "output": get_process_output(result).strip() or "No VLANs returned.",
        }

    if system == "windows":
        command = shutil.which("powershell") or shutil.which("pwsh")
        if not command:
            return {"platform": "windows", "tool": "PowerShell", "available": False, "output": "PowerShell was not found."}
        script = "Get-NetAdapterAdvancedProperty | Where-Object {$_.DisplayName -match 'VLAN'} | Format-Table Name,DisplayName,DisplayValue -AutoSize"
        result = subprocess.run([command, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=10)
        return {
            "platform": "windows",
            "tool": "Get-NetAdapterAdvancedProperty",
            "available": result.returncode == 0,
            "output": get_process_output(result).strip() or "No VLAN properties are currently exposed by the adapters.",
        }

    return {"platform": system or "unknown", "tool": "none", "available": False, "output": "This operating system is not supported."}


def password_resilience(password):
    checks = {
        "length_12_or_more": len(password) >= 12,
        "lowercase": any(character.islower() for character in password),
        "uppercase": any(character.isupper() for character in password),
        "number": any(character.isdigit() for character in password),
        "symbol": any(not character.isalnum() for character in password),
    }
    score = sum(checks.values())
    rating = ("weak", "weak", "fair", "good", "strong", "strong")[score]
    return {"score": score, "rating": rating, "checks": checks}


def get_loopback_interface():
    return "lo0" if platform.system().lower() == "darwin" else "lo"


def trigger_local_traffic(profile, port):
    curl = shutil.which("curl")
    if not curl:
        return

    if profile == "tls":
        subprocess.Popen(
            [curl, "-k", "-s", "--max-time", "2", f"https://127.0.0.1:{port}/healthz"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return

    subprocess.Popen(
        [curl, "-s", "--max-time", "2", f"http://127.0.0.1:{port}/healthz"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_tshark_inspect(profile, port, extra_flags=None):
    tshark = shutil.which("tshark")
    if not tshark:
        raise HTTPException(status_code=503, detail="tshark is not installed or is not in PATH.")

    interface = get_loopback_interface()
    display_filter = "http" if profile == "http" else "tls"
    command = [
        tshark,
        "-i",
        interface,
        "-f",
        f"tcp port {port}",
        "-a",
        f"duration:{TSHARK_CAPTURE_SECONDS}",
        "-c",
        str(TSHARK_MAX_PACKETS),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=|",
        "-e",
        "frame.number",
        "-e",
        "frame.time_relative",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
    ]

    if profile == "http":
        command.extend(["-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri", "-e", "http.response.code"])
    else:
        command.extend(["-e", "tls.handshake.type", "-e", "tls.handshake.extensions_server_name", "-e", "tls.record.version"])

    if extra_flags:
        command.extend(extra_flags)

    trigger_local_traffic(profile, port)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=TSHARK_CAPTURE_SECONDS + 10,
        )
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or "") + (error.stderr or "")
        formatted, rendered = format_command_output(command, output + "\nCapture timed out.", 124)
        return {
            "profile": profile,
            "port": port,
            "interface": interface,
            "command": rendered,
            "output": formatted,
            "exit_code": 124,
        }

    output = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if not output and stderr:
        output = stderr

    body = output or "No packets matched the filter. Confirm the local service is running on this port."
    formatted, rendered = format_command_output(command, body, result.returncode)

    return {
        "profile": profile,
        "port": port,
        "interface": interface,
        "command": rendered,
        "output": formatted,
        "exit_code": result.returncode,
        "note": "Loopback-only capture. Use TLS on port 8443 to inspect NGINX HTTPS handshakes.",
    }


@app.get("/")
def home():
    return {"message": get_data()}


@app.get("/ip")
def get_ip(request: Request):
    return {
        "user_ip": request.client.host,
        "machine_ip": get_machine_ip(),
        "public_ip": get_public_ip(),
    }


@app.post("/browser-action")
def browser_action(signal: BrowserSignal):
    output = run_browser_function(signal.browser_os)

    return {
        "browser_os": signal.browser_os,
        "message": f"{signal.browser_os} function executed",
        "output": output,
    }


def format_command_output(command, output, exit_code):
    rendered = " ".join(shlex.quote(part) for part in command)
    body = output.strip() or "(no output)"
    return f"$ {rendered}\n\n{body}", rendered


@app.post("/sherlock")
def run_sherlock(request: SherlockRequest):
    username = request.username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,50}", username):
        raise HTTPException(status_code=400, detail="Use 1 to 50 letters, numbers, dots, underscores or hyphens.")

    command, working_directory = find_tool("sherlock")
    if not command:
        raise HTTPException(status_code=503, detail="Sherlock is not installed or is not in PATH.")

    extra_flags = parse_extra_flags(request.flags, "sherlock")
    full_command = command + [username, "--print-found", "--timeout", "10", "--no-color", "--verbose"] + extra_flags

    try:
        result = subprocess.run(
            full_command,
            cwd=working_directory,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as error:
        output = normalize_process_output(error.stdout) + normalize_process_output(error.stderr)
        formatted, rendered = format_command_output(full_command, output + "\nScan timed out after 120 seconds.", 124)
        return {"username": username, "command": rendered, "output": formatted, "exit_code": 124}

    output = get_process_output(result)
    formatted, rendered = format_command_output(full_command, output, result.returncode)
    return {"username": username, "command": rendered, "output": formatted, "exit_code": result.returncode}


@app.post("/blackbird")
def run_blackbird(request: BlackbirdRequest):
    username = request.username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,50}", username):
        raise HTTPException(status_code=400, detail="Use 1 to 50 letters, numbers, dots, underscores or hyphens.")

    command, working_directory = find_tool("blackbird")
    if not command:
        raise HTTPException(status_code=503, detail="Blackbird is not installed or is not in PATH.")

    extra_flags = parse_extra_flags(request.flags, "blackbird")
    full_command = command + ["--username", username, "--timeout", "3", "--max-concurrent-requests", "60", "--no-nsfw", "--no-update", "-v"] + extra_flags

    try:
        result = subprocess.run(
            full_command,
            cwd=working_directory,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as error:
        output = normalize_process_output(error.stdout) + normalize_process_output(error.stderr)
        formatted, rendered = format_command_output(full_command, output + "\nScan timed out after 120 seconds.", 124)
        return {"username": username, "command": rendered, "output": formatted, "exit_code": 124}

    output = get_process_output(result)
    formatted, rendered = format_command_output(full_command, output, result.returncode)
    return {"username": username, "command": rendered, "output": formatted, "exit_code": result.returncode}


@app.post("/sqlmap")
def run_sqlmap(request: SqlmapRequest):
    if not request.accepted_policy:
        raise HTTPException(status_code=403, detail="Accept the privacy policy before running SQLMap.")
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Confirm authorization before running SQLMap.")

    target = request.target.strip()
    if not re.fullmatch(r"https?://[^\s]+", target):
        raise HTTPException(status_code=400, detail="Use a valid http or https URL.")

    command, working_directory = find_tool("sqlmap")
    if not command:
        raise HTTPException(
            status_code=503,
            detail="SQLMap is not installed. Run setup_tools.sh to clone osint/sqlmap.",
        )

    extra_flags = parse_extra_flags(request.flags, "sqlmap")
    full_command = command + ["-u", target, "--batch", "-v"] + extra_flags

    try:
        result = subprocess.run(
            full_command,
            cwd=working_directory,
            capture_output=True,
            text=True,
            timeout=SQLMAP_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        output = normalize_process_output(error.stdout) + normalize_process_output(error.stderr)
        formatted, rendered = format_command_output(
            full_command,
            output + f"\nSQLMap timed out after {SQLMAP_TIMEOUT_SECONDS} seconds.",
            124,
        )
        return {"target": target, "command": rendered, "output": formatted, "exit_code": 124}

    output = get_process_output(result)
    formatted, rendered = format_command_output(full_command, output, result.returncode)
    return {"target": target, "command": rendered, "output": formatted, "exit_code": result.returncode}


@app.post("/password-resilience")
def check_password_resilience(request: PasswordAuditRequest):
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Confirm that you are authorized to assess this test password.")
    if not 8 <= len(request.password) <= 128:
        raise HTTPException(status_code=400, detail="Use a test password with 8 to 128 characters.")

    return password_resilience(request.password)


@app.post("/wireless-status")
def wireless_status(request: WirelessStatusRequest):
    if not request.accepted_policy:
        raise HTTPException(status_code=403, detail="Accept the privacy policy before inspecting wireless adapters.")
    return get_wireless_status()


@app.post("/vlan-plan")
def vlan_plan(request: VlanPlanRequest):
    if not request.accepted_policy:
        raise HTTPException(status_code=403, detail="Accept the privacy policy before creating a VLAN plan.")
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Confirm authorization before creating a VLAN plan.")

    interface = request.interface.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface):
        raise HTTPException(status_code=400, detail="Use a valid local interface name with up to 32 characters.")
    if not 1 <= request.vlan_id <= 4094:
        raise HTTPException(status_code=400, detail="VLAN ID must be between 1 and 4094.")

    return get_vlan_plan(interface, request.vlan_id)


@app.post("/vlan-inventory")
def vlan_inventory(request: WirelessStatusRequest):
    if not request.accepted_policy:
        raise HTTPException(status_code=403, detail="Accept the privacy policy before viewing local VLANs.")
    return get_vlan_inventory()


@app.post("/tshark-inspect")
def tshark_inspect(request: TsharkInspectRequest):
    if not request.accepted_policy:
        raise HTTPException(status_code=403, detail="Accept the privacy policy before capturing packets.")
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Confirm authorization before capturing local traffic.")
    # if request.port not in ALLOWED_TSHARK_PORTS:
    #     raise HTTPException(status_code=400, detail="Use a local lab port: 3000, 8000, 8080 or 8443.")
    if not (1 <= request.port <= 65535):
        raise HTTPException(status_code=400, detail="Use a valid TCP port between 1 and 65535.")
    if request.profile not in {"http", "tls"}:
        raise HTTPException(status_code=400, detail="Use profile http or tls.")

    return run_tshark_inspect(request.profile, request.port, parse_extra_flags(request.flags, "tshark"))


@app.post("/nmap")
def run_nmap(request: NmapRequest):
    target = request.target.strip()

    if not request.authorized:
        raise HTTPException(status_code=403, detail="Confirm that you have permission to scan this target.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,252}", target):
        raise HTTPException(status_code=400, detail="Use a valid IP, hostname or CIDR target.")

    command, working_directory = find_tool("nmap")
    if not command:
        raise HTTPException(status_code=503, detail="Nmap is not installed or is not in PATH.")

    extra_flags = parse_extra_flags(request.flags, "nmap")
    full_command = command + ["-Pn", "-T3", "-v", "--top-ports", "100"] + extra_flags + [target]

    try:
        result = subprocess.run(
            full_command,
            cwd=working_directory,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as error:
        output = normalize_process_output(error.stdout) + normalize_process_output(error.stderr)
        formatted, rendered = format_command_output(full_command, output + "\nScan timed out after 120 seconds.", 124)
        return {"target": target, "command": rendered, "output": formatted, "exit_code": 124}

    output = get_process_output(result)
    formatted, rendered = format_command_output(full_command, output, result.returncode)
    return {"target": target, "command": rendered, "output": formatted, "exit_code": result.returncode}


@app.post("/security-sweep")
def security_sweep(request: SecuritySweepRequest):
    target = request.target.strip()

    if not request.authorized:
        raise HTTPException(status_code=403, detail="Confirm that you have permission to scan this target.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,252}", target):
        raise HTTPException(status_code=400, detail="Use a valid IP, hostname or CIDR target.")

    command, working_directory = find_tool("nmap")
    if not command:
        raise HTTPException(status_code=503, detail="Nmap is not installed or is not in PATH.")

    extra_flags = parse_extra_flags(request.flags, "nmap")
    full_command = command + ["-Pn", "-T3", "-v", "-sV", "--script", "safe", "--top-ports", "100"] + extra_flags + [target]

    try:
        result = subprocess.run(
            full_command,
            cwd=working_directory,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as error:
        output = normalize_process_output(error.stdout) + normalize_process_output(error.stderr)
        formatted, rendered = format_command_output(full_command, output + "\nSecurity sweep timed out after 120 seconds.", 124)
        return {"target": target, "command": rendered, "output": formatted, "exit_code": 124}

    output = get_process_output(result)
    formatted, rendered = format_command_output(full_command, output, result.returncode)
    return {"target": target, "command": rendered, "output": formatted, "exit_code": result.returncode}


@app.get("/ip_win")
def get_ip_shell():
    return {"browser_os": "windows", "output": run_browser_function("windows")}


@app.get("/ip_linux")
def get_ip_linux():
    return {"browser_os": "linux", "output": run_browser_function("linux")}


@app.get("/ip_mac")
def get_ip_mac():
    return {"browser_os": "mac", "output": run_browser_function("mac")}

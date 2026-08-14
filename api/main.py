import json
import platform
import re
import shutil
import subprocess
import sys
from uuid import uuid4
from random import randint
from pathlib import Path
from typing import Literal
from urllib.request import urlopen

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel

app = FastAPI()
PROJECT_ROOT = Path(__file__).resolve().parent.parent

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost"],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "http://localhost:3000"],
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


class BlackbirdRequest(BaseModel):
    username: str


class NmapRequest(BaseModel):
    target: str
    authorized: bool = False


class SecuritySweepRequest(BaseModel):
    target: str
    authorized: bool


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


def find_tool(name):
    local_tools = {
        "nmap": PROJECT_ROOT / "tools" / "nmap" / "bin" / "nmap",
        "sherlock": PROJECT_ROOT / ".venv" / "bin" / "sherlock",
        "blackbird": PROJECT_ROOT / "osint" / "blackbird" / "blackbird.py",
    }
    local_path = local_tools[name]

    if local_path.is_file():
        if name == "blackbird":
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


@app.post("/sherlock")
def run_sherlock(request: SherlockRequest):
    username = request.username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,50}", username):
        raise HTTPException(status_code=400, detail="Use 1 to 50 letters, numbers, dots, underscores or hyphens.")

    command, working_directory = find_tool("sherlock")
    if not command:
        raise HTTPException(status_code=503, detail="Sherlock is not installed or is not in PATH.")

    try:
        result = subprocess.run(
            command + [username, "--print-found", "--timeout", "10", "--no-color"],
            cwd=working_directory,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as error:
        output = normalize_process_output(error.stdout) + normalize_process_output(error.stderr)
        return {"username": username, "output": output + "\nScan timed out after 120 seconds.", "exit_code": 124}

    output = get_process_output(result)
    return {"username": username, "output": output, "exit_code": result.returncode}


@app.post("/blackbird")
def run_blackbird(request: BlackbirdRequest):
    username = request.username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,50}", username):
        raise HTTPException(status_code=400, detail="Use 1 to 50 letters, numbers, dots, underscores or hyphens.")

    command, working_directory = find_tool("blackbird")
    if not command:
        raise HTTPException(status_code=503, detail="Blackbird is not installed or is not in PATH.")

    try:
        result = subprocess.run(
            command + ["--username", username, "--timeout", "3", "--max-concurrent-requests", "60", "--no-nsfw", "--no-update"],
            cwd=working_directory,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as error:
        output = normalize_process_output(error.stdout) + normalize_process_output(error.stderr)
        return {"username": username, "output": output + "\nScan timed out after 120 seconds.", "exit_code": 124}

    output = get_process_output(result)
    return {"username": username, "output": output, "exit_code": result.returncode}


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

    try:
        result = subprocess.run(
            command + ["-Pn", "-T3", "--top-ports", "100", target],
            cwd=working_directory,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as error:
        output = normalize_process_output(error.stdout) + normalize_process_output(error.stderr)
        return {"target": target, "output": output + "\nScan timed out after 120 seconds.", "exit_code": 124}

    output = get_process_output(result)
    return {"target": target, "output": output, "exit_code": result.returncode}


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

    try:
        result = subprocess.run(
            command + ["-Pn", "-T3", "-sV", "--script", "safe", "--top-ports", "100", target],
            cwd=working_directory,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as error:
        output = normalize_process_output(error.stdout) + normalize_process_output(error.stderr)
        return {"target": target, "output": output + "\nSecurity sweep timed out after 120 seconds.", "exit_code": 124}

    output = get_process_output(result)
    return {"target": target, "output": output, "exit_code": result.returncode}


@app.get("/ip_win")
def get_ip_shell():
    return {"browser_os": "windows", "output": run_browser_function("windows")}


@app.get("/ip_linux")
def get_ip_linux():
    return {"browser_os": "linux", "output": run_browser_function("linux")}


@app.get("/ip_mac")
def get_ip_mac():
    return {"browser_os": "mac", "output": run_browser_function("mac")}

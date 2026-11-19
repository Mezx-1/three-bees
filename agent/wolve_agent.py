"""WOLVE endpoint agent.

What it monitors (only after the device user consents with --consent):
  * network connections: which program talks to which remote IP/port, direction (in/out), state
  * new processes: name, path and parent — full command lines ONLY for script hosts / LOLBins
    (powershell, cmd, wscript, mshta, …) where attackers live; other command lines can hold
    personal data and are not collected
  * security posture (read-only): Windows Firewall profiles, Microsoft Defender status, listening ports

What it never does: capture packet contents, screens, keystrokes, browsing history, files,
passwords or phone calls. Response actions (blocking an IP in Windows Firewall) run only when the
agent was started with --allow-response; otherwise they are refused and reported back.

Usage:
  python wolve_agent.py --server http://localhost:8000 --pair ABCD2345 --consent
  python wolve_agent.py --monitor                       # run with the saved enrolment
  python wolve_agent.py --monitor --allow-response      # also allow firewall block/unblock commands
  python wolve_agent.py --simulate-demo                 # send the labelled demo attack events
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "0.2.0"
STATE = Path(__file__).with_name(".wolve_agent.json")
IS_WINDOWS = os.name == "nt"
WATCHED_CMDLINE = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                   "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "schtasks.exe", "wmic.exe", "bash", "sh", "python.exe"}
FW_RULE_PREFIX = "WOLVE-block-"

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover
    psutil = None


def log(msg: str) -> None:
    print(f"[wolve-agent {time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ------------------------------------------------------------------ transport

class Server:
    def __init__(self, url: str, token: str | None = None, user: str | None = None):
        self.url, self.token, self.user = url.rstrip("/"), token, user

    def call(self, path: str, body=None, method: str = "POST", fatal: bool = False):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Device-Token"] = self.token
        if self.user:
            headers["X-WOLVE-User"] = self.user
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            msg = f"{path} failed ({e.code}): {e.read().decode(errors='replace')[:300]}"
        except urllib.error.URLError as e:
            msg = f"cannot reach {self.url}: {e.reason}"
        if fatal:
            sys.exit("[wolve-agent] " + msg)
        log(msg)
        return None


# ------------------------------------------------------------------ collectors

def local_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # UDP connect sends no packet; just selects the outbound interface
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def system_info() -> dict:
    info = {"platform": platform.platform(), "machine": platform.machine(), "python": platform.python_version(),
            "cpu_count": os.cpu_count(), "agent": f"wolve-agent/{VERSION}",
            "collection": "connections, new processes, security posture (no content)"}
    if psutil:
        info["boot_time"] = int(psutil.boot_time())
        info["memory_gb"] = round(psutil.virtual_memory().total / 1e9, 1)
    return info


def _proc_info(pid: int, cache: dict) -> dict:
    if pid in cache:
        return cache[pid]
    out = {"pid": pid, "name": None, "exe": None}
    try:
        p = psutil.Process(pid)
        out["name"] = p.name()
        try:
            out["exe"] = p.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass
    except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
        pass
    cache[pid] = out
    return out


def collect_connections() -> tuple[list[dict], list[dict]]:
    """Returns (connections, listening). Loopback and closed sockets are skipped."""
    conns: dict[tuple, dict] = {}
    listening: dict[tuple, dict] = {}
    cache: dict = {}
    raw = psutil.net_connections(kind="inet")
    listen_ports = {c.laddr.port for c in raw if c.status == psutil.CONN_LISTEN and c.laddr}
    for c in raw:
        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        if c.status == psutil.CONN_LISTEN and c.laddr:
            p = _proc_info(c.pid, cache) if c.pid else {"name": None}
            key = (proto, c.laddr.port)
            listening[key] = {"protocol": proto, "port": c.laddr.port, "address": c.laddr.ip, "process_name": p.get("name"), "pid": c.pid}
            continue
        if not c.raddr or not c.pid:
            continue
        if c.status in (psutil.CONN_TIME_WAIT, psutil.CONN_CLOSE, "NONE") and proto == "tcp":
            continue
        rip = c.raddr.ip
        try:
            ipobj = ipaddress.ip_address(rip.split("%")[0])
            if ipobj.is_loopback or ipobj.is_unspecified or ipobj.is_multicast:
                continue
        except ValueError:
            continue
        p = _proc_info(c.pid, cache)
        direction = "inbound" if c.laddr and c.laddr.port in listen_ports else "outbound"
        key = (p.get("name"), rip, c.raddr.port, direction, c.laddr.port if direction == "inbound" else 0)
        conns[key] = {"process_name": p.get("name"), "pid": c.pid, "exe": p.get("exe"), "protocol": proto,
                      "local_ip": c.laddr.ip if c.laddr else None, "local_port": c.laddr.port if c.laddr else None,
                      "remote_ip": rip, "remote_port": c.raddr.port, "status": str(c.status), "direction": direction}
    return list(conns.values())[:600], list(listening.values())[:200]


class ProcessWatcher:
    def __init__(self):
        self.known = set(psutil.pids())

    def new_processes(self) -> list[dict]:
        now = set(psutil.pids())
        fresh = now - self.known
        self.known = now
        events = []
        for pid in list(fresh)[:50]:
            try:
                p = psutil.Process(pid)
                name = p.name()
                parent = p.parent().name() if p.parent() else None
                try:
                    exe = p.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    exe = None
                details = {"process_name": name.lower(), "parent_process": (parent or "").lower(), "path": exe, "pid": pid}
                if name.lower() in WATCHED_CMDLINE:
                    try:
                        details["command_line"] = " ".join(p.cmdline())[:1000]
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                events.append({"event_type": "process", "title": f"Process started: {name}" + (f" (parent {parent})" if parent else ""), "details": details})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return events


def _exec(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    """Run a fixed command (argument list, never a shell). Returns (exit code, output)."""
    try:
        flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=flags, shell=False)
        return out.returncode, (out.stdout or "") + (out.stderr or "")
    except Exception as exc:
        return -1, f"ERROR {exc.__class__.__name__}: {exc}"


def _run(cmd: list[str], timeout: int = 20) -> str:
    return _exec(cmd, timeout)[1]


def is_admin() -> bool:
    if not IS_WINDOWS:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _ps_json(script: str, timeout: int = 30):
    """Run a fixed, read-only PowerShell query and parse its JSON output (locale-independent)."""
    rc, out = _exec(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout)
    if rc != 0 or not out.strip():
        return None, out.strip()[:300]
    try:
        start = min(i for i in (out.find("{"), out.find("[")) if i != -1)
        return json.loads(out[start:]), ""
    except Exception:
        return None, out.strip()[:300]


def collect_posture() -> dict:
    posture: dict = {"collected_at": int(time.time()), "os": f"{platform.system()} {platform.release()} ({platform.version()})"}
    if not IS_WINDOWS:
        posture["note"] = "Firewall/Defender checks are implemented for Windows only."
        return posture
    # Get-NetFirewallProfile returns structured data, so this works on Arabic/English/any-language Windows.
    fw, err = _ps_json("Get-NetFirewallProfile | Select-Object Name,@{n='Enabled';e={[bool]$_.Enabled}} | ConvertTo-Json")
    if fw is not None:
        rows = fw if isinstance(fw, list) else [fw]
        posture["firewall"] = {str(r.get("Name", "?")).lower(): ("on" if r.get("Enabled") else "off") for r in rows}
    else:
        posture["firewall"] = {"error": "Could not read Windows Firewall state" + (f": {err}" if err else "")}
    d, err = _ps_json("Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
                      "AntivirusSignatureAge,QuickScanAge | ConvertTo-Json")
    if isinstance(d, dict):
        posture["defender"] = {"service": d.get("AMServiceEnabled"), "antivirus": d.get("AntivirusEnabled"),
                               "realtime": d.get("RealTimeProtectionEnabled"), "signature_age_days": d.get("AntivirusSignatureAge"),
                               "last_quick_scan_days": d.get("QuickScanAge")}
    else:
        posture["defender"] = {"error": "Defender status unavailable (another antivirus is active, Defender is not installed, or permission was denied)"}
    posture["agent_is_admin"] = is_admin()
    return posture


# ------------------------------------------------------------------ response actions

def list_wolve_rules() -> tuple[list[dict] | None, str]:
    """Read-only: only rules whose name starts with the WOLVE prefix."""
    data, err = _ps_json(f"Get-NetFirewallRule -DisplayName '{FW_RULE_PREFIX}*' -ErrorAction SilentlyContinue | "
                         "Select-Object DisplayName,@{n='Direction';e={[string]$_.Direction}},@{n='Action';e={[string]$_.Action}},"
                         "@{n='Enabled';e={[string]$_.Enabled}} | ConvertTo-Json")
    if data is None:
        return ([] if not err else None), err
    rows = data if isinstance(data, list) else [data]
    return [{"name": r.get("DisplayName"), "direction": r.get("Direction"), "action": r.get("Action"), "enabled": r.get("Enabled")} for r in rows], ""


def _rule_exists(name: str, direction: str) -> bool:
    rc, _ = _exec(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}", f"dir={direction}"])
    return rc == 0


def validate_block_target(ip: str) -> str | None:
    """Returns an error message if the address must not be blocked."""
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return f"Invalid IP '{ip}'"
    if o.is_loopback or o.is_unspecified or o.is_multicast or o.is_link_local or o.is_reserved:
        return f"Refusing to block special-purpose address {ip}."
    if o.is_private:
        return f"Refusing to block private/local address {ip}: it could cut this device off from its own network or the WOLVE server."
    return None


def execute(cmd: dict, allow: bool) -> tuple[str, str]:
    """Run a response command from the server. Only touches firewall rules named WOLVE-block-<ip>."""
    ctype, params = cmd.get("type"), cmd.get("params") or {}
    if ctype == "list_rules":  # read-only, allowed without --allow-response
        if not IS_WINDOWS:
            return "failed", "Firewall inspection is implemented for Windows only."
        rules, err = list_wolve_rules()
        if rules is None:
            return "failed", f"Could not read firewall rules: {err}"
        return "done", json.dumps(rules)
    if ctype not in ("block_ip", "unblock_ip"):
        return "failed", f"Unknown command '{ctype}'"
    if not allow:
        return "refused", "Agent was not started with --allow-response; no change made on the device."
    if not IS_WINDOWS:
        return "failed", "Firewall actions are implemented for Windows only."
    if not is_admin():
        return "refused", "Agent is not running as administrator, so it cannot change Windows Firewall. No change made."
    ip = str(params.get("ip", ""))
    problem = validate_block_target(ip)
    if problem:
        return "refused", problem
    name = FW_RULE_PREFIX + ip
    if ctype == "block_ip":
        created = []
        for d in ("out", "in"):
            if _rule_exists(name, d):
                continue  # duplicate handling: never add the same rule twice
            rc, out = _exec(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={d}", "action=block", f"remoteip={ip}"])
            if rc != 0:
                for done_dir in created:  # roll back so no half-applied block is left behind
                    _exec(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}", f"dir={done_dir}"])
                return "failed", f"Could not create the {d}bound rule (exit {rc}): {out.strip()[:300]}. No WOLVE rule left in place."
            created.append(d)
        if not created:
            return "done", f"{ip} was already blocked by WOLVE rules (inbound and outbound); nothing changed."
        return "done", f"Blocked {ip} in Windows Firewall ({' + '.join(x + 'bound' for x in created)}), rule name '{name}'."
    # unblock
    if not (_rule_exists(name, "in") or _rule_exists(name, "out")):
        return "done", f"No WOLVE rule exists for {ip}; nothing to remove."
    rc, out = _exec(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
    return ("done", f"Removed WOLVE firewall rule '{name}'.") if rc == 0 else ("failed", f"Could not remove rule (exit {rc}): {out.strip()[:300]}")


# ------------------------------------------------------------------ main loop

def monitor(srv: Server, interval: int, allow_response: bool) -> None:
    if psutil is None:
        sys.exit("[wolve-agent] psutil is required: pip install psutil")
    watcher = ProcessWatcher()
    last_posture = 0.0
    if allow_response and not is_admin():
        log("WARNING: --allow-response given but the agent is not running as administrator; firewall commands will be refused.")
    log(f"monitoring every {interval}s · response actions {'ENABLED' if allow_response else 'disabled'} · Ctrl+C to stop")
    while True:
        try:
            srv.call("/api/agent/heartbeat", system_info())
            try:
                conns, listening = collect_connections()
                collection_error = None
            except (psutil.AccessDenied, PermissionError) as exc:
                conns, listening = [], []
                collection_error = f"Permission denied reading network connections ({exc.__class__.__name__}); run the agent as administrator."
                log(collection_error)
            res = srv.call("/api/agent/connections", {"connections": conns, "listening": listening, "collection_error": collection_error})
            if res:
                flagged = res.get("flagged", 0)
                log(f"{len(conns)} connections, {len(listening)} listening ports · {res.get('new', 0)} new · {flagged} flagged")
            procs = watcher.new_processes()
            if procs:
                srv.call("/api/agent/events", procs)
            if time.time() - last_posture > 300:
                srv.call("/api/agent/posture", collect_posture())
                last_posture = time.time()
            for cmd in (srv.call("/api/agent/commands", method="GET") or {}).get("commands", []):
                status, result = execute(cmd, allow_response)
                log(f"command {cmd['id']} {cmd['type']} → {status}: {result}")
                srv.call(f"/api/agent/commands/{cmd['id']}/result", {"status": status, "result": result})
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # keep the agent alive on transient errors
            log(f"cycle error: {exc}")
        time.sleep(interval)


def main() -> None:
    ap = argparse.ArgumentParser(description="WOLVE endpoint agent")
    ap.add_argument("--server", default=None, help="WOLVE server URL (default: saved, else http://localhost:8000)")
    ap.add_argument("--pair", metavar="CODE", help="One-time pairing code from WOLVE → Settings → Pair a device")
    ap.add_argument("--owner", help="Device owner email", default=None)
    ap.add_argument("--consent", action="store_true", help="Confirm the device user consents to WOLVE monitoring")
    ap.add_argument("--monitor", action="store_true", help="Continuously monitor connections, processes and posture")
    ap.add_argument("--interval", type=int, default=10)
    ap.add_argument("--allow-response", action="store_true", help="Allow analysts to block/unblock IPs in Windows Firewall")
    ap.add_argument("--simulate-demo", action="store_true", help="Send the labelled, SIMULATED demo attack events")
    a = ap.parse_args()

    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    server = a.server or state.get("server") or "http://localhost:8000"
    if a.pair:
        if not a.consent:
            sys.exit("[wolve-agent] Refusing to enrol: pass --consent to confirm the device user agreed to monitoring.")
        res = Server(server).call("/api/agent/register", {
            "pairing_code": a.pair,
            "hostname": socket.gethostname(), "os": f"{platform.system()} {platform.release()}",
            "owner_email": a.owner or f"{getpass.getuser()}@local", "ip_address": local_ip(),
            "agent_version": VERSION, "system_info": system_info(), "consent": True,
        }, fatal=True)
        state = {"server": server, "device_id": res["device_id"], "token": res["token"]}
        STATE.write_text(json.dumps(state))
        log(f"enrolled as {res['device_id']} (token saved to {STATE.name})")
    if not state.get("token"):
        sys.exit("[wolve-agent] not enrolled — run with --pair <CODE> --consent first (code: WOLVE → Settings → Pair a device)")
    srv = Server(server, token=state["token"])

    if a.simulate_demo:
        events = [
            {"event_type": "process", "title": "SIMULATED: wscript.exe executed Invoice_Q4_2026.pdf.js",
             "details": {"simulated": True, "process_name": "wscript.exe", "parent_process": "outlook.exe",
                         "command_line": "wscript.exe C:\\Users\\demo\\Downloads\\Invoice_Q4_2026.pdf.js", "file_name": "Invoice_Q4_2026.pdf.js"}},
            {"event_type": "network_connection", "title": "SIMULATED: outbound to verify.alnoor-logistics-portal.top",
             "details": {"simulated": True, "process_name": "wscript.exe", "dest_ip": "203.0.113.45",
                         "dest_domain": "verify.alnoor-logistics-portal.top", "dest_port": 8081}},
        ]
        log("demo events: " + json.dumps(srv.call("/api/agent/events", events)))
    if a.monitor:
        try:
            monitor(srv, max(3, a.interval), a.allow_response)
        except KeyboardInterrupt:
            log("stopped")
    elif not a.pair and not a.simulate_demo:
        log("heartbeat: " + json.dumps(srv.call("/api/agent/heartbeat", system_info())))


if __name__ == "__main__":
    main()

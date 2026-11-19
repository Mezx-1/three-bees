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
  python wolve_agent.py --server http://localhost:8000 --enrol-as aisha.admin --consent
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


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=flags)
        return (out.stdout or "") + (out.stderr or "")
    except Exception as exc:
        return f"ERROR {exc}"


def collect_posture() -> dict:
    posture: dict = {"collected_at": int(time.time()), "os": f"{platform.system()} {platform.release()} ({platform.version()})"}
    if not IS_WINDOWS:
        posture["note"] = "Firewall/Defender checks are implemented for Windows only."
        return posture
    fw = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    profiles = {}
    current = None
    for line in fw.splitlines():
        m = re.match(r"^(Domain|Private|Public) Profile Settings", line.strip())
        if m:
            current = m.group(1).lower()
        elif current and line.strip().lower().startswith("state"):
            profiles[current] = "on" if "on" in line.lower().split()[-1] else "off"
    posture["firewall"] = profiles or {"error": "could not read firewall state"}
    ps = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
               "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,QuickScanAge | ConvertTo-Json"], timeout=30)
    try:
        d = json.loads(ps[ps.index("{"):ps.rindex("}") + 1])
        posture["defender"] = {"service": d.get("AMServiceEnabled"), "antivirus": d.get("AntivirusEnabled"),
                               "realtime": d.get("RealTimeProtectionEnabled"), "signature_age_days": d.get("AntivirusSignatureAge"),
                               "last_quick_scan_days": d.get("QuickScanAge")}
    except Exception:
        posture["defender"] = {"error": "Defender status unavailable (third-party antivirus or no permission)"}
    return posture


# ------------------------------------------------------------------ response actions

def execute(cmd: dict, allow: bool) -> tuple[str, str]:
    ctype, params = cmd.get("type"), cmd.get("params") or {}
    if not allow:
        return "refused", "Agent was not started with --allow-response; no change made on the device."
    if not IS_WINDOWS:
        return "failed", "Firewall actions are implemented for Windows only."
    ip = str(params.get("ip", ""))
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "failed", f"Invalid IP '{ip}'"
    name = FW_RULE_PREFIX + ip
    if ctype == "block_ip":
        outs = [_run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={d}", "action=block", f"remoteip={ip}"]) for d in ("out", "in")]
        ok = all("Ok." in o for o in outs)
        return ("done" if ok else "failed"), ("Blocked in Windows Firewall (in+out)." if ok else " | ".join(o.strip() for o in outs)[:500])
    if ctype == "unblock_ip":
        out = _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
        ok = "Ok." in out or "Deleted" in out
        return ("done" if ok else "failed"), ("Firewall rule removed." if ok else out.strip()[:500])
    return "failed", f"Unknown command '{ctype}'"


# ------------------------------------------------------------------ main loop

def monitor(srv: Server, interval: int, allow_response: bool) -> None:
    if psutil is None:
        sys.exit("[wolve-agent] psutil is required: pip install psutil")
    watcher = ProcessWatcher()
    last_posture = 0.0
    log(f"monitoring every {interval}s · response actions {'ENABLED' if allow_response else 'disabled'} · Ctrl+C to stop")
    while True:
        try:
            srv.call("/api/agent/heartbeat", system_info())
            conns, listening = collect_connections()
            res = srv.call("/api/agent/connections", {"connections": conns, "listening": listening})
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
    ap.add_argument("--enrol-as", help="WOLVE admin username authorising enrolment")
    ap.add_argument("--owner", help="Device owner email", default=None)
    ap.add_argument("--consent", action="store_true", help="Confirm the device user consents to WOLVE monitoring")
    ap.add_argument("--monitor", action="store_true", help="Continuously monitor connections, processes and posture")
    ap.add_argument("--interval", type=int, default=10)
    ap.add_argument("--allow-response", action="store_true", help="Allow analysts to block/unblock IPs in Windows Firewall")
    ap.add_argument("--simulate-demo", action="store_true", help="Send the labelled, SIMULATED demo attack events")
    a = ap.parse_args()

    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    server = a.server or state.get("server") or "http://localhost:8000"
    if a.enrol_as:
        if not a.consent:
            sys.exit("[wolve-agent] Refusing to enrol: pass --consent to confirm the device user agreed to monitoring.")
        res = Server(server, user=a.enrol_as).call("/api/agent/register", {
            "hostname": socket.gethostname(), "os": f"{platform.system()} {platform.release()}",
            "owner_email": a.owner or f"{getpass.getuser()}@local", "ip_address": local_ip(),
            "agent_version": VERSION, "system_info": system_info(), "consent": True,
        }, fatal=True)
        state = {"server": server, "device_id": res["device_id"], "token": res["token"]}
        STATE.write_text(json.dumps(state))
        log(f"enrolled as {res['device_id']} (token saved to {STATE.name})")
    if not state.get("token"):
        sys.exit("[wolve-agent] not enrolled — run with --enrol-as <admin> --consent first")
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
    elif not a.enrol_as and not a.simulate_demo:
        log("heartbeat: " + json.dumps(srv.call("/api/agent/heartbeat", system_info())))


if __name__ == "__main__":
    main()

"""WOLVE AI endpoint agent — prototype.

Consent-first and minimal by design:
  * refuses to run without --consent (the device user must agree)
  * sends only: hostname, OS, platform info, and heartbeats
  * NEVER records screens, keystrokes, calls, browsing, files or passwords
  * --simulate-demo sends the labelled demo events (marked simulated=True)

Future Windows agent (see docs/ARCHITECTURE.md): ETW/Sysmon process + network telemetry,
signed service, tamper protection, local policy and offline queue.

Usage:
  python wolve_agent.py --server http://localhost:8000 --enrol-as aisha.admin --consent
  python wolve_agent.py --server http://localhost:8000 --enrol-as aisha.admin --consent --simulate-demo
  python wolve_agent.py --server http://localhost:8000 --watch            # heartbeat loop with saved token
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "0.1.0"
STATE = Path(__file__).with_name(".wolve_agent.json")


def call(server: str, path: str, body, headers: dict) -> dict:
    req = urllib.request.Request(server.rstrip("/") + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        sys.exit(f"[wolve-agent] {path} failed ({e.code}): {detail}")
    except urllib.error.URLError as e:
        sys.exit(f"[wolve-agent] cannot reach {server}: {e.reason}")


def local_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # documentation address: no packet is actually sent for UDP connect
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def system_info() -> dict:
    return {"platform": platform.platform(), "machine": platform.machine(), "python": platform.python_version(),
            "cpu_count": os.cpu_count(), "agent": f"wolve-agent/{VERSION}", "collection": "heartbeat+system-info only"}


def main() -> None:
    ap = argparse.ArgumentParser(description="WOLVE AI endpoint agent (prototype)")
    ap.add_argument("--server", default="http://localhost:8000")
    ap.add_argument("--enrol-as", help="WOLVE admin username authorising enrolment")
    ap.add_argument("--owner", help="Device owner email", default=None)
    ap.add_argument("--consent", action="store_true", help="Confirm the device user consents to WOLVE monitoring")
    ap.add_argument("--simulate-demo", action="store_true", help="Send the labelled, SIMULATED demo attack events")
    ap.add_argument("--watch", action="store_true", help="Keep sending heartbeats every 30 s")
    a = ap.parse_args()

    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    if a.enrol_as:
        if not a.consent:
            sys.exit("[wolve-agent] Refusing to enrol: pass --consent to confirm the device user agreed to monitoring.")
        res = call(a.server, "/api/agent/register", {
            "hostname": socket.gethostname(), "os": f"{platform.system()} {platform.release()}",
            "owner_email": a.owner or f"{getpass.getuser()}@local", "ip_address": local_ip(),
            "agent_version": VERSION, "system_info": system_info(), "consent": True,
        }, {"X-WOLVE-User": a.enrol_as})
        state = {"server": a.server, "device_id": res["device_id"], "token": res["token"]}
        STATE.write_text(json.dumps(state))
        print(f"[wolve-agent] enrolled as {res['device_id']} (token saved to {STATE.name})")
    if not state.get("token"):
        sys.exit("[wolve-agent] not enrolled — run with --enrol-as <admin> --consent first")

    hdr = {"X-Device-Token": state["token"]}
    print("[wolve-agent] heartbeat:", call(a.server, "/api/agent/heartbeat", system_info(), hdr))

    if a.simulate_demo:
        events = [
            {"event_type": "process", "title": "SIMULATED: wscript.exe executed Invoice_Q4_2026.pdf.js",
             "details": {"simulated": True, "process_name": "wscript.exe", "parent_process": "outlook.exe",
                         "command_line": "wscript.exe C:\\Users\\demo\\Downloads\\Invoice_Q4_2026.pdf.js", "file_name": "Invoice_Q4_2026.pdf.js"}},
            {"event_type": "network_connection", "title": "SIMULATED: outbound to verify.alnoor-logistics-portal.top",
             "details": {"simulated": True, "process_name": "wscript.exe", "dest_ip": "203.0.113.45",
                         "dest_domain": "verify.alnoor-logistics-portal.top", "dest_port": 8081}},
        ]
        print("[wolve-agent] demo events:", json.dumps(call(a.server, "/api/agent/events", events, hdr), indent=2))

    while a.watch:
        time.sleep(30)
        call(a.server, "/api/agent/heartbeat", system_info(), hdr)
        print("[wolve-agent] heartbeat sent")


if __name__ == "__main__":
    main()

# 3B — safe, repeatable demonstration

Everything below is either **real** (live data from this laptop) or **simulated**, which is labelled in the UI and stored with `simulated=true`. No malware, no real attacks, no firewall changes.

| # | Step | Real or simulated | How |
|---|---|---|---|
| 0 | Start 3B | — | `.\start.ps1` (backend :8000, web :3000). The interface opens in Arabic. |
| 1 | Start the endpoint agent manually | **Real** | `backend\.venv\Scripts\python agent\threeb_agent.py --server http://localhost:8000 --enrol-as aisha.admin --consent`, then `... --monitor` |
| 2 | Endpoint registered | **Real** | Endpoint Protection → the laptop appears with a green "live" badge |
| 3 | Real connection metadata | **Real** | Laptop → *Live connections*: program, direction, remote address, port |
| 4 | Approximate location of public IPs | **Real**, opt-in | Settings → as admin, switch on *External lookups* and accept the consent dialog. The map and countries fill in, labelled "approximate". |
| 5 | Controlled suspicious event | **Simulated** | Command Center → *Demo attack scenario*, steps 1–3 (phishing email, quarantine, simulated endpoint events), or *Inject simulated event* on a device |
| 6 | Correlated incident | Real correlation of simulated data | The incident shows "correlated" and its timeline explains the shared hash/domain |
| 7 | Command Center updates | — | Status becomes "Critical — action needed"; counters and recommendations update |
| 8 | Arabic report | — | Open the analysis → *Report* downloads an Arabic, right-to-left HTML report |
| 9 | Response recommendations | — | Incident page → *Recommended response*; Block on a public IP queues a firewall command that is **refused** unless the agent runs as administrator with `--allow-response` |
| 10 | Scam call | Real analysis of a generated sample | Call Guard → *Recorded call* → upload `backend/app/demo/sample_scam_call.wav`, number `+882 1234 5678` |
| 11 | Phone protection | Simulation of the phone app (real analysis) | Phone Protection → *Receive message* (Salik example → Junk), *Simulate incoming call* (warning before answering) |

Reset: Settings → *Reset demo environment* (as admin).

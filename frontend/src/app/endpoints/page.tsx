"use client";

import { Cpu, HeartPulse, Laptop, Plus, ShieldOff, Terminal, Zap } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { broadcastRefresh, Button, Card, cn, EmptyState, ErrorBox, fmtTime, inputCls, Label, PageHeader, Pill, ScanBar, SeverityBadge, SimBadge, StatusDot, timeAgo, useApi, useToast } from "@/components/ui";
import { apiGet, apiSend } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import type { Device, EndpointEvent } from "@/lib/types";

const PRESETS = [
  { key: "office_ps", label: "Word spawns encoded PowerShell", event_type: "process", title: "powershell.exe launched by WINWORD.EXE",
    details: { process_name: "powershell.exe", parent_process: "winword.exe", command_line: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" } },
  { key: "c2", label: "Script host connects out on port 4444", event_type: "network_connection", title: "wscript.exe outbound to 203.0.113.99:4444",
    details: { process_name: "wscript.exe", dest_ip: "203.0.113.99", dest_port: 4444, protocol: "tcp" } },
  { key: "brute", label: "7 failed logins", event_type: "login", title: "Repeated failed logins for local account", details: { result: "failure", attempts: 7, account: "administrator" } },
  { key: "benign", label: "Benign: Teams update", event_type: "process", title: "Teams.exe updated", details: { process_name: "teams.exe", parent_process: "explorer.exe", path: "C:\\Program Files\\Microsoft\\Teams\\Teams.exe" } },
];

const SOURCE_LABEL: Record<string, React.ReactNode> = {
  agent: <Pill className="text-safe">WOLVE agent</Pill>, simulated: <SimBadge label="Simulated device" />, manual: <Pill>Manual entry</Pill>,
};

export default function Endpoints() {
  const { t } = useI18n();
  const toast = useToast();
  const devices = useApi<Device[]>(() => apiGet("/api/endpoints"), [], 10000);
  const [sel, setSel] = useState<string | null>(null);
  const detail = useApi<Device & { events: EndpointEvent[] }>(() => (sel ? apiGet(`/api/endpoints/${sel}`) : Promise.resolve(null as any)), [sel], 10000);
  const [busy, setBusy] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ hostname: "", os: "Windows 11", owner_email: "", ip_address: "" });
  const [formErr, setFormErr] = useState<string | null>(null);

  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get("device");
    if (q) setSel(q);
  }, []);
  useEffect(() => {
    if (!sel && devices.data?.length) setSel(devices.data[0].id);
  }, [devices.data, sel]);

  const act = async (k: string, fn: () => Promise<any>) => {
    setBusy(k);
    try {
      await fn();
      devices.reload(true);
      detail.reload(true);
      broadcastRefresh();
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };

  const addDevice = () => {
    if (!form.hostname.trim()) return setFormErr("Hostname is required.");
    if (form.owner_email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(form.owner_email)) return setFormErr("Owner email is not valid.");
    setFormErr(null);
    act("add", async () => {
      const d = await apiSend("/api/endpoints", "POST", { ...form, owner_email: form.owner_email || null, ip_address: form.ip_address || null });
      toast("ok", `Device ${d.hostname} added to inventory (manual entry — no agent reporting yet).`);
      setShowAdd(false);
      setForm({ hostname: "", os: "Windows 11", owner_email: "", ip_address: "" });
      setSel(d.id);
    });
  };

  const d = detail.data;
  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_endpoints")} subtitle="Device inventory, endpoint telemetry ingestion and endpoint risk" icon={Cpu}
        actions={<Button onClick={() => setShowAdd(!showAdd)}><Plus className="h-4 w-4" /> Register device</Button>} />

      <div className="rounded-lg border border-violet-400/30 bg-violet-500/5 px-3 py-2 text-xs text-violet-200">
        Seeded devices are <b>simulated inventory</b> for the demo. Real devices appear only when the consent-based WOLVE agent registers. WOLVE does not record screens, calls, keystrokes or passwords.
      </div>

      {showAdd && (
        <Card title="Register device (inventory)">
          <div className="grid gap-3 md:grid-cols-4">
            {(["hostname", "os", "owner_email", "ip_address"] as const).map((k) => (
              <div key={k}><Label htmlFor={k}>{k.replace("_", " ")}</Label><input id={k} className={inputCls} value={form[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} /></div>
            ))}
          </div>
          {formErr && <div className="mt-2"><ErrorBox error={formErr} /></div>}
          <div className="mt-3 flex gap-2"><Button variant="primary" loading={busy === "add"} onClick={addDevice}>Save</Button><Button variant="ghost" onClick={() => setShowAdd(false)}>Cancel</Button></div>
        </Card>
      )}

      <div className="grid gap-5 xl:grid-cols-[1fr_1.3fr]">
        <Card title="Device inventory">
          {devices.error ? <ErrorBox error={devices.error} /> : !devices.data ? <ScanBar /> : devices.data.length === 0 ? <EmptyState title="No devices" icon={Laptop} /> : (
            <ul className="space-y-2">
              {devices.data.map((dv) => (
                <li key={dv.id}>
                  <button onClick={() => setSel(dv.id)} className={cn("w-full rounded-lg border p-3 text-start transition", sel === dv.id ? "border-volt/50 bg-volt/5" : "border-ink-700 bg-ink-850/60 hover:border-ink-500")}>
                    <div className="flex flex-wrap items-center gap-2">
                      <Laptop className="h-4 w-4 text-ink-400" /><span className="font-mono text-sm font-semibold text-ink-100">{dv.hostname}</span>
                      <StatusDot s={dv.status} />
                      <span className="ms-auto font-mono text-xs text-ink-300">risk {dv.risk_score}</span>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-ink-400">
                      {SOURCE_LABEL[dv.source]}<span>{dv.os}</span><span>· {dv.owner_email || "no owner"}</span><span>· seen {timeAgo(dv.last_seen)}</span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <div className="space-y-4">
          {!d ? <Card><p className="text-sm text-ink-400">Select a device.</p></Card> : (
            <>
              <Card title={<span className="font-mono">{d.hostname}</span>} subtitle={`${d.os} · ${d.ip_address || "no IP"} · agent ${d.agent_version}`}
                action={<div className="flex flex-wrap gap-2">
                  <Button variant="danger" className="text-xs" loading={busy === "iso"} disabled={d.status === "isolation_recommended"} onClick={() => act("iso", async () => { const r = await apiSend(`/api/endpoints/${d.id}/recommend-isolation`, "POST"); toast("ok", r.message); })}><ShieldOff className="h-4 w-4" /> Recommend isolation</Button>
                  <Button className="text-xs" loading={busy === "ok"} onClick={() => act("ok", async () => { await apiSend(`/api/endpoints/${d.id}/mark-healthy`, "POST"); toast("ok", `${d.hostname} marked healthy.`); })}><HeartPulse className="h-4 w-4" /> Mark healthy</Button>
                </div>}>
                <div className="flex flex-wrap items-center gap-3 text-sm"><StatusDot s={d.status} /><span className="text-ink-300">Risk <b className="font-mono">{d.risk_score}</b>/100</span>{SOURCE_LABEL[d.source]}<span className="text-xs text-ink-400">Owner: {d.owner_email || "—"}</span></div>
                {d.status === "isolation_recommended" && <p className="mt-2 text-xs text-high">Isolation recommended. WOLVE does not control the network in the MVP — isolate via EDR/NAC.</p>}
                <div className="mt-4">
                  <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-ink-400"><Zap className="h-3.5 w-3.5 text-violet-300" /> Inject simulated event</div>
                  <div className="flex flex-wrap gap-2">
                    {PRESETS.map((p) => (
                      <Button key={p.key} className="text-xs" loading={busy === p.key} onClick={() => act(p.key, async () => {
                        const r = await apiSend(`/api/endpoints/${d.id}/events/simulate`, "POST", { event_type: p.event_type, title: p.title, details: p.details });
                        toast(r.event.risk_score >= 60 ? "err" : "ok", `Simulated event scored ${r.event.risk_score}/100${r.correlation.incident_id ? ` → incident ${r.correlation.incident_id}` : ""}.`);
                      })}>{p.label}</Button>
                    ))}
                  </div>
                </div>
              </Card>
              <Card title={`Event timeline (${d.events.length})`}>
                {d.events.length === 0 ? <EmptyState title="No events from this device" icon={Terminal}>Events arrive from the WOLVE agent, or inject a simulated event above.</EmptyState> : (
                  <ul className="space-y-2">
                    {d.events.map((e) => (
                      <li key={e.id} className="rounded-lg border border-ink-700 bg-ink-850/60 p-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <SeverityBadge s={e.severity} />{e.simulated && <SimBadge />}<Pill>{e.event_type}</Pill>
                          <span className="text-sm text-ink-100">{e.title}</span>
                          <span className="ms-auto text-[11px] text-ink-400">{fmtTime(e.created_at)}</span>
                        </div>
                        {e.findings.length > 0 && <ul className="mt-1.5 list-disc ps-5 text-xs text-ink-300">{e.findings.map((f, i) => <li key={i}>{f.title}{f.evidence ? <span className="font-mono text-ink-400"> — {f.evidence}</span> : null}</li>)}</ul>}
                        <details className="mt-1 text-[11px] text-ink-400"><summary className="cursor-pointer">Raw telemetry</summary><pre className="mt-1 overflow-x-auto rounded bg-ink-950/70 p-2 font-mono">{JSON.stringify(e.details, null, 2)}</pre></details>
                        {e.incident_id && <p className="mt-1 text-xs">→ <Link className="text-volt hover:underline" href={`/incidents/${e.incident_id}`}>Incident {e.incident_id}</Link></p>}
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            </>
          )}
        </div>
      </div>

      <Card title={<span className="flex items-center gap-2"><Terminal className="h-4 w-4 text-volt" /> Real WOLVE endpoint agent (prototype)</span>}
        subtitle="Consent-based. Sends heartbeat + system info, and only the security events you enable. Never runs hidden.">
        <pre className="overflow-x-auto rounded-lg bg-ink-950/80 p-3 font-mono text-xs text-ink-200">{`cd agent
python wolve_agent.py --server http://localhost:8000 --enrol-as aisha.admin --consent
# optional: send the labelled demo events from this machine
python wolve_agent.py --server http://localhost:8000 --enrol-as aisha.admin --consent --simulate-demo`}</pre>
      </Card>
    </div>
  );
}

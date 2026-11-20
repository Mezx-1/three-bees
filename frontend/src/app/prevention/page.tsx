"use client";

import { Ban, CheckCircle2, ScrollText, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { useState } from "react";
import { broadcastRefresh, Button, Card, EmptyState, ErrorBox, fmtTime, inputCls, Label, PageHeader, Pill, ScanBar, SimBadge, Tabs, useApi, useToast } from "@/components/ui";
import { apiGet, apiSend } from "@/lib/api";
import { useI18n, tr } from "@/lib/i18n";

type T = "indicators" | "blocklist" | "actions" | "audit";

export default function Prevention() {
  const { t } = useI18n();
  const toast = useToast();
  const [tab, setTab] = useState<T>("indicators");
  const [onlyMal, setOnlyMal] = useState(true);
  const inds = useApi<any[]>(() => apiGet(`/api/indicators${onlyMal ? "?malicious=true" : ""}`), [onlyMal]);
  const bl = useApi<any[]>(() => apiGet("/api/blocklist"), []);
  const actions = useApi<any[]>(() => apiGet("/api/actions"), [], 15000);
  const audit = useApi<any[]>(() => apiGet("/api/audit"), [], 15000);
  const [form, setForm] = useState({ type: "domain", value: "", reason: "" });
  const [busy, setBusy] = useState<string | null>(null);

  const act = async (k: string, fn: () => Promise<any>) => {
    setBusy(k);
    try {
      await fn();
      inds.reload(true); bl.reload(true); actions.reload(true); audit.reload(true);
      broadcastRefresh();
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };

  const block = (type: string, value: string, reason = "") => act(`b-${value}`, async () => { const r = await apiSend("/api/blocklist", "POST", { type, value, reason }); toast("ok", r.message); });

  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_prevention")} subtitle={tr("Block indicators, review IOCs and audit every response action")} icon={ShieldCheck} />
      <div className="rounded-lg border border-ink-700 bg-ink-900/70 px-3 py-2 text-xs text-ink-300">
        {tr("Blocking is enforced inside 3B: future analyses and endpoint telemetry matching a blocked indicator are flagged critical. To block an IP on a real laptop, use Block on its live connections (Endpoint Protection). Blocklist entries are not pushed to a network firewall, proxy or mail gateway.")}
      </div>
      <Tabs value={tab} onChange={setTab} items={[
        { value: "indicators", label: tr("Indicators (IOCs)") }, { value: "blocklist", label: `${tr("Blocklist")}${bl.data ? ` (${bl.data.length})` : ""}` },
        { value: "actions", label: tr("Response actions") }, { value: "audit", label: tr("Audit log") }]} />

      {tab === "indicators" && (
        <Card title={tr("Observed indicators")} action={<label className="flex items-center gap-2 text-xs text-ink-300"><input type="checkbox" checked={onlyMal} onChange={(e) => setOnlyMal(e.target.checked)} /> {tr("Malicious only")}</label>}>
          {inds.error ? <ErrorBox error={inds.error} /> : !inds.data ? <ScanBar /> : inds.data.length === 0 ? <EmptyState title={tr("No indicators")} /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-xs font-medium text-ink-400"><tr><th className="py-2 pe-3 text-start">{tr("Type")}</th><th className="pe-3 text-start">{tr("Value")}</th><th className="pe-3 text-start">{tr("Sightings")}</th><th className="pe-3 text-start">{tr("State")}</th><th className="text-end">{tr("Actions")}</th></tr></thead>
                <tbody className="divide-y divide-ink-800">
                  {inds.data.map((i) => (
                    <tr key={`${i.type}:${i.value}`}>
                      <td className="py-2 pe-3"><Pill>{i.type}</Pill></td>
                      <td className="max-w-[420px] truncate pe-3 font-mono text-xs" title={i.value}>{i.value}</td>
                      <td className="pe-3 font-mono text-xs">{i.sightings}</td>
                      <td className="pe-3 text-xs">
                        {i.malicious ? <span className="text-crit">{tr("malicious")}</span> : <span className="text-ink-300">{tr("not flagged")}</span>}
                        {i.reviewed && <span className="ms-2 text-safe">{tr("reviewed")}</span>}{i.blocked && <span className="ms-2 text-violet-700">{tr("blocked")}</span>}
                      </td>
                      <td className="whitespace-nowrap text-end">
                        <Button variant="ghost" className="h-7 !px-2 text-xs" loading={busy === `m-${i.value}`} onClick={() => act(`m-${i.value}`, () => apiSend("/api/indicators/review", "POST", { type: i.type, value: i.value, verdict: "malicious" }))}><XCircle className="h-3.5 w-3.5 text-crit" /> {tr("Malicious")}</Button>
                        <Button variant="ghost" className="h-7 !px-2 text-xs" loading={busy === `g-${i.value}`} onClick={() => act(`g-${i.value}`, () => apiSend("/api/indicators/review", "POST", { type: i.type, value: i.value, verdict: "benign" }))}><CheckCircle2 className="h-3.5 w-3.5 text-safe" /> {tr("Benign")}</Button>
                        {["domain", "ip", "url", "hash"].includes(i.type) && !i.blocked && (
                          <Button variant="danger" className="h-7 !px-2 text-xs" loading={busy === `b-${i.value}`} onClick={() => block(i.type, i.value, "Blocked from IOC review")}><Ban className="h-3.5 w-3.5" /> {tr("Block")}</Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {tab === "blocklist" && (
        <div className="grid gap-5 xl:grid-cols-[360px_1fr]">
          <Card title={tr("Add to blocklist")}>
            <div className="space-y-3">
              <div><Label htmlFor="bt">{tr("Type")}</Label><select id="bt" className={inputCls} value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>{["domain", "url", "ip", "hash", "phone"].map((x) => <option key={x} value={x}>{tr(x)}</option>)}</select></div>
              <div><Label htmlFor="bv">{tr("Value")}</Label><input id="bv" dir="ltr" className={inputCls + " font-mono"} value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder={form.type === "hash" ? "SHA-256" : form.type === "ip" ? "203.0.113.45" : form.type === "phone" ? "+971 50 123 4567" : "phish-example.top"} /></div>
              <div><Label htmlFor="br">{tr("Reason")}</Label><input id="br" className={inputCls} value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} maxLength={500} /></div>
              <Button variant="danger" loading={busy === `b-${form.value}`} onClick={() => { if (form.value.trim().length < 3) return toast("err", "Enter a value."); block(form.type, form.value.trim(), form.reason); setForm({ ...form, value: "", reason: "" }); }}><Ban className="h-4 w-4" /> {tr("Block")}</Button>
            </div>
          </Card>
          <Card title={tr("Blocked indicators")}>
            {!bl.data ? <ScanBar /> : bl.data.length === 0 ? <EmptyState title={tr("Blocklist is empty")} icon={Ban} /> : (
              <ul className="divide-y divide-ink-800">
                {bl.data.map((b) => (
                  <li key={b.id} className="flex items-center gap-3 py-2 text-sm">
                    <Pill>{b.type}</Pill><span className="min-w-0 flex-1 truncate font-mono text-xs">{b.value}</span>
                    <span className="hidden text-xs text-ink-400 md:inline">{b.reason}</span><span className="text-xs text-ink-500">{b.added_by} · {fmtTime(b.created_at)}</span>
                    <Button variant="ghost" className="h-7 !px-2" aria-label={tr("Remove")} loading={busy === `r-${b.id}`} onClick={() => act(`r-${b.id}`, async () => { await apiSend(`/api/blocklist/${b.id}`, "DELETE"); toast("ok", "Removed from blocklist."); })}><Trash2 className="h-4 w-4 text-ink-400" /></Button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      )}

      {tab === "actions" && (
        <Card title={tr("Response actions")}>
          {!actions.data ? <ScanBar /> : actions.data.length === 0 ? <EmptyState title={tr("No response actions yet")} /> : (
            <ul className="divide-y divide-ink-800">
              {actions.data.map((a) => (
                <li key={a.id} className="py-2 text-sm">
                  <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs text-volt">{a.action}</span><Pill>{a.target_type}</Pill><span className="truncate font-mono text-xs text-ink-300">{a.target_id}</span>{a.simulated && <SimBadge label={tr("demo env")} />}<span className="ms-auto text-xs text-ink-500">{a.actor} · {fmtTime(a.created_at)}</span></div>
                  <p className="text-xs text-ink-400">{a.result}</p>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}

      {tab === "audit" && (
        <Card title={<span className="flex items-center gap-2"><ScrollText className="h-4 w-4 text-volt" /> {tr("Audit log")}</span>} subtitle={tr("Who did what, and when (analyst role required)")}>
          {audit.error ? <ErrorBox error={audit.error} /> : !audit.data ? <ScanBar /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="text-xs font-medium text-ink-400"><tr><th className="py-2 pe-3 text-start">{tr("Time")}</th><th className="pe-3 text-start">{tr("Actor")}</th><th className="pe-3 text-start">{tr("Action")}</th><th className="pe-3 text-start">{tr("Target")}</th><th className="text-start">{tr("Details")}</th></tr></thead>
                <tbody className="divide-y divide-ink-800 font-mono">
                  {audit.data.map((l) => (
                    <tr key={l.id}><td className="whitespace-nowrap py-1.5 pe-3 text-ink-400">{fmtTime(l.created_at)}</td><td className="pe-3 text-ink-200">{l.actor}</td><td className="pe-3 text-volt">{l.action}</td><td className="max-w-[200px] truncate pe-3">{l.target}</td><td className="max-w-[360px] truncate text-ink-400" title={JSON.stringify(l.details)}>{JSON.stringify(l.details)}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

"use client";

import { Plus, Siren } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { broadcastRefresh, Button, Card, EmptyState, ErrorBox, inputCls, Label, PageHeader, ScanBar, SeverityBadge, SimBadge, StatusDot, timeAgo, useApi, useToast } from "@/components/ui";
import { apiGet, apiSend } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import type { Incident } from "@/lib/types";

export default function Incidents() {
  const { t } = useI18n();
  const toast = useToast();
  const [status, setStatus] = useState("open,investigating,contained");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [nf, setNf] = useState({ title: "", severity: "medium", summary: "" });
  const [busy, setBusy] = useState(false);
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);
  if (q.trim()) params.set("q", q.trim());
  const list = useApi<Incident[]>(() => apiGet(`/api/incidents?${params}`), [status, severity, q], 10000);

  const create = async () => {
    if (nf.title.trim().length < 3) return toast("err", "Title must be at least 3 characters.");
    setBusy(true);
    try {
      const inc = await apiSend("/api/incidents", "POST", nf);
      toast("ok", `Incident ${inc.id} created.`);
      setShowNew(false);
      setNf({ title: "", severity: "medium", summary: "" });
      list.reload(true);
      broadcastRefresh();
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_incidents")} subtitle="Triage, assign, investigate and resolve security incidents" icon={Siren}
        actions={<Button onClick={() => setShowNew(!showNew)}><Plus className="h-4 w-4" /> New incident</Button>} />
      {showNew && (
        <Card title="Create incident manually">
          <div className="grid gap-3 md:grid-cols-[2fr_1fr]">
            <div><Label htmlFor="t">Title</Label><input id="t" className={inputCls} value={nf.title} onChange={(e) => setNf({ ...nf, title: e.target.value })} maxLength={400} /></div>
            <div><Label htmlFor="s">Severity</Label>
              <select id="s" className={inputCls} value={nf.severity} onChange={(e) => setNf({ ...nf, severity: e.target.value })}>{["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}</select></div>
          </div>
          <div className="mt-3"><Label htmlFor="sm">Summary</Label><textarea id="sm" className={inputCls + " min-h-20"} value={nf.summary} onChange={(e) => setNf({ ...nf, summary: e.target.value })} maxLength={5000} /></div>
          <div className="mt-3 flex gap-2"><Button variant="primary" loading={busy} onClick={create}>Create</Button><Button variant="ghost" onClick={() => setShowNew(false)}>Cancel</Button></div>
        </Card>
      )}
      <Card>
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <div><Label htmlFor="fs">Status</Label>
            <select id="fs" className={inputCls} value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="open,investigating,contained">Active</option><option value="">All</option>
              {["open", "investigating", "contained", "resolved", "false_positive"].map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
            </select></div>
          <div><Label htmlFor="fv">Severity</Label>
            <select id="fv" className={inputCls} value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">Any</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
            </select></div>
          <div><Label htmlFor="fq">Search</Label><input id="fq" className={inputCls} placeholder="Title contains…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        </div>
        {list.error ? <ErrorBox error={list.error} onRetry={() => list.reload()} /> : !list.data ? <ScanBar /> : list.data.length === 0 ? (
          <EmptyState title="No incidents match" icon={Siren}>High-risk analyses (score ≥ threshold) create incidents automatically.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-[11px] uppercase tracking-wider text-ink-400">
                <tr><th className="py-2 pe-3 text-start">ID</th><th className="pe-3 text-start">Title</th><th className="pe-3 text-start">Severity</th><th className="pe-3 text-start">Status</th><th className="pe-3 text-start">Source</th><th className="pe-3 text-start">Assignee</th><th className="text-start">Created</th></tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {list.data.map((i) => (
                  <tr key={i.id} className="hover:bg-ink-800/40">
                    <td className="py-2 pe-3 font-mono text-xs"><Link href={`/incidents/${i.id}`} className="text-volt hover:underline">{i.id}</Link></td>
                    <td className="max-w-[360px] pe-3"><Link href={`/incidents/${i.id}`} className="block truncate text-ink-100 hover:text-volt">{i.title}</Link>
                      <div className="flex gap-2 text-[10px] uppercase">{i.correlated && <span className="text-volt">correlated</span>}{i.escalated && <span className="text-crit">escalated</span>}{i.demo && <SimBadge label="demo" />}</div></td>
                    <td className="pe-3"><SeverityBadge s={i.severity} /></td>
                    <td className="pe-3"><StatusDot s={i.status} /></td>
                    <td className="pe-3 text-xs text-ink-300">{i.source}</td>
                    <td className="pe-3 text-xs text-ink-300">{i.assigned_to || <span className="text-ink-500">unassigned</span>}</td>
                    <td className="text-xs text-ink-400">{timeAgo(i.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

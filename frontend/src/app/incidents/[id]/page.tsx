"use client";

import { tr } from "@/lib/i18n";
import { ArrowLeft, Bot, CheckCircle2, GitMerge, Megaphone, Network, ShieldBan } from "lucide-react";
import Link from "next/link";
import { use, useEffect, useState } from "react";
import { broadcastRefresh, Button, Card, cn, ErrorBox, fmtTime, inputCls, Label, Pill, SeverityBadge, SimBadge, Spinner, StatusDot, useApi, useToast } from "@/components/ui";
import { apiGet, apiSend } from "@/lib/api";

const EVENT_COLOR: Record<string, string> = {
  created: "bg-volt", evidence: "bg-ink-400", correlation: "bg-azure", escalation: "bg-crit", status: "bg-warn", assignment: "bg-safe", note: "bg-ink-300", action: "bg-violet-400",
};

export default function IncidentDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const toast = useToast();
  const { data: inc, error, loading, reload } = useApi<any>(() => apiGet(`/api/incidents/${id}`), [id], 10000);
  const users = useApi<any[]>(() => apiGet("/api/users"), []);
  const [status, setStatus] = useState("");
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    if (inc) {
      setStatus(inc.status);
      setAssignee(inc.assigned_to || "");
    }
  }, [inc?.status, inc?.assigned_to]); // eslint-disable-line react-hooks/exhaustive-deps

  const act = async (k: string, fn: () => Promise<any>) => {
    setBusy(k);
    try {
      await fn();
      reload(true);
      broadcastRefresh();
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };

  if (loading && !inc) return <Spinner label={tr("Loading incident…")} />;
  if (error && !inc) return <ErrorBox error={error} onRetry={() => reload()} />;
  if (!inc) return null;

  const save = () => act("save", async () => {
    const body: any = {};
    if (status !== inc.status) body.status = status;
    if (assignee !== (inc.assigned_to || "")) body.assigned_to = assignee;
    if (note.trim()) body.note = note.trim();
    if (!Object.keys(body).length) throw new Error("No changes to save.");
    await apiSend(`/api/incidents/${id}`, "PATCH", body);
    setNote("");
    toast("ok", "Incident updated.");
  });

  const badDomains = inc.indicators.filter((i: any) => i.malicious && ["domain", "ip"].includes(i.type));
  const analysts = (users.data || []).filter((u) => u.role !== "employee");

  return (
    <div className="space-y-5">
      <Link href="/incidents" className="inline-flex items-center gap-1 text-sm text-ink-300 hover:text-ink-100"><ArrowLeft className="h-4 w-4 rtl:rotate-180" /> {tr("Incidents")}</Link>
      <Card>
        <div className="flex flex-wrap items-start gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm text-volt">{inc.id}</span><SeverityBadge s={inc.severity} /><StatusDot s={inc.status} />
              {inc.correlated && <Pill className="text-volt"><GitMerge className="h-3 w-3" /> {tr("correlated")}</Pill>}
              {inc.escalated && <Pill className="text-crit">{tr("escalated")}</Pill>}{inc.demo && <SimBadge label={tr("demo")} />}
            </div>
            <h1 className="mt-2 text-lg font-semibold text-ink-100">{inc.title}</h1>
            <p className="mt-1 text-xs text-ink-400">{tr("Source:")} {inc.source} · Risk {inc.risk_score}/100 · Created {fmtTime(inc.created_at)} · Updated {fmtTime(inc.updated_at)}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link href={`/graph?incident=${inc.id}`}><Button><Network className="h-4 w-4" /> {tr("Attack graph")}</Button></Link>
            <Button variant="danger" loading={busy === "esc"} disabled={inc.escalated} onClick={() => act("esc", async () => { const r = await apiSend(`/api/incidents/${id}/escalate`, "POST"); toast("ok", r.message); })}><Megaphone className="h-4 w-4" /> {inc.escalated ? tr("Escalated") : tr("Escalate")}</Button>
          </div>
        </div>
      </Card>

      <div className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <div className="space-y-5">
          <Card title={tr("Timeline")}>
            <ol className="relative space-y-4 border-s border-ink-700 ps-5">
              {inc.timeline.map((e: any) => (
                <li key={e.id} className="relative">
                  <span className={cn("absolute -start-[25px] top-1.5 h-2.5 w-2.5 rounded-full ring-4 ring-ink-900", EVENT_COLOR[e.type] || "bg-ink-400")} />
                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-ink-400"><span className="font-semibold">{e.type}</span><span>{fmtTime(e.created_at)}</span><span>· {e.actor}</span></div>
                  <p className={cn("mt-0.5 text-sm", e.type === "correlation" ? "text-sky-700" : e.type === "escalation" ? "text-rose-700" : "text-ink-200")}>{e.message}</p>
                </li>
              ))}
            </ol>
          </Card>
          <Card title={`${tr("Evidence")} — ${tr("analyses")} (${inc.analyses.length}) · ${tr("endpoint events")} (${inc.endpoint_events.length})`}>
            <ul className="space-y-2">
              {inc.analyses.map((a: any) => (
                <li key={a.id}><Link href={`/analyses/${a.id}`} className="flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-850/60 p-2.5 text-sm hover:border-ink-500">
                  <SeverityBadge s={a.severity} /><Pill>{a.kind}</Pill><span className="min-w-0 flex-1 truncate">{a.title}</span><span className="font-mono text-xs">{a.risk_score}</span></Link></li>
              ))}
              {inc.endpoint_events.map((e: any) => (
                <li key={e.id} className="flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-850/60 p-2.5 text-sm">
                  <SeverityBadge s={e.severity} /><Pill>{e.event_type}</Pill>{e.simulated && <SimBadge />}<span className="min-w-0 flex-1 truncate">{e.title}</span><span className="font-mono text-xs">{e.risk_score}</span>
                </li>
              ))}
            </ul>
          </Card>
          <Card title={`${tr("Related indicators")} (${inc.indicators.length})`}>
            <div className="flex flex-wrap gap-1.5">
              {inc.indicators.map((i: any) => (
                <span key={i.id} className={cn("rounded px-2 py-1 font-mono text-[11px] ring-1", i.malicious ? "bg-crit/10 text-rose-700 ring-crit/40" : "bg-ink-850 text-ink-200 ring-ink-600")} title={i.role}>
                  <span className="text-ink-400">{i.type}:</span> {i.value.length > 60 ? i.value.slice(0, 60) + "…" : i.value}
                </span>
              ))}
            </div>
          </Card>
        </div>

        <div className="space-y-5">
          <Card title={tr("Manage")}>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div><Label htmlFor="st">{tr("Status")}</Label>
                  <select id="st" className={inputCls} value={status} onChange={(e) => setStatus(e.target.value)}>
                    {["open", "investigating", "contained", "resolved", "false_positive"].map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
                  </select></div>
                <div><Label htmlFor="as">{tr("Assigned analyst")}</Label>
                  <select id="as" className={inputCls} value={assignee} onChange={(e) => setAssignee(e.target.value)}>
                    <option value="">{tr("Unassigned")}</option>{analysts.map((u) => <option key={u.username} value={u.username}>{u.full_name}</option>)}
                  </select></div>
              </div>
              <div><Label htmlFor="nt">{tr("Note")} {["resolved", "false_positive"].includes(status) && status !== inc.status && <span className="text-crit">{tr("(required to close)")}</span>}</Label>
                <textarea id="nt" className={inputCls + " min-h-20"} value={note} onChange={(e) => setNote(e.target.value)} maxLength={5000} placeholder={tr("Investigation notes, containment steps, resolution…")} /></div>
              <div className="flex flex-wrap gap-2">
                <Button variant="primary" loading={busy === "save"} onClick={save}>{tr("Save changes")}</Button>
                {inc.status !== "resolved" && <Button variant="success" loading={busy === "res"} onClick={() => {
                  const n = note.trim() || window.prompt(tr("Resolution note (required):")) || "";
                  if (!n.trim()) return;
                  act("res", async () => { await apiSend(`/api/incidents/${id}`, "PATCH", { status: "resolved", note: n }); setNote(""); toast("ok", "Incident resolved."); });
                }}><CheckCircle2 className="h-4 w-4" /> {tr("Resolve")}</Button>}
              </div>
            </div>
          </Card>
          {inc.ai_explanation ? (
            <Card title={<span className="flex items-center gap-2"><Bot className="h-4 w-4 text-slate-600" /> {tr("AI explanation")}</span>}><p className="text-sm text-ink-200">{inc.ai_explanation}</p><p className="mt-2 text-[11px] text-ink-500">{tr("Model-generated; verify against evidence.")}</p></Card>
          ) : (
            <Card title={tr("Summary")}><p className="text-sm text-ink-300">{inc.summary || "—"}</p><p className="mt-2 text-[11px] text-ink-500">{tr("AI explanation unavailable — summary built from deterministic findings.")}</p></Card>
          )}
          <Card title={tr("Recommended response")}>
            <ol className="list-decimal space-y-1.5 ps-5 text-sm text-ink-200">{(inc.recommended_response || []).map((r: string) => <li key={r}>{r}</li>)}</ol>
            {badDomains.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-2 border-t border-ink-700 pt-3">
                {badDomains.slice(0, 4).map((d: any) => (
                  <Button key={d.value} variant="danger" className="text-xs" loading={busy === d.value} onClick={() => act(d.value, async () => { const r = await apiSend("/api/blocklist", "POST", { type: d.type, value: d.value, reason: `Incident ${id}` }); toast("ok", r.message); })}>
                    <ShieldBan className="h-3.5 w-3.5" /> {tr("Block")} {d.value}
                  </Button>
                ))}
              </div>
            )}
          </Card>
          <Card title={tr("Response actions log")}>
            {inc.actions.length === 0 ? <p className="text-xs text-ink-400">{tr("No response actions yet.")}</p> : (
              <ul className="space-y-2 text-xs">{inc.actions.map((x: any, i: number) => <li key={i}><span className="font-mono text-volt">{x.action}</span> · {x.actor} · {fmtTime(x.created_at)}{x.simulated && <> <SimBadge label={tr("demo env")} /></>}<p className="text-ink-400">{x.result}</p></li>)}</ul>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

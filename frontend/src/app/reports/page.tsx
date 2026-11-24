"use client";

import { Database, FlaskConical, Link2, RotateCcw, Siren, Users } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Button, Card, cn, EmptyState, ErrorBox, inputCls, PageHeader, SeverityBadge, Stat, Tabs, timeAgo, useApi, useToast } from "@/components/ui";
import { apiGet, apiSend } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { CATEGORIES, DEMO_LABEL, STATUS_TONE, STATUSES, type ReportRow } from "@/lib/reports";

const tooltipStyle = { borderRadius: 8, border: "1px solid #e1e5ec", fontSize: 12 };

export default function Reports() {
  const toast = useToast();
  const [mode, setMode] = useState<"user" | "demo">("user");
  const [status, setStatus] = useState("");
  const [category, setCategory] = useState("");
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const params = new URLSearchParams({ mode });
  if (status) params.set("status", status);
  if (category) params.set("category", category);
  if (q.trim()) params.set("q", q.trim());
  const stats = useApi<any>(() => apiGet(`/api/reports/stats?mode=${mode}`), [mode]);
  const list = useApi<ReportRow[]>(() => apiGet(`/api/reports?${params}`), [mode, status, category, q]);

  const demo = async (action: "load" | "reset") => {
    if (action === "reset" && !window.confirm(tr("Remove all demo reports? Reports submitted by people are not touched."))) return;
    setBusy(action);
    try {
      const r = await apiSend(`/api/reports/demo/${action}`, "POST");
      toast("ok", tr(r.message));
      setMode("demo");
      stats.reload(true);
      list.reload(true);
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };

  const s = stats.data;
  const cats = s ? Object.entries(s.by_category as Record<string, number>).map(([k, v]) => ({ name: tr(CATEGORIES[k] || k), count: v })) : [];
  return (
    <div className="space-y-5">
      <PageHeader title={tr("Scam Reports")} icon={Siren}
        subtitle={tr("Reports from people, potentially related cases and patterns — for investigators.")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Tabs value={mode} onChange={setMode} items={[{ value: "user", label: <span className="flex items-center gap-1.5"><Users className="h-4 w-4" />{tr("Submitted reports")}</span> },
              { value: "demo", label: <span className="flex items-center gap-1.5"><FlaskConical className="h-4 w-4" />{tr("Demo data")}</span> }]} />
            <Button loading={busy === "load"} onClick={() => demo("load")}><Database className="h-4 w-4" /> {tr("Load demo data")}</Button>
            <Button variant="ghost" loading={busy === "reset"} onClick={() => demo("reset")}><RotateCcw className="h-4 w-4" /> {tr("Reset demo data")}</Button>
          </div>
        } />

      <div className={cn("flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium", mode === "demo" ? "border-2 border-honey bg-wax text-volt" : "border border-ink-700 bg-ink-900 text-ink-300")}>
        {mode === "demo" ? <><FlaskConical className="h-4 w-4" /> {tr("DEMO MODE")} · {tr(DEMO_LABEL)}</> : <><Users className="h-4 w-4" /> {tr("Showing reports submitted by people through 3B. Demo data is kept separate.")}</>}
      </div>

      {stats.error && <ErrorBox error={stats.error} onRetry={() => stats.reload()} />}
      {s && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Stat label={tr("Total reports")} value={s.total} />
            <Stat label={tr("Awaiting review")} value={s.pending} tone="warn" />
            <Stat label={tr("Escalated")} value={s.escalated} tone="crit" />
            <Stat label={tr("High risk")} value={s.high_risk} tone="crit" />
            <Stat label={tr("In related groups")} value={s.linked} tone="volt" />
            <Stat label={tr("Money reported lost")} value={`${(s.total_lost || 0).toLocaleString()} AED`} />
          </div>
          {s.total === 0 ? (
            <EmptyState title={mode === "demo" ? tr("No demo data loaded") : tr("No reports submitted yet")} icon={Database}>
              {mode === "demo" ? tr("Press Load demo data to add 24 fictional reports with shared numbers and domains.") : tr("Reports appear here when people submit them from Report a Scam.")}
            </EmptyState>
          ) : (
            <>
              <div className="grid gap-4 xl:grid-cols-3">
                <Card title={tr("Reports over time")} subtitle={tr("Per week, last 12 weeks")} className="xl:col-span-2">
                  <div className="h-52"><ResponsiveContainer>
                    <AreaChart data={s.by_week}>
                      <CartesianGrid stroke="#eef1f5" vertical={false} />
                      <XAxis dataKey="week" tickFormatter={(v) => v.slice(5)} stroke="#98a2b3" fontSize={11} />
                      <YAxis allowDecimals={false} stroke="#98a2b3" fontSize={11} width={28} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Area type="monotone" dataKey="count" name={tr("Reports")} stroke="#e08e0b" fill="#f4a62a" fillOpacity={0.3} />
                    </AreaChart>
                  </ResponsiveContainer></div>
                </Card>
                <Card title={tr("Reports by type")}>
                  <div className="h-64"><ResponsiveContainer>
                    <BarChart data={cats} layout="vertical" margin={{ left: 8 }}>
                      <XAxis type="number" allowDecimals={false} stroke="#98a2b3" fontSize={11} />
                      <YAxis type="category" dataKey="name" width={130} interval={0} stroke="#98a2b3" fontSize={10} />
                      <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#eef1f5" }} />
                      <Bar dataKey="count" name={tr("Reports")} fill="#0e1726" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer></div>
                </Card>
              </div>

              <div className="grid gap-4 xl:grid-cols-3">
                <Card title={<span className="flex items-center gap-2"><Link2 className="h-4 w-4 text-volt" />{tr("Potentially related groups")}</span>} className="xl:col-span-2">
                  <p className="mb-3 text-xs text-ink-400">{tr("Reports joined by the same number, the same domain or near-identical wording. A lead to review — numbers and domains can be spoofed or shared, so this is not proof of a single network.")}</p>
                  {s.groups.length === 0 ? <p className="text-sm text-ink-400">{tr("No related reports found.")}</p> : (
                    <ul className="space-y-2">
                      {s.groups.map((g: any, i: number) => (
                        <li key={i} className="rounded-lg border border-ink-700 p-3 text-sm">
                          <div className="flex flex-wrap items-center gap-2">
                            <b className="text-ink-100">{g.size} {tr("reports")}</b>
                            <span className="text-ink-400">·</span>
                            <span className="text-ink-300">{g.categories.map((c: string) => tr(CATEGORIES[c] || c)).join(" · ")}</span>
                            {g.total_lost > 0 && <span className="ms-auto text-crit">{g.total_lost.toLocaleString()} AED</span>}
                          </div>
                          <div className="mt-1 flex flex-wrap gap-1.5 text-xs">
                            {Object.entries(g.shared as Record<string, string[]>).map(([m, vals]) => vals.map((v) => (
                              <span key={m + v} dir="ltr" className="rounded bg-wax px-1.5 py-0.5 text-volt">{tr(m === "same_phone" ? "Same number" : m === "same_domain" ? "Same domain" : "Similar text")}: {v}</span>
                            )))}
                          </div>
                          <div className="mt-1.5 flex flex-wrap gap-1.5">
                            {g.references.map((ref: string) => <Link key={ref} dir="ltr" href={`/reports/${ref}`} className="font-mono text-xs text-volt hover:underline">{ref}</Link>)}
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </Card>
                <Card title={tr("Most reported")}>
                  <div className="space-y-3 text-sm">
                    <div>
                      <div className="mb-1 text-xs font-medium text-ink-400">{tr("Phone numbers")}</div>
                      {s.top_phones.length === 0 ? <p className="text-ink-400">—</p> : s.top_phones.map((p: any) => (
                        <button key={p.value} onClick={() => setQ(p.value)} className="flex w-full justify-between rounded px-1 py-0.5 hover:bg-ink-850"><span dir="ltr" className="font-mono">{p.value}</span><b>{p.count}</b></button>))}
                    </div>
                    <div>
                      <div className="mb-1 text-xs font-medium text-ink-400">{tr("Domains")}</div>
                      {s.top_domains.length === 0 ? <p className="text-ink-400">—</p> : s.top_domains.map((d: any) => (
                        <button key={d.value} onClick={() => setQ(d.value)} className="flex w-full justify-between rounded px-1 py-0.5 hover:bg-ink-850"><span dir="ltr" className="font-mono">{d.value}</span><b>{d.count}</b></button>))}
                    </div>
                  </div>
                </Card>
              </div>
            </>
          )}
        </>
      )}

      <Card title={tr("All reports")} action={
        <div className="flex flex-wrap gap-2">
          <input className={inputCls + " w-48"} placeholder={tr("Search number, domain, text…")} value={q} onChange={(e) => setQ(e.target.value)} />
          <select className={inputCls + " w-40"} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">{tr("All statuses")}</option>
            {Object.entries(STATUSES).map(([k, v]) => <option key={k} value={k}>{tr(v)}</option>)}
          </select>
          <select className={inputCls + " w-48"} value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">{tr("All types")}</option>
            {Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{tr(v)}</option>)}
          </select>
        </div>}>
        {list.error && <ErrorBox error={list.error} />}
        {(list.data || []).length === 0 ? <p className="text-sm text-ink-400">{tr("No reports match.")}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-ink-700 text-start text-xs text-ink-400">
                <th className="py-2 text-start">{tr("Reference")}</th><th className="text-start">{tr("Type")}</th><th className="text-start">{tr("Number / domain")}</th>
                <th className="text-start">{tr("Risk")}</th><th className="text-start">{tr("Status")}</th><th className="text-start">{tr("Received")}</th>
              </tr></thead>
              <tbody>
                {list.data!.map((r) => (
                  <tr key={r.reference} className="border-b border-ink-800 hover:bg-ink-850">
                    <td className="py-2"><Link dir="ltr" href={`/reports/${r.reference}`} className="font-mono text-xs text-volt hover:underline">{r.reference}</Link></td>
                    <td>{tr(CATEGORIES[r.category] || r.category)}</td>
                    <td dir="ltr" className="text-start font-mono text-xs">{r.phone || r.domain || "—"}</td>
                    <td><SeverityBadge s={r.severity} /> <span className="text-xs text-ink-400">{r.risk_score}</span></td>
                    <td><span className={cn("rounded-full px-2 py-0.5 text-xs", STATUS_TONE[r.status])}>{tr(STATUSES[r.status] || r.status)}</span></td>
                    <td className="text-xs text-ink-400">{timeAgo(r.created_at)}</td>
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

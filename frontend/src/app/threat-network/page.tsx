"use client";

import { FlaskConical, Gavel, Network, PhoneCall, RefreshCw, Users } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Button, Card, cn, EmptyState, ErrorBox, inputCls, PageHeader, Pill, Stat, Tabs, timeAgo, useApi, useToast } from "@/components/ui";
import { apiGet, apiSend } from "@/lib/api";
import { tr, trf } from "@/lib/i18n";

const STATUS_TONE: Record<string, string> = {
  verified: "bg-red-50 text-crit", suspicious: "bg-amber-50 text-warn", reported: "bg-ink-800 text-ink-300", revoked: "bg-ink-800 text-ink-400 line-through", allowlisted: "bg-emerald-50 text-safe",
};
const LEVEL_STYLE: Record<string, { stroke: string; dash?: string; label: string }> = {
  contains: { stroke: "#98a2b3", label: "Contains" },
  strongly_related: { stroke: "#d92d20", label: "Strongly related" },
  potentially_related: { stroke: "#dc6803", dash: "5 4", label: "Potentially related" },
};
const NODE_COLOR: Record<string, string> = { report: "#f5a524", phone: "#2e90fa", domain: "#7a5af8", email: "#12b76a" };

export default function ThreatNetwork() {
  const toast = useToast();
  const [mode, setMode] = useState<"user" | "demo">("user");
  const [status, setStatus] = useState("suspicious,verified");
  const [type, setType] = useState("");
  const stats = useApi<any>(() => apiGet("/api/network/stats"), []);
  const inds = useApi<any[]>(() => apiGet(`/api/network/indicators?mode=${mode}${status ? `&status=${status}` : ""}${type ? `&type=${type}` : ""}`), [mode, status, type]);
  const appeals = useApi<any[]>(() => apiGet("/api/network/appeals"), []);
  const queue = useApi<any[]>(() => apiGet("/api/phone/reports"), []);
  const graph = useApi<any>(() => apiGet(`/api/network/campaigns?mode=${mode}`), [mode]);
  const s = stats.data?.[mode];

  const setInd = async (id: number, st: string) => {
    const note = st === "suspicious" || st === "reported" ? "" : window.prompt(tr("Explain the evidence or reason (at least a sentence):")) || "";
    if (["verified", "revoked", "allowlisted"].includes(st) && note.trim().length < 10) return toast("err", tr("Explain the evidence or reason (at least a sentence)."));
    try { await apiSend(`/api/network/indicators/${id}`, "PATCH", { status: st, note }); inds.reload(true); stats.reload(true); } catch (e: any) { toast("err", e.message); }
  };
  const decide = async (id: number, uphold: boolean) => {
    const note = window.prompt(tr("Decision note:")) || "";
    try { await apiSend(`/api/network/appeals/${id}`, "PATCH", { uphold, note }); appeals.reload(true); inds.reload(true); } catch (e: any) { toast("err", e.message); }
  };
  const moderate = async (id: number, st: string) => {
    try { await apiSend(`/api/phone/reports/${id}`, "PATCH", { status: st }); queue.reload(true); inds.reload(true); } catch (e: any) { toast("err", e.message); }
  };

  return (
    <div className="space-y-5">
      <PageHeader title={tr("Collective Threat Network")} icon={Network}
        subtitle={tr("What 3B users reported, what analysts verified, and how scams connect when numbers, emails and links change.")}
        actions={<Tabs value={mode} onChange={setMode} items={[{ value: "user", label: <span className="flex items-center gap-1.5"><Users className="h-4 w-4" />{tr("Real data")}</span> },
          { value: "demo", label: <span className="flex items-center gap-1.5"><FlaskConical className="h-4 w-4" />{tr("Demo data")}</span> }]} />} />

      {mode === "demo" && <div className="rounded-lg border-2 border-honey bg-wax px-3 py-2 text-sm font-medium text-volt">{tr("DEMO MODE · fictional data. Load it from Scam Reports → Load demo data.")}</div>}
      {stats.error && <ErrorBox error={stats.error} onRetry={() => stats.reload()} />}
      {s && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
          <Stat label={tr("Verified indicators")} value={s.verified} tone="crit" />
          <Stat label={tr("Awaiting review")} value={s.suspicious_awaiting_review} tone="warn" />
          <Stat label={tr("Reported once")} value={s.reported_only} />
          <Stat label={tr("Phone numbers")} value={s.phones} />
          <Stat label={tr("Emails")} value={s.emails} />
          <Stat label={tr("Domains & links")} value={s.domains} />
          <Stat label={tr("Campaigns")} value={s.campaigns} tone="volt" hint={trf("{n} linked reports", { n: s.related_reports })} />
          <Stat label={tr("Sync version")} value={stats.data.sync_version} hint={trf("{n} open appeals", { n: stats.data.open_appeals })} />
        </div>
      )}

      <Card title={tr("Campaign graph")} subtitle={tr("Solid red: near-identical template or same identifier. Dashed: similar domain, nearby number or similar wording — a lead, not proof.")}>
        {graph.error && <ErrorBox error={graph.error} />}
        {graph.data && (graph.data.nodes.length === 0 ? <EmptyState title={tr("No reports yet")} icon={Network} /> : <Graph g={graph.data} />)}
        {graph.data?.campaigns?.length > 0 && (
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {graph.data.campaigns.map((c: any) => (
              <div key={c.campaign_id} className="rounded-lg border border-ink-700 p-3 text-sm">
                <div className="flex items-center justify-between"><b className="text-ink-100">{c.campaign_id}</b><span className="text-xs text-ink-400">{trf("{n} reports", { n: c.size })}</span></div>
                <div className="mt-1 text-xs text-ink-300">{trf("{p} numbers · {e} emails · {d} domains", { p: c.indicators.phone, e: c.indicators.email, d: c.indicators.domain })}</div>
                <div className="mt-1 flex flex-wrap gap-1">{c.categories.map((x: string) => <Pill key={x}>{tr(x)}</Pill>)}</div>
                <p className="mt-2 text-xs text-ink-400">{tr(c.relationship)} {tr(c.confidence_note)}</p>
                <div className="mt-1 flex flex-wrap gap-1.5">{c.references.slice(0, 6).map((r: string) => <Link key={r} href={`/reports/${r}`} className="text-xs text-volt hover:underline">{r}</Link>)}</div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title={tr("Shared indicators")} subtitle={tr("Only Suspicious (warn) and Verified (block-eligible) are sent to devices, as hashes. A report alone is never enough to verify.")}
        action={<div className="flex gap-2">
          <select className={cn(inputCls, "w-40")} value={status} onChange={(e) => setStatus(e.target.value)} aria-label={tr("Status")}>
            <option value="suspicious,verified">{tr("Active")}</option><option value="reported">{tr("Reported once")}</option><option value="suspicious">{tr("Awaiting review")}</option>
            <option value="verified">{tr("Verified")}</option><option value="revoked,allowlisted">{tr("Cleared")}</option><option value="">{tr("All")}</option></select>
          <select className={cn(inputCls, "w-32")} value={type} onChange={(e) => setType(e.target.value)} aria-label={tr("Type")}>
            <option value="">{tr("All types")}</option>{["phone", "email", "email_domain", "domain", "url", "payment"].map((t) => <option key={t} value={t}>{tr(t)}</option>)}</select>
        </div>}>
        {inds.error && <ErrorBox error={inds.error} />}
        {inds.data && inds.data.length === 0 ? <p className="text-sm text-ink-400">{tr("Nothing here.")}</p> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead><tr className="text-start text-xs text-ink-400"><th className="py-2 text-start">{tr("Indicator")}</th><th className="text-start">{tr("Status")}</th><th className="text-start">{tr("Reporters")}</th><th className="text-start">{tr("Confidence")}</th><th className="text-start">{tr("Last seen")}</th><th /></tr></thead>
              <tbody className="divide-y divide-ink-700">
                {(inds.data || []).map((i) => (
                  <tr key={i.id}>
                    <td className="py-2"><span dir="ltr" className="text-ink-100">{i.value}</span> <span className="text-xs text-ink-400">· {tr(i.type)} · {tr(i.category)}</span></td>
                    <td><span className={cn("rounded-full px-2 py-0.5 text-xs", STATUS_TONE[i.status])}>{tr(i.status)}</span></td>
                    <td>{i.distinct_reporters}</td><td>{i.confidence}</td><td className="text-xs text-ink-400">{timeAgo(i.last_seen)}</td>
                    <td className="space-x-1 whitespace-nowrap text-end rtl:space-x-reverse">
                      {i.status !== "verified" && <Button onClick={() => setInd(i.id, "verified")}>{tr("Verify")}</Button>}
                      {i.status !== "revoked" && <Button variant="ghost" onClick={() => setInd(i.id, "revoked")}>{tr("Revoke")}</Button>}
                      {i.status !== "allowlisted" && <Button variant="ghost" onClick={() => setInd(i.id, "allowlisted")}>{tr("Legitimate")}</Button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={<span className="flex items-center gap-2"><Gavel className="h-4 w-4" /> {tr("Appeals (false-positive reports)")}</span>}>
          {appeals.data?.length ? (
            <ul className="space-y-2">{appeals.data.map((a) => (
              <li key={a.id} className="rounded-lg border border-ink-700 p-3 text-sm">
                <div dir="ltr" className="font-medium text-ink-100">{a.indicator?.value}</div>
                <p className="mt-1 text-ink-300">{a.reason}</p>
                <div className="mt-2 flex gap-2"><Button onClick={() => decide(a.id, true)}>{tr("Uphold — mark legitimate")}</Button><Button variant="ghost" onClick={() => decide(a.id, false)}>{tr("Reject")}</Button></div>
              </li>
            ))}</ul>
          ) : <p className="text-sm text-ink-400">{tr("No open appeals.")}</p>}
        </Card>
        <Card title={<span className="flex items-center gap-2"><PhoneCall className="h-4 w-4" /> {tr("Number reports to moderate")}</span>} subtitle={tr("Reporter identities are hidden. Rejecting a report removes it from the counts.")}>
          {queue.data?.length ? (
            <ul className="divide-y divide-ink-700 text-sm">{queue.data.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center gap-2 py-2">
                <span dir="ltr" className="text-ink-100">{r.number}</span><Pill>{tr(r.category)}</Pill><span className="flex-1 truncate text-xs text-ink-400">{r.description}</span>
                <Button onClick={() => moderate(r.id, "accepted")}>{tr("Accept")}</Button><Button variant="ghost" onClick={() => moderate(r.id, "rejected")}>{tr("Reject")}</Button>
              </li>
            ))}</ul>
          ) : <p className="text-sm text-ink-400">{tr("Nothing waiting.")}</p>}
        </Card>
      </div>

      <Card title={<span className="flex items-center gap-2"><RefreshCw className="h-4 w-4" /> {tr("How protection reaches other users")}</span>}>
        <ol className="list-decimal space-y-1 ps-5 text-sm text-ink-300">
          <li>{tr("A user reports a number, email or link. It is stored as 'reported' and is not shared.")}</li>
          <li>{tr("Three independent reporters (or two plus a high-risk analysis) make it 'suspicious': devices show a warning only.")}</li>
          <li>{tr("An analyst (or a trusted reputation provider) verifies it: devices may block it if the user turned blocking on.")}</li>
          <li>{tr("Devices download only changes since their last version, as hashes, and keep working offline.")}</li>
          <li>{tr("Appeals pause unverified warnings; revoked or legitimate indicators are removed from every device on the next sync. Reviews expire after 30/90 days.")}</li>
        </ol>
      </Card>
    </div>
  );
}

/** Simple deterministic layout: each campaign gets a cluster; reports on an inner ring, identifiers outside. */
function Graph({ g }: { g: any }) {
  const W = 960, H = 460;
  const layout = useMemo(() => {
    const pos: Record<string, { x: number; y: number }> = {};
    const groups: string[][] = g.campaigns.map((c: any) => c.references);
    const grouped = new Set(groups.flat());
    const loose = g.nodes.filter((n: any) => n.kind === "report" && !grouped.has(n.id)).map((n: any) => n.id);
    const clusters = [...groups, ...(loose.length ? [loose] : [])];
    const cols = Math.max(1, Math.min(clusters.length, 4)), rows = Math.ceil(clusters.length / cols);
    clusters.forEach((refs, ci) => {
      const cx = ((ci % cols) + 0.5) * (W / cols), cy = (Math.floor(ci / cols) + 0.5) * (H / rows);
      const r = Math.min(W / cols, H / rows) * 0.22;
      refs.forEach((id: string, i: number) => {
        const a = (2 * Math.PI * i) / refs.length;
        pos[id] = { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
      });
      const outer = new Set<string>();
      g.edges.filter((e: any) => e.level === "contains" && refs.includes(e.source)).forEach((e: any) => outer.add(e.target));
      [...outer].forEach((id, i, arr) => {
        if (pos[id]) return;
        const a = (2 * Math.PI * i) / arr.length + 0.3;
        pos[id] = { x: cx + r * 1.9 * Math.cos(a), y: cy + r * 1.9 * Math.sin(a) };
      });
    });
    return pos;
  }, [g]);
  const [hover, setHover] = useState<string | null>(null);
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full min-w-[640px]" role="img" aria-label={tr("Campaign graph")}>
        {g.edges.map((e: any, i: number) => {
          const a = layout[e.source], b = layout[e.target];
          if (!a || !b) return null;
          const st = LEVEL_STYLE[e.level] || LEVEL_STYLE.contains;
          return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={st.stroke} strokeDasharray={st.dash} strokeWidth={e.level === "contains" ? 1 : 2} opacity={0.7}><title>{tr(e.explanation)}</title></line>;
        })}
        {g.nodes.map((n: any) => {
          const p = layout[n.id];
          if (!p) return null;
          return (
            <g key={n.id} onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}>
              <circle cx={p.x} cy={p.y} r={n.kind === "report" ? 9 : 7} fill={NODE_COLOR[n.kind]} stroke="#fff" strokeWidth={2} />
              {(hover === n.id || n.kind !== "report") && <text x={p.x + 10} y={p.y + 4} fontSize={11} fill="currentColor" className="text-ink-300">{n.label}</text>}
              <title>{n.label}{n.category ? ` · ${n.category}` : ""}</title>
            </g>
          );
        })}
      </svg>
      <div className="mt-2 flex flex-wrap gap-3 text-xs text-ink-400">
        {Object.entries(NODE_COLOR).map(([k, c]) => <span key={k} className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full" style={{ background: c }} />{tr(k)}</span>)}
      </div>
    </div>
  );
}

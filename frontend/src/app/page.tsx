"use client";

import { Activity, AlertTriangle, ArrowUpRight, Cpu, FileSearch, LayoutDashboard, Mail, MailWarning, ShieldBan, ShieldCheck, Siren } from "lucide-react";
import Link from "next/link";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { DemoScenario } from "@/components/DemoScenario";
import { Card, cn, EmptyState, ErrorBox, PageHeader, SEV_HEX, SeverityBadge, SimBadge, Spinner, Stat, StatusDot, timeAgo, useApi } from "@/components/ui";
import { apiGet } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

const STATUS_BANNER: Record<string, [string, string]> = {
  critical: ["CRITICAL", "from-crit/25 border-crit/50 text-crit"],
  elevated: ["ELEVATED", "from-high/20 border-high/50 text-high"],
  guarded: ["GUARDED", "from-warn/15 border-warn/40 text-warn"],
  normal: ["NORMAL", "from-safe/15 border-safe/40 text-safe"],
};

const tooltipStyle = { background: "#0b1220", border: "1px solid #1f2e4d", borderRadius: 8, fontSize: 12, color: "#e3e9f5" };

export default function CommandCenter() {
  const { t } = useI18n();
  const { data: d, error, loading, reload } = useApi(() => apiGet("/api/dashboard"), [], 10000);

  if (loading && !d) return <Spinner label="Loading command center…" />;
  if (error && !d) return <ErrorBox error={error} onRetry={() => reload()} />;
  if (!d) return null;
  const [label, cls] = STATUS_BANNER[d.security_status];
  const tot = d.totals;

  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_command")} subtitle="Live view of analyses, incidents and endpoints across the organisation" icon={LayoutDashboard}
        actions={d.contains_demo_data && <SimBadge label="Includes demo / simulated data" />} />

      <div className={cn("flex flex-wrap items-center gap-4 rounded-xl border bg-gradient-to-r to-transparent p-4", cls)}>
        <ShieldCheck className="h-8 w-8" />
        <div>
          <div className="text-[11px] uppercase tracking-[0.2em] text-ink-300">{t("security_status")}</div>
          <div className="text-2xl font-bold tracking-wider">{label}</div>
        </div>
        <p className="text-sm text-ink-200">{d.security_status_text}</p>
        <span className="ms-auto text-[11px] text-ink-400">Updated {timeAgo(d.generated_at)} · auto-refresh 10s</span>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        <Stat label="Emails analysed" value={tot.emails_analyzed} icon={Mail} />
        <Stat label="Suspicious emails" value={tot.suspicious_emails} icon={MailWarning} tone={tot.suspicious_emails ? "warn" : "default"} />
        <Stat label="Critical threats" value={tot.critical_threats} icon={AlertTriangle} tone={tot.critical_threats ? "crit" : "default"} />
        <Stat label="Files analysed" value={tot.files_analyzed} icon={FileSearch} />
        <Stat label="Active incidents" value={tot.active_incidents} icon={Siren} tone={tot.active_incidents ? "crit" : "safe"} />
        <Stat label="Endpoints" value={tot.endpoints} icon={Cpu} hint={`${tot.endpoints_at_risk} at risk`} tone={tot.endpoints_at_risk ? "warn" : "default"} />
        <Stat label="Quarantined" value={tot.quarantined_emails} icon={ShieldBan} tone="volt" />
        <Stat label="Blocked IOCs" value={tot.blocked_indicators} icon={ShieldBan} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Threat activity — last 14 days" subtitle="Analyses by severity" className="xl:col-span-2">
          <div className="h-56">
            <ResponsiveContainer>
              <AreaChart data={d.activity}>
                <CartesianGrid stroke="#16223a" vertical={false} />
                <XAxis dataKey="date" tickFormatter={(v) => v.slice(5)} stroke="#5b6f95" fontSize={11} />
                <YAxis allowDecimals={false} stroke="#5b6f95" fontSize={11} width={28} />
                <Tooltip contentStyle={tooltipStyle} />
                {(["low", "medium", "high", "critical"] as const).map((s) => (
                  <Area key={s} type="monotone" dataKey={s} stackId="1" stroke={SEV_HEX[s]} fill={SEV_HEX[s]} fillOpacity={0.25} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Severity distribution" subtitle="All analyses">
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={d.severity_distribution}>
                <CartesianGrid stroke="#16223a" vertical={false} />
                <XAxis dataKey="severity" stroke="#5b6f95" fontSize={11} />
                <YAxis allowDecimals={false} stroke="#5b6f95" fontSize={11} width={28} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#16223a" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>{d.severity_distribution.map((x: any) => <Cell key={x.severity} fill={SEV_HEX[x.severity]} />)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Recent analysis history" className="xl:col-span-2" action={<Link href="/scam-analyzer" className="text-xs text-volt hover:underline">Analyze new →</Link>}>
          {d.recent_analyses.length === 0 ? (
            <EmptyState title="No analyses yet" icon={Activity}>Submit an email, message, URL or file — or run the demo scenario.</EmptyState>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-[11px] uppercase tracking-wider text-ink-400">
                  <tr><th className="py-2 pe-3 text-start">Item</th><th className="pe-3 text-start">Type</th><th className="pe-3 text-start">Verdict</th><th className="pe-3 text-start">Score</th><th className="text-start">When</th></tr>
                </thead>
                <tbody className="divide-y divide-ink-800">
                  {d.recent_analyses.map((a: any) => (
                    <tr key={a.id} className="hover:bg-ink-800/40">
                      <td className="max-w-[280px] py-2 pe-3"><Link href={`/analyses/${a.id}`} className="block truncate text-ink-100 hover:text-volt">{a.title}</Link></td>
                      <td className="pe-3 text-xs capitalize text-ink-300">{a.kind}</td>
                      <td className="pe-3"><div className="flex items-center gap-2"><SeverityBadge s={a.severity} /><span className="hidden truncate text-xs text-ink-300 md:inline">{a.classification}</span></div></td>
                      <td className="pe-3 font-mono text-xs">{a.risk_score}</td>
                      <td className="text-xs text-ink-400">{timeAgo(a.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Security recommendations">
          {d.recommendations.length === 0 ? <p className="text-sm text-ink-400">No outstanding recommendations.</p> : (
            <ul className="space-y-2">
              {d.recommendations.map((r: any, i: number) => (
                <li key={i}>
                  <Link href={r.link} className="flex items-start gap-2 rounded-lg border border-ink-700 bg-ink-850/60 p-2.5 text-sm hover:border-ink-500">
                    <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: r.level === "info" ? "#5b6f95" : SEV_HEX[r.level] }} />
                    <span className="flex-1 text-ink-200">{r.text}</span>
                    <ArrowUpRight className="h-4 w-4 shrink-0 text-ink-400" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Active & recent incidents" action={<Link href="/incidents" className="text-xs text-volt hover:underline">All incidents →</Link>}>
          {d.recent_incidents.length === 0 ? <EmptyState title="No incidents" icon={Siren} /> : (
            <ul className="space-y-2">
              {d.recent_incidents.map((i: any) => (
                <li key={i.id}>
                  <Link href={`/incidents/${i.id}`} className="block rounded-lg border border-ink-700 bg-ink-850/60 p-2.5 hover:border-ink-500">
                    <div className="flex items-center gap-2"><SeverityBadge s={i.severity} /><StatusDot s={i.status} />{i.correlated && <span className="text-[10px] font-semibold uppercase text-volt">correlated</span>}</div>
                    <p className="mt-1 truncate text-sm text-ink-100">{i.title}</p>
                    <p className="text-[11px] text-ink-400">{i.id} · {i.source} · {timeAgo(i.created_at)}</p>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Endpoint activity" action={<Link href="/endpoints" className="text-xs text-volt hover:underline">Endpoints →</Link>}>
          <div className="mb-3 flex flex-wrap gap-2">{d.endpoint_status.map((s: any) => <span key={s.status} className="rounded-md bg-ink-850 px-2 py-1 ring-1 ring-ink-700"><StatusDot s={s.status} /> <b className="ms-1 font-mono text-xs">{s.count}</b></span>)}</div>
          {d.recent_endpoint_events.length === 0 ? <p className="text-sm text-ink-400">No endpoint events received.</p> : (
            <ul className="space-y-1.5">
              {d.recent_endpoint_events.slice(0, 6).map((e: any) => (
                <li key={e.id} className="flex items-center gap-2 text-xs">
                  <SeverityBadge s={e.severity} /><span className="truncate text-ink-200">{e.title}</span>{e.simulated && <SimBadge />}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <DemoScenario />
      </div>
    </div>
  );
}

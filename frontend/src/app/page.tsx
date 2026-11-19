"use client";

import { Activity, AlertTriangle, ArrowUpRight, Cpu, FileSearch, LayoutDashboard, Mail, MailWarning, ShieldAlert, ShieldBan, ShieldCheck, Siren } from "lucide-react";
import Link from "next/link";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { DemoScenario } from "@/components/DemoScenario";
import { Card, cn, EmptyState, ErrorBox, PageHeader, SEV_HEX, SeverityBadge, SimBadge, Spinner, Stat, StatusDot, timeAgo, useApi } from "@/components/ui";
import { apiGet } from "@/lib/api";
import { tr, trf, useI18n } from "@/lib/i18n";

const STATUS_BANNER: Record<string, [string, string]> = {
  critical: ["Critical — action needed", "border-red-200 bg-red-50 text-crit"],
  elevated: ["Elevated", "border-orange-200 bg-orange-50 text-high"],
  guarded: ["Guarded", "border-amber-200 bg-amber-50 text-warn"],
  normal: ["All clear", "border-green-200 bg-green-50 text-safe"],
};

const tooltipStyle = { background: "#ffffff", border: "1px solid #e2e7ee", borderRadius: 8, fontSize: 12, color: "#101828" };

export default function CommandCenter() {
  const { t } = useI18n();
  const { data: d, error, loading, reload } = useApi(() => apiGet("/api/dashboard"), [], 10000);

  if (loading && !d) return <Spinner label={tr("Loading command center…")} />;
  if (error && !d) return <ErrorBox error={error} onRetry={() => reload()} />;
  if (!d) return null;
  const [label, cls] = STATUS_BANNER[d.security_status];
  const tot = d.totals;

  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_command")} subtitle={tr("Overview of what has been checked, open incidents and devices")} icon={LayoutDashboard}
        actions={d.contains_demo_data && <SimBadge label={tr("Includes demo / simulated data")} />} />

      <div className="grid gap-4 lg:grid-cols-[1.2fr_1fr]">
        <div className={cn("flex flex-wrap items-center gap-4 rounded-xl border p-5", cls)}>
          <ShieldCheck className="h-9 w-9" />
          <div>
            <div className="text-sm text-ink-300">{t("security_status")}</div>
            <div className="text-2xl font-semibold">{tr(label)}</div>
            <p className="mt-0.5 text-sm text-ink-200">{d.security_status_text}</p>
          </div>
          <span className="ms-auto self-end text-xs text-ink-400">{tr("Updated")} {timeAgo(d.generated_at)}</span>
        </div>
        <div className="flex flex-col justify-center gap-3 rounded-xl border border-ink-700 bg-ink-900 p-5 shadow-[0_1px_2px_rgba(16,24,40,0.05)]">
          <div className="text-base font-semibold text-ink-100">{tr("Got something suspicious?")}</div>
          <div className="flex flex-wrap gap-2">
            <Link href="/scam-analyzer" className="inline-flex items-center gap-2 rounded-lg bg-volt px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-blue-800"><ShieldAlert className="h-4 w-4" /> {tr("Check a message or link")}</Link>
            <Link href="/email-security" className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm text-ink-200 ring-1 ring-ink-600 hover:bg-ink-800"><Mail className="h-4 w-4" /> {tr("Check an email")}</Link>
            <Link href="/forensics" className="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm text-ink-200 ring-1 ring-ink-600 hover:bg-ink-800"><FileSearch className="h-4 w-4" /> {tr("Check a file")}</Link>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label={tr("Emails checked")} value={tot.emails_analyzed} icon={Mail} />
        <Stat label={tr("Suspicious emails")} value={tot.suspicious_emails} icon={MailWarning} tone={tot.suspicious_emails ? "warn" : "default"} />
        <Stat label={tr("Critical threats")} value={tot.critical_threats} icon={AlertTriangle} tone={tot.critical_threats ? "crit" : "default"} />
        <Stat label={tr("Files checked")} value={tot.files_analyzed} icon={FileSearch} />
        <Stat label={tr("Active incidents")} value={tot.active_incidents} icon={Siren} tone={tot.active_incidents ? "crit" : "safe"} />
        <Stat label={tr("Endpoints")} value={tot.endpoints} icon={Cpu} hint={trf("{n} at risk", { n: tot.endpoints_at_risk })} tone={tot.endpoints_at_risk ? "warn" : "default"} />
        <Stat label={tr("Quarantined")} value={tot.quarantined_emails} icon={ShieldBan} tone="volt" />
        <Stat label={tr("Blocked items")} value={tot.blocked_indicators} icon={ShieldBan} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title={tr("Threat activity — last 14 days")} subtitle={tr("Analyses by severity")} className="xl:col-span-2">
          <div className="h-56">
            <ResponsiveContainer>
              <AreaChart data={d.activity}>
                <CartesianGrid stroke="#eef1f5" vertical={false} />
                <XAxis dataKey="date" tickFormatter={(v) => v.slice(5)} stroke="#98a2b3" fontSize={11} />
                <YAxis allowDecimals={false} stroke="#98a2b3" fontSize={11} width={28} />
                <Tooltip contentStyle={tooltipStyle} />
                {(["low", "medium", "high", "critical"] as const).map((s) => (
                  <Area key={s} type="monotone" dataKey={s} stackId="1" stroke={SEV_HEX[s]} fill={SEV_HEX[s]} fillOpacity={0.25} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title={tr("Severity distribution")} subtitle={tr("All analyses")}>
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={d.severity_distribution}>
                <CartesianGrid stroke="#eef1f5" vertical={false} />
                <XAxis dataKey="severity" stroke="#98a2b3" fontSize={11} />
                <YAxis allowDecimals={false} stroke="#98a2b3" fontSize={11} width={28} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#eef1f5" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>{d.severity_distribution.map((x: any) => <Cell key={x.severity} fill={SEV_HEX[x.severity]} />)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title={tr("Recent analysis history")} className="xl:col-span-2" action={<Link href="/scam-analyzer" className="text-xs text-volt hover:underline">{tr("Analyze new →")}</Link>}>
          {d.recent_analyses.length === 0 ? (
            <EmptyState title={tr("No analyses yet")} icon={Activity}>{tr("Submit an email, message, URL or file — or run the demo scenario.")}</EmptyState>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-xs font-medium text-ink-400">
                  <tr><th className="py-2 pe-3 text-start">{tr("Item")}</th><th className="pe-3 text-start">{tr("Type")}</th><th className="pe-3 text-start">{tr("Verdict")}</th><th className="pe-3 text-start">{tr("Score")}</th><th className="text-start">{tr("When")}</th></tr>
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
        <Card title={tr("Security recommendations")}>
          {d.recommendations.length === 0 ? <p className="text-sm text-ink-400">{tr("No outstanding recommendations.")}</p> : (
            <ul className="space-y-2">
              {d.recommendations.map((r: any, i: number) => (
                <li key={i}>
                  <Link href={r.link} className="flex items-start gap-2 rounded-lg border border-ink-700 bg-ink-850/60 p-2.5 text-sm hover:border-ink-500">
                    <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: r.level === "info" ? "#98a2b3" : SEV_HEX[r.level] }} />
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
        <Card title={tr("Active & recent incidents")} action={<Link href="/incidents" className="text-xs text-volt hover:underline">{tr("All incidents →")}</Link>}>
          {d.recent_incidents.length === 0 ? <EmptyState title={tr("No incidents")} icon={Siren} /> : (
            <ul className="space-y-2">
              {d.recent_incidents.map((i: any) => (
                <li key={i.id}>
                  <Link href={`/incidents/${i.id}`} className="block rounded-lg border border-ink-700 bg-ink-850/60 p-2.5 hover:border-ink-500">
                    <div className="flex items-center gap-2"><SeverityBadge s={i.severity} /><StatusDot s={i.status} />{i.correlated && <span className="text-[10px] font-semibold uppercase text-volt">{tr("correlated")}</span>}</div>
                    <p className="mt-1 truncate text-sm text-ink-100">{i.title}</p>
                    <p className="text-[11px] text-ink-400">{i.id} · {i.source} · {timeAgo(i.created_at)}</p>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title={tr("Endpoint activity")} action={<Link href="/endpoints" className="text-xs text-volt hover:underline">{tr("Endpoints →")}</Link>}>
          <div className="mb-3 flex flex-wrap gap-2">{d.endpoint_status.map((s: any) => <span key={s.status} className="rounded-md bg-ink-850 px-2 py-1 ring-1 ring-ink-700"><StatusDot s={s.status} /> <b className="ms-1 font-mono text-xs">{s.count}</b></span>)}</div>
          {d.recent_endpoint_events.length === 0 ? <p className="text-sm text-ink-400">{tr("No endpoint events received.")}</p> : (
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

"use client";

import { ArrowDownLeft, ArrowUpRight, Ban, Globe2, Radio, ShieldCheck, ShieldOff, Undo2 } from "lucide-react";
import { useMemo, useState } from "react";
import { apiGet, apiSend } from "@/lib/api";
import { getLang, tr } from "@/lib/i18n";
import { Button, Card, cn, EmptyState, ErrorBox, fmtTime, inputCls, Pill, ScanBar, SeverityBadge, Tabs, timeAgo, useApi, useToast } from "./ui";
import { WorldMap } from "./WorldMap";

function flag(code?: string | null) {
  if (!code || code.length !== 2) return "🌐";
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

function countryName(code?: string | null, fallback?: string) {
  if (code && getLang() === "ar") {
    try {
      return new Intl.DisplayNames(["ar"], { type: "region" }).of(code) || fallback || "";
    } catch {}
  }
  return tr(fallback || "");
}

function sevOf(score: number) {
  return score >= 80 ? "critical" : score >= 60 ? "high" : score >= 30 ? "medium" : "low";
}

export function LiveConnections({ deviceId, hostname, online }: { deviceId: string; hostname: string; online: boolean }) {
  const toast = useToast();
  const data = useApi<any>(() => apiGet(`/api/endpoints/${deviceId}/connections`), [deviceId], 5000);
  const cmds = useApi<any[]>(() => apiGet(`/api/endpoints/${deviceId}/commands`), [deviceId], 5000);
  const [tab, setTab] = useState<"all" | "flagged" | "inbound" | "outbound">("all");
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const rows = useMemo(() => {
    let r: any[] = data.data?.connections || [];
    if (tab === "flagged") r = r.filter((c) => c.risk_score >= 30);
    if (tab === "inbound" || tab === "outbound") r = r.filter((c) => c.direction === tab);
    const s = q.trim().toLowerCase();
    if (s) r = r.filter((c) => [c.process_name, c.remote_ip, c.origin?.country, c.origin?.city, c.origin?.org, c.origin?.isp].some((v) => (v || "").toLowerCase().includes(s)));
    return r;
  }, [data.data, tab, q]);

  const command = async (type: "block_ip" | "unblock_ip", ip: string) => {
    if (type === "block_ip" && !window.confirm(tr("Block {ip} in Windows Firewall on {host}?").replace("{ip}", ip).replace("{host}", hostname))) return;
    setBusy(type + ip);
    try {
      const r = await apiSend(`/api/endpoints/${deviceId}/commands`, "POST", { type, ip });
      toast("ok", tr(r.message));
      cmds.reload(true);
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };

  if (data.error) return <ErrorBox error={data.error} onRetry={() => data.reload()} />;
  if (!data.data) return <ScanBar />;
  const s = data.data.summary;
  const posture = data.data.posture;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-ink-700 bg-ink-900 px-4 py-3 text-sm">
        <span className={cn("flex items-center gap-2 font-medium", online ? "text-safe" : "text-ink-400")}>
          <Radio className={cn("h-4 w-4", online && "animate-pulse")} /> {online ? tr("Live — agent reporting") : tr("Agent offline")}
        </span>
        <span className="text-ink-400">{tr("Updated")} {timeAgo(data.data.updated_at)}</span>
        <span className="ms-auto flex flex-wrap gap-2">
          <Pill>{s.active_connections} {tr("active connections")}</Pill>
          <Pill><ArrowUpRight className="h-3 w-3" /> {s.outbound} {tr("outbound")}</Pill>
          <Pill><ArrowDownLeft className="h-3 w-3" /> {s.inbound} {tr("inbound")}</Pill>
          <Pill className={s.flagged ? "bg-red-50 text-crit ring-red-200" : ""}>{s.flagged} {tr("flagged")}</Pill>
        </span>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.6fr_1fr]">
        <Card title={<span className="flex items-center gap-2"><Globe2 className="h-4 w-4 text-volt" /> {tr("Where this device is connecting")}</span>}
          subtitle={tr("Approximate location of the remote network (not of a person). Source: ip-api.com")}>
          {s.points.length ? <WorldMap points={s.points} /> : <EmptyState title={tr("No locations yet")}>{tr("Public IPs appear here once origin lookups finish.")}</EmptyState>}
        </Card>
        <div className="space-y-4">
          <Card title={tr("Countries")}>
            <ul className="space-y-1.5 text-sm">
              {s.countries.slice(0, 8).map((c: any) => (
                <li key={c.country} className="flex items-center gap-2">
                  <span className="text-base">{flag(c.code)}</span><span className="flex-1 text-ink-200">{countryName(c.code, c.country)}</span>
                  {c.flagged > 0 && <span className="text-xs text-crit">{c.flagged} {tr("flagged")}</span>}
                  <span className="tabular-nums text-ink-400">{c.count}</span>
                </li>
              ))}
            </ul>
          </Card>
          <Card title={tr("Top network owners")}>
            <ul className="space-y-1.5 text-sm">{s.top_orgs.map((o: any) => <li key={o.org} className="flex gap-2"><span className="flex-1 truncate text-ink-200">{tr(o.org)}</span><span className="tabular-nums text-ink-400">{o.count}</span></li>)}</ul>
          </Card>
        </div>
      </div>

      <Card title={tr("Connections")} action={<Tabs value={tab} onChange={setTab} items={[
        { value: "all", label: tr("All") }, { value: "flagged", label: `${tr("Flagged")} ${s.flagged}` },
        { value: "outbound", label: tr("Outbound") }, { value: "inbound", label: tr("Inbound") }]} />}>
        <input className={inputCls + " mb-3"} placeholder={tr("Search program, IP, country or company…")} value={q} onChange={(e) => setQ(e.target.value)} />
        {rows.length === 0 ? <EmptyState title={tr("No connections match")} /> : (
          <div className="max-h-[520px] overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-ink-900 text-xs font-medium text-ink-400">
                <tr><th className="py-2 pe-3 text-start">{tr("Program")}</th><th className="pe-3 text-start">{tr("Direction")}</th><th className="pe-3 text-start">{tr("Remote address")}</th>
                  <th className="pe-3 text-start">{tr("Comes from / goes to")}</th><th className="pe-3 text-start">{tr("Risk")}</th><th className="text-end">{tr("Action")}</th></tr>
              </thead>
              <tbody className="divide-y divide-ink-700">
                {rows.map((c) => {
                  const o = c.origin || {};
                  const place = o.scope === "public" ? [o.city, countryName(o.countryCode, o.country)].filter(Boolean).join("، ") : tr(o.label || "");
                  return (
                    <tr key={c.id} className={cn("align-top", c.risk_score >= 60 && "bg-red-50/60")}>
                      <td className="py-2 pe-3"><div className="font-medium text-ink-100">{c.process_name || tr("unknown")}</div><div className="text-xs text-ink-400">{tr("PID")} {c.pid ?? "—"}</div></td>
                      <td className="pe-3 text-xs">{c.direction === "inbound" ? <span className="inline-flex items-center gap-1 text-warn"><ArrowDownLeft className="h-3.5 w-3.5" />{tr("Inbound")}</span> : <span className="inline-flex items-center gap-1 text-ink-300"><ArrowUpRight className="h-3.5 w-3.5" />{tr("Outbound")}</span>}</td>
                      <td className="pe-3 font-mono text-xs text-ink-200" dir="ltr">{c.remote_ip}:{c.remote_port}<div className="text-ink-400">{c.protocol.toUpperCase()} · {c.status}</div></td>
                      <td className="pe-3 text-xs">
                        <div className="text-ink-200">{o.countryCode ? flag(o.countryCode) + " " : ""}{place || tr("Unknown")}</div>
                        {(o.org || o.isp) && <div className="text-ink-400">{o.org || o.isp}{o.as ? ` · ${o.as.split(" ")[0]}` : ""}</div>}
                        {(o.hosting || o.proxy) && <div className="text-warn">{o.proxy ? tr("Proxy/VPN") : tr("Data centre / hosting")}</div>}
                      </td>
                      <td className="pe-3">
                        {c.risk_score > 0 ? <SeverityBadge s={sevOf(c.risk_score)} /> : <span className="text-xs text-ink-400">—</span>}
                        {c.flags?.map((f: any) => <div key={f.title} className="mt-1 max-w-[220px] text-xs text-ink-300">{tr(f.title)}</div>)}
                      </td>
                      <td className="text-end">
                        {o.scope === "public" && (
                          <Button variant="ghost" className="h-7 !px-2 text-xs text-crit" loading={busy === "block_ip" + c.remote_ip} onClick={() => command("block_ip", c.remote_ip)}>
                            <Ban className="h-3.5 w-3.5" /> {tr("Block")}
                          </Button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 text-xs text-ink-400">{tr("WOLVE records connection metadata only (program, address, port). It never reads the content of your traffic.")}</p>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={<span className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-safe" /> {tr("Device protection status")}</span>}>
          {!posture ? <p className="text-sm text-ink-400">{tr("Waiting for the first posture report from the agent (every 5 minutes).")}</p> : (
            <div className="space-y-2 text-sm">
              {posture.firewall && !posture.firewall.error && (
                <div className="flex flex-wrap gap-2">{Object.entries(posture.firewall).map(([k, v]: any) => (
                  <span key={k} className={cn("rounded-full px-2.5 py-1 text-xs ring-1 ring-inset", v === "on" ? "bg-green-50 text-safe ring-green-200" : "bg-red-50 text-crit ring-red-200")}>
                    {tr("Firewall")} · {tr(k)}: {tr(v)}</span>))}</div>
              )}
              {posture.defender && !posture.defender.error ? (
                <ul className="space-y-1 text-ink-200">
                  <li>{tr("Real-time protection")}: <b className={posture.defender.realtime ? "text-safe" : "text-crit"}>{posture.defender.realtime ? tr("on") : tr("off")}</b></li>
                  <li>{tr("Antivirus signatures age")}: <b>{posture.defender.signature_age_days ?? "—"}</b> {tr("days")}</li>
                  <li>{tr("Last quick scan")}: <b>{posture.defender.last_quick_scan_days ?? "—"}</b> {tr("days ago")}</li>
                </ul>
              ) : <p className="text-xs text-ink-400">{tr(posture.defender?.error || "")}</p>}
              {(data.data.posture_findings || []).map((f: any) => <p key={f.title} className="text-sm text-crit">⚠ {tr(f.title)}</p>)}
              <p className="text-xs text-ink-400">{posture.os}</p>
            </div>
          )}
        </Card>
        <Card title={<span className="flex items-center gap-2"><ShieldOff className="h-4 w-4 text-crit" /> {tr("Response actions on this device")}</span>}
          subtitle={tr("Blocking runs only if the agent was started with --allow-response.")}>
          {(cmds.data || []).length === 0 ? <p className="text-sm text-ink-400">{tr("No actions yet. Use Block on a connection above.")}</p> : (
            <ul className="space-y-2 text-sm">
              {cmds.data!.map((c) => (
                <li key={c.id} className="flex flex-wrap items-center gap-2 rounded-lg border border-ink-700 p-2.5">
                  <span className="font-medium">{c.type === "block_ip" ? tr("Block") : tr("Unblock")} <span className="font-mono" dir="ltr">{c.params.ip}</span></span>
                  <Pill className={c.status === "done" ? "text-safe" : c.status === "refused" || c.status === "failed" ? "text-crit" : ""}>{tr(c.status)}</Pill>
                  <span className="text-xs text-ink-400">{c.created_by} · {fmtTime(c.created_at)}</span>
                  {c.type === "block_ip" && c.status === "done" && (
                    <Button variant="ghost" className="ms-auto h-7 !px-2 text-xs" loading={busy === "unblock_ip" + c.params.ip} onClick={() => command("unblock_ip", c.params.ip)}><Undo2 className="h-3.5 w-3.5" /> {tr("Unblock")}</Button>
                  )}
                  {c.result && <p className="w-full text-xs text-ink-400">{tr(c.result)}</p>}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {(data.data.listening || []).length > 0 && (
        <Card title={tr("Open (listening) ports")} subtitle={tr("Programs waiting for incoming connections")}>
          <div className="flex flex-wrap gap-1.5">
            {data.data.listening.slice(0, 60).map((l: any) => <Pill key={`${l.protocol}${l.port}`}><span dir="ltr">{l.protocol}/{l.port}</span> · {l.process_name || "?"}</Pill>)}
          </div>
        </Card>
      )}
    </div>
  );
}

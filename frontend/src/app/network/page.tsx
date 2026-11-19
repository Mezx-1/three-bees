"use client";

import { Globe2, Info } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { AnalysisActions } from "@/components/AnalysisActions";
import { ReportView } from "@/components/ReportView";
import { broadcastRefresh, Button, Card, ErrorBox, inputCls, PageHeader, Pill, ScanBar, SeverityBadge, Tabs, timeAgo, useApi } from "@/components/ui";
import { apiGet, apiSend } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import type { Analysis } from "@/lib/types";

type M = "ip" | "domain" | "url";
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export default function Network() {
  const { t } = useI18n();
  const [mode, setMode] = useState<M>("ip");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<Analysis | null>(null);
  const sys = useApi<any>(() => apiGet("/api/system/status"), []);
  const hist = useApi<Analysis[]>(() => apiGet("/api/analyses?kind=ip,domain,url&limit=15"), []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const v = value.trim();
    if (!v) return setErr("Enter a value.");
    if (mode === "ip" && !IPV4.test(v) && !v.includes(":")) return setErr("Not a valid IPv4/IPv6 address.");
    if (mode === "domain" && (!/^[^\s/]+\.[^\s/]+$/.test(v))) return setErr("Enter a bare domain like example.com (no scheme or path).");
    if (mode === "url" && !/\./.test(v)) return setErr("Enter a valid URL.");
    setErr(null);
    setBusy(true);
    setResult(null);
    try {
      const r = await apiSend<Analysis>(`/api/analyze/${mode}`, "POST", { value: v });
      setResult(r);
      hist.reload(true);
      broadcastRefresh();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const ext = sys.data?.external_lookups;
  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_network")} subtitle="IP, domain and URL intelligence with sourced, timestamped external lookups" icon={Globe2} />
      <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
        <Card>
          <form onSubmit={submit} className="space-y-3" noValidate>
            <Tabs value={mode} onChange={(m) => { setMode(m); setErr(null); }} items={[{ value: "ip", label: "IP address" }, { value: "domain", label: "Domain" }, { value: "url", label: "URL" }]} />
            <input dir="ltr" aria-label="Indicator" className={inputCls + " font-mono"} value={value} onChange={(e) => setValue(e.target.value)}
              placeholder={mode === "ip" ? "8.8.8.8 or 203.0.113.45" : mode === "domain" ? "alnoor-logistics-portal.top" : "https://secure-login.example.top/verify"} />
            {err && <ErrorBox error={err} />}
            <div className="flex items-center gap-3">
              <Button type="submit" variant="primary" loading={busy}>{t("analyze")}</Button>
              <span className="text-xs text-ink-400">External lookups: {ext === undefined ? "…" : ext ? <span className="text-safe">on</span> : <span className="text-warn">off</span>} (change in Settings)</span>
            </div>
            {busy && <ScanBar />}
          </form>
        </Card>
        <Card title={<span className="flex items-center gap-2"><Info className="h-4 w-4 text-warn" /> Interpretation limits</span>}>
          <ul className="list-disc space-y-1.5 ps-4 text-xs text-ink-300">
            <li>IP geolocation is approximate and describes the network operator — never a person&apos;s or device&apos;s exact location.</li>
            <li>VPNs, proxies and cloud hosting hide true origin.</li>
            <li>A phone country code shows where the number range is registered, not where the caller is. Caller ID can be spoofed.</li>
            <li>Reputation is shown only from configured providers: {sys.data ? <>AbuseIPDB <Pill>{sys.data.providers.abuseipdb.configured ? "configured" : "not configured"}</Pill></> : "…"}. Missing reputation means unknown, not clean.</li>
          </ul>
        </Card>
      </div>
      {result && <ReportView a={result} actions={<AnalysisActions a={result} onChange={setResult} />} />}
      <Card title="Recent lookups">
        {(hist.data?.length ?? 0) === 0 ? <p className="text-sm text-ink-400">No lookups yet.</p> : (
          <ul className="divide-y divide-ink-800">
            {hist.data!.map((a) => (
              <li key={a.id} className="flex items-center gap-3 py-2 text-sm">
                <SeverityBadge s={a.severity} /><span className="w-14 text-xs uppercase text-ink-400">{a.kind}</span>
                <Link href={`/analyses/${a.id}`} className="min-w-0 flex-1 truncate font-mono text-ink-100 hover:text-volt">{a.title}</Link>
                <span className="font-mono text-xs">{a.risk_score}</span><span className="w-16 text-end text-xs text-ink-400">{timeAgo(a.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

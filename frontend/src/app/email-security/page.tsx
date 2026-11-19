"use client";

import { Inbox, Mail, PlugZap, ShieldBan } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { AnalysisActions } from "@/components/AnalysisActions";
import { FileDrop } from "@/components/FileDrop";
import { ReportView } from "@/components/ReportView";
import { broadcastRefresh, Button, Card, EmptyState, ErrorBox, inputCls, PageHeader, Pill, ScanBar, SeverityBadge, StatusDot, Tabs, timeAgo, useApi, useToast } from "@/components/ui";
import { apiGet, apiSend, apiUpload, fetchSampleFile } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import type { Analysis } from "@/lib/types";

const FILTERS = ["all", "suspicious", "quarantined", "reported", "safe", "new"] as const;
type F = (typeof FILTERS)[number];

const PIPELINE = ["Parse MIME", "Headers & sender", "SPF / DKIM / DMARC", "Extract URLs", "Attachments: signature & MIME", "Images: OCR + QR", "Social-engineering", "Risk engine", "Report"];

export default function EmailSecurity() {
  const { t } = useI18n();
  const toast = useToast();
  const [mode, setMode] = useState<"upload" | "paste">("upload");
  const [file, setFile] = useState<File | null>(null);
  const [raw, setRaw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<Analysis | null>(null);
  const [filter, setFilter] = useState<F>("all");
  const [rowBusy, setRowBusy] = useState<string | null>(null);

  useEffect(() => {
    const s = new URLSearchParams(window.location.search).get("status") as F | null;
    if (s && FILTERS.includes(s)) setFilter(s);
  }, []);

  const list = useApi<Analysis[]>(() => apiGet(`/api/emails${filter !== "all" ? `?status=${filter}` : ""}`), [filter], 15000);

  const submit = async () => {
    if (mode === "upload" && !file) return setErr("Choose an .eml file, or load a sample.");
    if (mode === "paste" && !raw.trim()) return setErr("Paste the email source (headers + body) or at least the body.");
    if (mode === "upload" && file && !/\.(eml|txt)$/i.test(file.name)) return setErr("Only .eml files are supported. In Outlook use File → Save As → .eml; in Gmail use ⋮ → Download message.");
    setErr(null);
    setBusy(true);
    setResult(null);
    try {
      const fd = new FormData();
      if (mode === "upload") fd.append("file", file!);
      else fd.append("raw", raw);
      const r = await apiUpload<Analysis>("/api/emails/analyze", fd);
      setResult(r);
      list.reload(true);
      broadcastRefresh();
      if (r.incident_id) toast("info", `High-risk email: incident ${r.incident_id} opened automatically.`);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const loadSample = async (name: string) => {
    try {
      setMode("upload");
      setFile(await fetchSampleFile(name));
      setErr(null);
    } catch (e: any) {
      setErr(e.message);
    }
  };

  const quickQuarantine = async (id: string) => {
    setRowBusy(id);
    try {
      const r = await apiSend(`/api/emails/${id}/action`, "POST", { action: "quarantine" });
      toast("ok", r.message);
      list.reload(true);
      broadcastRefresh();
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setRowBusy(null);
    }
  };

  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_email")} subtitle="Inspect emails, headers, links, images and attachments — then quarantine, report or clear them" icon={Mail} />

      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-ink-700 bg-ink-900/70 px-3 py-2 text-xs text-ink-300">
        <PlugZap className="h-4 w-4 text-ink-400" />
        Mailbox integrations: <Pill>Microsoft 365 — not connected</Pill><Pill>Google Workspace — not connected</Pill>
        <span className="text-ink-400">Planned via Microsoft Graph / Gmail API with admin consent. In this MVP, emails are submitted manually and actions apply to WOLVE records only.</span>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_320px]">
        <Card title="Submit an email">
          <div className="space-y-3">
            <Tabs value={mode} onChange={setMode} items={[{ value: "upload", label: "Upload .eml" }, { value: "paste", label: "Paste source / body" }]} />
            {mode === "upload" ? (
              <FileDrop file={file} onFile={setFile} accept=".eml,message/rfc822,.txt" hint=".eml files with full headers give the best results (SPF/DKIM/DMARC, Received chain, attachments)" />
            ) : (
              <textarea aria-label="Raw email" dir="auto" className={inputCls + " min-h-52 font-mono text-[12px]"} value={raw} onChange={(e) => setRaw(e.target.value)}
                placeholder={"From: \"IT Support\" <it@example-secure.top>\nTo: you@company.ae\nSubject: Password expires today\nAuthentication-Results: ...\n\nDear user, verify your account..."} />
            )}
            {err && <ErrorBox error={err} />}
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="primary" loading={busy} onClick={submit}>{busy ? t("analyzing") : "Analyze email"}</Button>
              <span className="text-xs text-ink-400">Samples:</span>
              <Button variant="ghost" className="text-xs" onClick={() => loadSample("phishing-ceo-fraud.eml")}>CEO-fraud phishing .eml</Button>
              <Button variant="ghost" className="text-xs" onClick={() => loadSample("legitimate-hr.eml")}>Legitimate HR .eml</Button>
            </div>
            {busy && <ScanBar />}
          </div>
        </Card>
        <Card title="Inspection pipeline">
          <ol className="space-y-1.5 text-xs">
            {PIPELINE.map((p, i) => (
              <li key={p} className="flex items-center gap-2">
                <span className={"flex h-5 w-5 items-center justify-center rounded-full font-mono text-[10px] " + (result ? "bg-safe/20 text-safe" : busy ? "bg-volt/20 text-volt" : "bg-ink-700 text-ink-300")}>{i + 1}</span>
                <span className="text-ink-200">{p}</span>
              </li>
            ))}
          </ol>
        </Card>
      </div>

      {result && <ReportView a={result} actions={<AnalysisActions a={result} onChange={(a) => { setResult(a); list.reload(true); }} />} />}

      <Card title={<span className="flex items-center gap-2"><Inbox className="h-4 w-4 text-volt" /> Email security queue</span>}
        action={<Tabs value={filter} onChange={setFilter} items={FILTERS.map((f) => ({ value: f, label: <span className="capitalize">{f}</span> }))} />}>
        {list.error ? <ErrorBox error={list.error} onRetry={() => list.reload()} /> : !list.data ? <ScanBar /> : list.data.length === 0 ? (
          <EmptyState title={filter === "all" ? "No emails analysed yet" : `No ${filter} emails`} icon={Mail}>Upload an .eml or load the phishing sample above.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs font-medium text-ink-400">
                <tr><th className="py-2 pe-3 text-start">Subject</th><th className="pe-3 text-start">From</th><th className="pe-3 text-start">Risk</th><th className="pe-3 text-start">Status</th><th className="pe-3 text-start">Received</th><th className="text-end">Action</th></tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {list.data.map((a) => (
                  <tr key={a.id} className="hover:bg-ink-800/40">
                    <td className="max-w-[320px] py-2 pe-3"><Link href={`/analyses/${a.id}`} className="block truncate text-ink-100 hover:text-volt" dir="auto">{a.title}</Link>
                      <span className="text-[11px] text-ink-500">{a.classification}{a.demo ? " · demo" : ""}</span></td>
                    <td className="max-w-[220px] truncate pe-3 font-mono text-xs text-ink-300" title={a.from}>{a.from || "—"}</td>
                    <td className="pe-3"><div className="flex items-center gap-2"><SeverityBadge s={a.severity} /><span className="font-mono text-xs">{a.risk_score}</span></div></td>
                    <td className="pe-3"><StatusDot s={a.status} /></td>
                    <td className="pe-3 text-xs text-ink-400">{timeAgo(a.created_at)}</td>
                    <td className="text-end">
                      {a.status !== "quarantined" && a.status !== "safe" && a.risk_score >= 30 ? (
                        <Button variant="warn" className="h-7 !px-2 text-xs" loading={rowBusy === a.id} onClick={() => quickQuarantine(a.id)}><ShieldBan className="h-3.5 w-3.5" /> Quarantine</Button>
                      ) : <Link href={`/analyses/${a.id}`} className="text-xs text-volt hover:underline">Open</Link>}
                    </td>
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

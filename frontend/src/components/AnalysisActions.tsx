"use client";

import { tr } from "@/lib/i18n";
import { Download, FileJson, FileText, Flag, MailCheck, MailWarning, MoreHorizontal, ShieldBan, Siren, Trash2, Undo2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { apiSend, download } from "@/lib/api";
import type { Analysis } from "@/lib/types";
import { PoliceReport } from "./PoliceReport";
import { broadcastRefresh, Button, useToast } from "./ui";

export function AnalysisActions({ a, onChange }: { a: Analysis; onChange: (a: Analysis) => void }) {
  const toast = useToast();
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const [showReport, setShowReport] = useState(false);
  const [more, setMore] = useState(false);

  const act = async (key: string, fn: () => Promise<void>) => {
    setBusy(key);
    try {
      await fn();
      broadcastRefresh();
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };

  const emailAction = (action: string, note?: string) =>
    act(action, async () => {
      const r = await apiSend(`/api/emails/${a.id}/action`, "POST", { action, note });
      onChange({ ...a, ...r.analysis, report: a.report });
      toast("ok", r.message);
    });

  const maliciousDomains: string[] = Array.from(new Set(
    [...(a.report?.urls || []).filter((u: any) => u.score >= 60).map((u: any) => u.registered_domain).filter(Boolean),
      ...(a.kind === "url" || a.kind === "domain") && a.risk_score >= 60 && a.report?.url?.registered_domain ? [a.report.url.registered_domain] : []],
  ));

  return (
    <>
      {a.risk_score >= 30 && (
        <Button variant="primary" onClick={() => setShowReport(true)}><FileText className="h-4 w-4" /> {tr("Prepare police report")}</Button>
      )}
      {showReport && <PoliceReport id={a.id} onClose={() => setShowReport(false)} />}
      {a.kind === "email" && (
        <>
          {a.status !== "quarantined" ? (
            <Button variant="warn" loading={busy === "quarantine"} onClick={() => emailAction("quarantine")}><ShieldBan className="h-4 w-4" /> {tr("Quarantine")}</Button>
          ) : (
            <Button loading={busy === "release"} onClick={() => emailAction("release")}><Undo2 className="h-4 w-4" /> {tr("Release")}</Button>
          )}
          {a.status !== "suspicious" && a.status !== "quarantined" && (
            <Button loading={busy === "mark_suspicious"} onClick={() => emailAction("mark_suspicious")}><MailWarning className="h-4 w-4" /> {tr("Mark suspicious")}</Button>
          )}
          <Button loading={busy === "mark_safe"} onClick={() => {
            const note = a.risk_score >= 80 ? window.prompt(tr("Critical-risk email: enter your review note to mark it safe")) : undefined;
            if (a.risk_score >= 80 && !note) return;
            emailAction("mark_safe", note || undefined);
          }}><MailCheck className="h-4 w-4" /> {tr("Mark safe")}</Button>
          <Button loading={busy === "report"} onClick={() => emailAction("report")}><Flag className="h-4 w-4" /> {tr("Report to IT")}</Button>
        </>
      )}
      {!a.incident_id && a.kind !== "email" && (
        <Button loading={busy === "inc"} onClick={() => act("inc", async () => {
          const inc = await apiSend("/api/incidents", "POST", { title: `${a.classification}: ${a.title}`.slice(0, 390), severity: a.severity === "info" ? "low" : a.severity, analysis_id: a.id, summary: a.report?.findings.slice(0, 5).map((f) => f.title).join("; ") });
          onChange({ ...a, incident_id: inc.id });
          toast("ok", `Incident ${inc.id} created.`);
        })}><Siren className="h-4 w-4" /> {tr("Create incident")}</Button>
      )}
      {maliciousDomains.map((d) => (
        <Button key={d} variant="danger" loading={busy === `b-${d}`} onClick={() => act(`b-${d}`, async () => {
          const r = await apiSend("/api/blocklist", "POST", { type: "domain", value: d, reason: `From analysis ${a.id}` });
          toast("ok", r.message);
        })}><ShieldBan className="h-4 w-4" /> {tr("Block")} {d}</Button>
      ))}
      <div className="relative">
        <Button variant="ghost" onClick={() => setMore(!more)} aria-expanded={more}><MoreHorizontal className="h-4 w-4" /> {tr("More")}</Button>
        {more && (
          <div className="absolute bottom-full start-0 z-20 mb-1 flex w-48 flex-col gap-0.5 rounded-lg border border-ink-700 bg-white p-1 shadow-lg" onClick={() => setMore(false)}>
      <Button variant="ghost" className="justify-start" loading={busy === "html"} onClick={() => act("html", () => download(`/api/analyses/${a.id}/export?format=html`, `${a.id}.html`))}><Download className="h-4 w-4" /> {tr("Report")}</Button>
      <Button variant="ghost" className="justify-start" loading={busy === "json"} onClick={() => act("json", () => download(`/api/analyses/${a.id}/export?format=json`, `${a.id}.json`))}><FileJson className="h-4 w-4" /> {tr("JSON")}</Button>
      <Button variant="ghost" className="justify-start text-crit" loading={busy === "del"} onClick={() => {
        if (!window.confirm(tr("Delete this local 3B record? This does not affect any external mailbox."))) return;
        act("del", async () => {
          const r = await apiSend(`/api/analyses/${a.id}`, "DELETE");
          toast("ok", r.message);
          router.push("/");
        });
      }}><Trash2 className="h-4 w-4" /> {tr("Delete record")}</Button>
          </div>
        )}
      </div>
    </>
  );
}

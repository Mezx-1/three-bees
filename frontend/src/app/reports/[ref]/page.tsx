"use client";

import { ArrowLeft, FileDown, FlaskConical, Footprints, Link2, MessageSquare } from "lucide-react";
import Link from "next/link";
import { Fragment, use, useEffect, useState } from "react";
import { Button, Card, cn, ErrorBox, inputCls, Label, SeverityBadge, Spinner, fmtTime, useApi, useToast } from "@/components/ui";
import { apiBlobUrl, apiGet, apiSend } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { CATEGORIES, CHANNELS, DEMO_LABEL, STATUS_TONE, STATUSES } from "@/lib/reports";

export default function ReportDetail({ params }: { params: Promise<{ ref: string }> }) {
  const { ref } = use(params);
  const toast = useToast();
  const { data: r, error, loading, setData } = useApi<any>(() => apiGet(`/api/reports/${ref}`), [ref]);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [img, setImg] = useState<string | null>(null);

  useEffect(() => {
    if (!r?.has_evidence) return;
    let url: string | null = null;
    apiBlobUrl(`/api/reports/${ref}/evidence`).then((u) => { url = u; setImg(u); }).catch(() => setImg(null));
    return () => { if (url) URL.revokeObjectURL(url); };
  }, [r?.has_evidence, ref]);

  const update = async (body: { status?: string; note?: string }, key: string) => {
    setBusy(key);
    try {
      setData(await apiSend(`/api/reports/${ref}`, "PATCH", body));
      if (body.note) setNote("");
      toast("ok", tr("Saved."));
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };
  const print = async () => {
    try {
      const url = await apiBlobUrl(`/api/reports/${ref}/print`);
      window.open(url, "_blank", "noopener");
    } catch (e: any) {
      toast("err", e.message);
    }
  };

  if (loading && !r) return <Spinner label={tr("Loading report…")} />;
  if (error) return <ErrorBox error={error} />;
  if (!r) return null;
  const facts: [string, React.ReactNode][] = [
    ["Type", tr(CATEGORIES[r.category] || r.category)], ["Channel", tr(CHANNELS[r.channel] || r.channel)],
    ["Phone number", r.phone ? <span dir="ltr" className="font-mono">{r.phone}</span> : "—"],
    ["Link", r.url ? <span dir="ltr" className="break-all font-mono text-xs">{r.url}</span> : "—"],
    ["Incident date", r.incident_date || "—"], ["Emirate", r.emirate ? tr(r.emirate) : "—"],
    ["Money lost", r.amount_lost ? `${r.amount_lost.toLocaleString()} ${r.currency}` : "—"],
    ["Received", fmtTime(r.created_at)], ["Reporter", r.reporter || "—"], ["Contact", r.contact || "—"],
  ];
  return (
    <div className="space-y-4">
      <button onClick={() => history.back()} className="inline-flex items-center gap-1 text-sm text-ink-300 hover:text-ink-100"><ArrowLeft className="h-4 w-4 rtl:rotate-180" /> {tr("Back")}</button>
      {r.data_mode === "demo" && <div className="flex items-center gap-2 rounded-lg border-2 border-honey bg-wax px-3 py-2 text-sm font-semibold text-volt"><FlaskConical className="h-4 w-4" />{tr(DEMO_LABEL)}</div>}
      <div className="flex flex-wrap items-center gap-3">
        <h1 dir="ltr" className="font-mono text-2xl font-semibold text-ink-100">{r.reference}</h1>
        <SeverityBadge s={r.severity} /><span className="text-sm text-ink-400">{r.risk_score}/100</span>
        <span className={cn("rounded-full px-2.5 py-0.5 text-sm", STATUS_TONE[r.status])}>{tr(STATUSES[r.status] || r.status)}</span>
        <Button className="ms-auto" onClick={print}><FileDown className="h-4 w-4" /> {tr("Print / save as PDF")}</Button>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
        <div className="space-y-4">
          <Card title={tr("Report")}>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
              {facts.map(([k, v]) => <Fragment key={k}><dt className="text-ink-400">{tr(k)}</dt><dd className="text-ink-100">{v}</dd></Fragment>)}
            </dl>
            {r.message && <><div className="mt-3 text-xs font-medium text-ink-400">{tr("What was received")}</div><p dir="auto" className="mt-1 whitespace-pre-wrap rounded-lg bg-ink-850 p-3 text-sm text-ink-200">{r.message}</p></>}
            {r.description && <><div className="mt-3 text-xs font-medium text-ink-400">{tr("What happened")}</div><p dir="auto" className="mt-1 whitespace-pre-wrap text-sm text-ink-200">{r.description}</p></>}
            {img && <><div className="mt-3 text-xs font-medium text-ink-400">{tr("Screenshot")} · <span dir="ltr" className="font-mono">{r.evidence_name}</span></div><img src={img} alt={tr("Evidence screenshot")} className="mt-1 max-h-80 rounded-lg border border-ink-700" /></>}
          </Card>
          {r.analysis && (
            <Card title={tr("What 3B found")} action={<Link href={`/analyses/${r.analysis.id}`} className="text-sm text-volt hover:underline">{tr("Full analysis")}</Link>}>
              <ul className="space-y-1 text-sm text-ink-200">{r.analysis.reasons.map((x: string) => <li key={x}>• {x}</li>)}</ul>
              {r.analysis.next_steps?.items?.[0] && (
                <p className="mt-3 flex gap-2 rounded-lg bg-wax/70 p-3 text-sm text-ink-100"><Footprints className="h-4 w-4 shrink-0 text-volt" />{r.analysis.next_steps.items[0].step}</p>
              )}
              <p className="mt-2 text-xs text-ink-400">{tr("Indicators are signs that need review, not proof of a crime.")}</p>
            </Card>
          )}
          <Card title={<span className="flex items-center gap-2"><Link2 className="h-4 w-4 text-volt" />{tr("Potentially related reports")}</span>}>
            {(r.related || []).length === 0 ? <p className="text-sm text-ink-400">{tr("No related reports found.")}</p> : (
              <ul className="space-y-2 text-sm">
                {r.related.map((x: any) => (
                  <li key={x.reference} className="rounded-lg border border-ink-700 p-2.5">
                    <div className="flex items-center gap-2"><Link dir="ltr" href={`/reports/${x.reference}`} className="font-mono text-xs text-volt hover:underline">{x.reference}</Link>
                      <span className="text-xs text-ink-400">{tr(CATEGORIES[x.category] || x.category)}</span><span className="ms-auto text-xs text-ink-400">{Math.round(x.score * 100)}%</span></div>
                    <ul className="mt-1 text-xs text-ink-300">{x.links.map((l: any) => <li key={l.method}>• {tr(l.explanation)} <span dir="ltr" className="font-mono">({l.indicator})</span></li>)}</ul>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-2 text-xs text-ink-400">{tr("A shared number or domain is a lead, not proof: numbers can be spoofed, shared or mistyped.")}</p>
          </Card>
        </div>

        <div className="space-y-4">
          <Card title={tr("Review")}>
            <Label>{tr("Status")}</Label>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(STATUSES).map(([k, v]) => (
                <Button key={k} variant={r.status === k ? "primary" : "subtle"} loading={busy === k} onClick={() => r.status !== k && update({ status: k }, k)}>{tr(v)}</Button>
              ))}
            </div>
            <Label htmlFor="note">{tr("Add a note")}</Label>
            <textarea id="note" dir="auto" className={inputCls + " min-h-20"} value={note} onChange={(e) => setNote(e.target.value)} />
            <Button className="mt-2" loading={busy === "note"} disabled={!note.trim()} onClick={() => update({ note }, "note")}><MessageSquare className="h-4 w-4" /> {tr("Save note")}</Button>
          </Card>
          <Card title={tr("Timeline")}>
            <ul className="space-y-2 text-sm">
              {[...(r.history || []).map((h: any) => ({ at: h.at, by: h.by, text: `${tr("Status")}: ${tr(STATUSES[h.status] || h.status)}` })),
                ...(r.notes || []).map((n: any) => ({ at: n.at, by: n.by, text: n.text }))]
                .sort((a, b) => a.at.localeCompare(b.at)).map((e, i) => (
                  <li key={i} className="border-s-2 border-honey ps-3"><div className="text-xs text-ink-400">{fmtTime(e.at)} · {e.by}</div><div dir="auto" className="text-ink-200">{e.text}</div></li>
                ))}
            </ul>
          </Card>
          <p className="text-xs text-ink-400">{tr(r.disclaimer)}</p>
        </div>
      </div>
    </div>
  );
}

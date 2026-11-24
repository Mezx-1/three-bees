"use client";

import { CheckCircle2, FileWarning, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { FileDrop } from "@/components/FileDrop";
import { Button, Card, ErrorBox, inputCls, Label, PageHeader, ScanBar, SeverityBadge, useApi } from "@/components/ui";
import { apiGet, apiUpload } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { CATEGORIES, CHANNELS, EMIRATES, STATUSES, type ReportRow } from "@/lib/reports";

const EMPTY = { category: "", channel: "sms", phone: "", url: "", message: "", description: "", incident_date: "", amount_lost: "", currency: "AED", emirate: "", contact: "" };

export default function ReportScam() {
  const [f, setF] = useState(EMPTY);
  const [file, setFile] = useState<File | null>(null);
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<any>(null);
  const mine = useApi<ReportRow[]>(() => apiGet("/api/reports/mine"), [done?.reference]);
  const set = (k: keyof typeof EMPTY) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });

  const submit = async () => {
    setErr(null);
    if (!f.category) return setErr(tr("Choose what kind of scam it was."));
    if (!f.message.trim() && !f.description.trim() && !f.url.trim() && !f.phone.trim() && !file) return setErr(tr("Describe what happened, or add the message, link, number or a screenshot."));
    if (!ack) return setErr(tr("Please confirm you have read how the report is stored and used."));
    const fd = new FormData();
    Object.entries(f).forEach(([k, v]) => v !== "" && fd.append(k, v));
    fd.append("privacy_ack", "true");
    if (file) fd.append("evidence", file);
    setBusy(true);
    try {
      setDone(await apiUpload("/api/reports", fd));
      setF(EMPTY); setFile(null); setAck(false);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-5">
      <PageHeader title={tr("Report a Scam")} icon={ShieldAlert}
        subtitle={tr("Tell us what happened. Your report helps warn the next person and helps investigators link related cases.")} />

      {done && (
        <section role="status" className="rounded-xl border-2 border-green-200 bg-green-50 p-5">
          <div className="flex items-center gap-2 text-xl font-semibold text-safe"><CheckCircle2 className="h-6 w-6" />{tr("Report received")}</div>
          <p className="mt-2 text-ink-100">{tr("Your reference number:")} <b dir="ltr" className="font-mono text-lg">{done.reference}</b></p>
          <p className="mt-1 text-sm text-ink-300">{tr("Risk found in what you reported:")} <SeverityBadge s={done.severity} /> {done.risk_score}/100</p>
          <p className="mt-3 rounded-lg bg-white/70 p-3 text-sm text-ink-200">{tr("3B is a hackathon prototype. A report here is not an official police complaint. For urgent help or a formal complaint, use the Abu Dhabi Police app, call Aman on 8002626, or 999 in an emergency.")}</p>
          <Button className="mt-3" onClick={() => setDone(null)}>{tr("Report another scam")}</Button>
        </section>
      )}

      {!done && (
        <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
          <Card>
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-2">
                <div>
                  <Label htmlFor="cat">{tr("What kind of scam?")} *</Label>
                  <select id="cat" className={inputCls} value={f.category} onChange={set("category")}>
                    <option value="">{tr("Choose…")}</option>
                    {Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{tr(v)}</option>)}
                  </select>
                </div>
                <div>
                  <Label htmlFor="ch">{tr("How did it reach you?")}</Label>
                  <select id="ch" className={inputCls} value={f.channel} onChange={set("channel")}>
                    {Object.entries(CHANNELS).map(([k, v]) => <option key={k} value={k}>{tr(v)}</option>)}
                  </select>
                </div>
                <div>
                  <Label htmlFor="ph">{tr("Phone number involved")}</Label>
                  <input id="ph" dir="ltr" className={inputCls} value={f.phone} onChange={set("phone")} placeholder="+971 …" />
                </div>
                <div>
                  <Label htmlFor="url">{tr("Suspicious link")}</Label>
                  <input id="url" dir="ltr" className={inputCls} value={f.url} onChange={set("url")} placeholder="https://…" />
                  <p className="mt-1 text-xs text-ink-400">{tr("3B never opens the link.")}</p>
                </div>
              </div>
              <div>
                <Label htmlFor="msg">{tr("The message you received (paste it)")}</Label>
                <textarea id="msg" dir="auto" className={inputCls + " min-h-24"} value={f.message} onChange={set("message")} />
              </div>
              <div>
                <Label htmlFor="desc">{tr("What happened?")}</Label>
                <textarea id="desc" dir="auto" className={inputCls + " min-h-20"} value={f.description} onChange={set("description")} />
              </div>
              <div className="grid gap-3 md:grid-cols-4">
                <div>
                  <Label htmlFor="date">{tr("Date")}</Label>
                  <input id="date" type="date" className={inputCls} value={f.incident_date} onChange={set("incident_date")} />
                </div>
                <div>
                  <Label htmlFor="amt">{tr("Money lost")}</Label>
                  <input id="amt" type="number" min={0} className={inputCls} value={f.amount_lost} onChange={set("amount_lost")} placeholder="0" />
                </div>
                <div>
                  <Label htmlFor="cur">{tr("Currency")}</Label>
                  <select id="cur" className={inputCls} value={f.currency} onChange={set("currency")}>
                    {["AED", "USD", "EUR", "SAR"].map((c) => <option key={c}>{c}</option>)}
                  </select>
                </div>
                <div>
                  <Label htmlFor="em">{tr("Emirate")}</Label>
                  <select id="em" className={inputCls} value={f.emirate} onChange={set("emirate")}>
                    <option value="">—</option>
                    {EMIRATES.map((e) => <option key={e} value={e}>{tr(e)}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <Label>{tr("Screenshot (optional)")}</Label>
                <FileDrop file={file} onFile={setFile} accept="image/png,image/jpeg,image/webp" hint={tr("PNG, JPG or WEBP, up to 5 MB. If you don't paste the message, 3B reads the text from the screenshot on this computer.")} />
              </div>
              <div>
                <Label htmlFor="ct">{tr("Contact (optional)")}</Label>
                <input id="ct" className={inputCls} value={f.contact} onChange={set("contact")} placeholder={tr("Email or phone, only if you want to be contacted")} />
              </div>
              <label className="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-ink-200">
                <input type="checkbox" className="mt-1 h-4 w-4 accent-amber-600" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                <span>{tr("I understand: the report is stored on this 3B server and only investigators can read it. It is not an official police complaint. Don't include passwords, card numbers or codes.")}</span>
              </label>
              {err && <ErrorBox error={err} />}
              <Button variant="primary" className="px-5 py-2.5 text-base" loading={busy} onClick={submit}><FileWarning className="h-4 w-4" /> {tr("Submit report")}</Button>
              {busy && <ScanBar />}
            </div>
          </Card>
          <Card title={tr("Your reports")}>
            {(mine.data || []).length === 0 ? <p className="text-sm text-ink-400">{tr("No reports yet.")}</p> : (
              <ul className="space-y-2 text-sm">
                {mine.data!.map((r) => (
                  <li key={r.reference} className="rounded-lg border border-ink-700 p-2">
                    <div dir="ltr" className="text-start font-mono text-xs text-ink-300">{r.reference}</div>
                    <div className="text-ink-100">{tr(CATEGORIES[r.category] || r.category)}</div>
                    <div className="text-xs text-ink-400">{tr(STATUSES[r.status] || r.status)}</div>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-3 text-xs text-ink-400">{tr("Urgent? Call 999. To file a formal complaint use the Abu Dhabi Police app or Aman 8002626.")}</p>
            <Link href="/learn" className="mt-2 inline-block text-sm text-volt hover:underline">{tr("Learn how common scams work →")}</Link>
          </Card>
        </div>
      )}
    </div>
  );
}

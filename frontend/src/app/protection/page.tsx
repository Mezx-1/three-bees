"use client";

import { Ban, Bell, CheckCircle2, Flag, Search, ShieldCheck, Trash2, UserCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { Button, Card, cn, EmptyState, ErrorBox, inputCls, Label, PageHeader, Pill, timeAgo, useApi, useToast } from "@/components/ui";
import { apiGet, apiSend } from "@/lib/api";
import { tr } from "@/lib/i18n";

const TYPES = [{ v: "phone", l: "Phone number" }, { v: "email", l: "Email address" }, { v: "domain", l: "Website / domain" }, { v: "url", l: "Link" }];
const PREFS: { key: string; title: string; desc: string; note?: string; disabled?: boolean }[] = [
  { key: "shared_intel", title: "Use shared threat intelligence", desc: "Warn me about numbers, emails and links other 3B users reported and analysts checked." },
  { key: "caller_warnings", title: "Caller warnings", desc: "Show a warning label for suspicious incoming calls.", note: "Needs the 3B phone app (iPhone Call Directory / Android call screening)." },
  { key: "auto_block_calls", title: "Block verified scam numbers automatically", desc: "Off = warn only. Only numbers verified by an analyst or trusted source are ever blocked; reported numbers are never blocked.", note: "Needs the 3B phone app. A website can't block calls." },
  { key: "email_warnings", title: "Suspicious email warnings", desc: "Warn when an email you analyse matches a reported campaign or sender." },
  { key: "email_scanning", title: "Scan my mailbox automatically", desc: "Read new emails with your permission (Gmail via OAuth, read-only).", note: "Not available yet: it needs Google's OAuth approval for the read-only Gmail scope. 3B never asks for your email password.", disabled: true },
  { key: "url_protection", title: "Malicious link protection", desc: "Check links against the shared list and reputation services when you analyse them." },
  { key: "message_similarity", title: "Message similarity detection", desc: "Compare messages with scams already reported to 3B, even if the number or link changed." },
  { key: "cross_device_sync", title: "Sync to my devices", desc: "Keep a local copy of the shared list on my paired phone so protection works offline." },
];

export default function Protection() {
  const toast = useToast();
  const prefs = useApi<Record<string, boolean>>(() => apiGet("/api/network/prefs"), []);
  const lists = useApi<any[]>(() => apiGet("/api/network/lists"), []);
  const events = useApi<any[]>(() => apiGet("/api/network/events"), []);
  const [check, setCheck] = useState({ type: "phone", value: "" });
  const [checkRes, setCheckRes] = useState<any>(null);
  const [entry, setEntry] = useState({ list: "blocked", type: "phone", value: "", note: "" });
  const [appeal, setAppeal] = useState({ type: "phone", value: "", reason: "", contact: "" });
  const [appealRes, setAppealRes] = useState<string | null>(null);

  useEffect(() => {
    if (window.location.hash === "#mistake") document.getElementById("mistake")?.scrollIntoView();
  }, []);

  const toggle = async (key: string, v: boolean) => {
    try { prefs.setData(await apiSend("/api/network/prefs", "PUT", { [key]: v })); } catch (e: any) { toast("err", e.message); }
  };
  const doCheck = async () => {
    try {
      const r = await apiSend("/api/network/check", "POST", check);
      setCheckRes(r);
      if (r.level !== "none") apiSend("/api/network/events", "POST", { kind: r.level === "block" ? "blocked" : "warned", channel: check.type === "phone" ? "call" : check.type, indicator_type: check.type, indicator: check.value, reason: r.status }).then(() => events.reload(true)).catch(() => {});
    } catch (e: any) { toast("err", e.message); setCheckRes(null); }
  };
  const addEntry = async () => {
    try { await apiSend("/api/network/lists", "POST", entry); setEntry({ ...entry, value: "", note: "" }); lists.reload(true); } catch (e: any) { toast("err", e.message); }
  };
  const sendAppeal = async () => {
    try { const r = await apiSend("/api/network/appeals", "POST", appeal); setAppealRes(r.message); } catch (e: any) { toast("err", e.message); }
  };

  return (
    <div className="space-y-5">
      <PageHeader title={tr("Protection Settings")} icon={ShieldCheck}
        subtitle={tr("You decide what 3B warns about or blocks. Nothing is blocked or scanned without your choice.")} />

      <Card title={tr("Check a number, email or link")} subtitle={tr("Is it on the shared 3B list? You see the status, never who reported it.")}>
        <div className="flex flex-col gap-2 sm:flex-row">
          <select className={cn(inputCls, "sm:w-44")} value={check.type} onChange={(e) => setCheck({ ...check, type: e.target.value })} aria-label={tr("Type")}>{TYPES.map((t) => <option key={t.v} value={t.v}>{tr(t.l)}</option>)}</select>
          <input className={inputCls} dir="ltr" value={check.value} onChange={(e) => setCheck({ ...check, value: e.target.value })} aria-label={tr("Value")} placeholder="+971 50 000 0000" />
          <Button variant="primary" onClick={doCheck}><Search className="h-4 w-4" /> {tr("Check")}</Button>
        </div>
        {checkRes && (
          <div className={cn("mt-3 rounded-lg p-3 text-sm", checkRes.level === "block" ? "bg-red-50 text-crit" : checkRes.level === "warn" ? "bg-amber-50 text-warn" : "bg-ink-900 text-ink-200")}>
            <b>{tr({ verified: "Verified scam indicator", suspicious: "Reported by several users — not verified", reported: "Reported once — not verified", allowlisted: "Reviewed: legitimate",
              revoked: "Was listed, then cleared", not_listed: "Not on the shared list", trusted_by_you: "You marked this as trusted" }[checkRes.status as string] || checkRes.status)}</b>
            {checkRes.category && <> · {tr(checkRes.category)}</>}{checkRes.demo && " · DEMO"}
            {checkRes.note && <p className="mt-1 text-xs">{tr(checkRes.note)}</p>}
          </div>
        )}
      </Card>

      <Card title={tr("What 3B does for you")}>
        {prefs.error && <ErrorBox error={prefs.error} />}
        <ul className="divide-y divide-ink-700">
          {PREFS.map((p) => (
            <li key={p.key} className="flex items-start gap-4 py-3">
              <div className="flex-1">
                <div className="text-sm font-medium text-ink-100">{tr(p.title)}</div>
                <div className="text-xs text-ink-300">{tr(p.desc)}</div>
                {p.note && <div className="mt-0.5 text-xs text-ink-400">{tr(p.note)}</div>}
              </div>
              <label className={cn("relative mt-1 inline-flex shrink-0 items-center", p.disabled && "opacity-40")}>
                <input type="checkbox" className="peer sr-only" checked={!!prefs.data?.[p.key]} disabled={p.disabled || !prefs.data} onChange={(e) => toggle(p.key, e.target.checked)} aria-label={tr(p.title)} />
                <span className="h-6 w-11 rounded-full bg-ink-600 transition peer-checked:bg-honey-deep peer-focus-visible:ring-2 peer-focus-visible:ring-honey" />
                <span className="absolute start-0.5 top-0.5 h-5 w-5 rounded-full bg-white shadow transition peer-checked:translate-x-5 rtl:peer-checked:-translate-x-5" />
              </label>
            </li>
          ))}
        </ul>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={tr("My blocked and trusted list")} subtitle={tr("Trusted contacts are never warned about, even if someone reports them.")}>
          <div className="grid gap-2 sm:grid-cols-[auto_auto_1fr_auto]">
            <select className={inputCls} value={entry.list} onChange={(e) => setEntry({ ...entry, list: e.target.value })} aria-label={tr("List")}><option value="blocked">{tr("Block")}</option><option value="trusted">{tr("Trust")}</option></select>
            <select className={inputCls} value={entry.type} onChange={(e) => setEntry({ ...entry, type: e.target.value })} aria-label={tr("Type")}>{TYPES.slice(0, 3).map((t) => <option key={t.v} value={t.v}>{tr(t.l)}</option>)}</select>
            <input className={inputCls} dir="ltr" value={entry.value} onChange={(e) => setEntry({ ...entry, value: e.target.value })} aria-label={tr("Value")} />
            <Button onClick={addEntry}>{tr("Add")}</Button>
          </div>
          {lists.data?.length ? (
            <ul className="mt-3 divide-y divide-ink-700 text-sm">{lists.data.map((x) => (
              <li key={x.id} className="flex items-center gap-2 py-2">
                {x.list === "blocked" ? <Ban className="h-4 w-4 text-crit" /> : <UserCheck className="h-4 w-4 text-safe" />}
                <span dir="ltr" className="flex-1 text-ink-100">{x.value}</span><Pill>{tr(x.type)}</Pill>
                <button onClick={() => apiSend(`/api/network/lists/${x.id}`, "DELETE").then(() => lists.reload(true))} aria-label={tr("Remove")} className="rounded p-1 text-ink-400 hover:bg-ink-800"><Trash2 className="h-4 w-4" /></button>
              </li>
            ))}</ul>
          ) : <p className="mt-3 text-sm text-ink-400">{tr("Nothing added yet.")}</p>}
        </Card>

        <Card title={<span className="flex items-center gap-2"><Bell className="h-4 w-4" /> {tr("Recent protection events")}</span>}>
          {events.data?.length ? (
            <ul className="divide-y divide-ink-700 text-sm">{events.data.map((e) => (
              <li key={e.id} className="flex items-center gap-2 py-2"><span className={cn("rounded-full px-2 py-0.5 text-xs", e.kind === "blocked" ? "bg-red-50 text-crit" : "bg-amber-50 text-warn")}>{tr(e.kind)}</span>
                <span dir="ltr" className="text-ink-100">{e.indicator}</span><span className="ms-auto text-xs text-ink-400">{timeAgo(e.at)}</span></li>
            ))}</ul>
          ) : <EmptyState title={tr("No warnings or blocks yet")} icon={CheckCircle2}>{tr("Events from your checks and your paired phone appear here.")}</EmptyState>}
        </Card>
      </div>

      <Card title={<span id="mistake" className="flex items-center gap-2"><Flag className="h-4 w-4" /> {tr("Report a mistake")}</span>}
        subtitle={tr("Is your number, email or website wrongly listed? An analyst reviews every request. Unverified warnings are paused while it is reviewed.")}>
        <div className="grid gap-2 sm:grid-cols-[auto_1fr]">
          <select className={inputCls} value={appeal.type} onChange={(e) => setAppeal({ ...appeal, type: e.target.value })} aria-label={tr("Type")}>{TYPES.map((t) => <option key={t.v} value={t.v}>{tr(t.l)}</option>)}</select>
          <input className={inputCls} dir="ltr" value={appeal.value} onChange={(e) => setAppeal({ ...appeal, value: e.target.value })} aria-label={tr("Value")} />
        </div>
        <div className="mt-2"><Label htmlFor="why">{tr("Why is this a mistake?")}</Label><textarea id="why" rows={3} className={inputCls} value={appeal.reason} onChange={(e) => setAppeal({ ...appeal, reason: e.target.value })} /></div>
        <div className="mt-2"><Label htmlFor="ct">{tr("How can we reach you? (optional)")}</Label><input id="ct" className={inputCls} value={appeal.contact} onChange={(e) => setAppeal({ ...appeal, contact: e.target.value })} /></div>
        <Button className="mt-3" variant="primary" onClick={sendAppeal}>{tr("Send for review")}</Button>
        {appealRes && <p className="mt-2 text-sm text-safe">{tr(appealRes)}</p>}
      </Card>
    </div>
  );
}

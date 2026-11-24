"use client";

import { AlertTriangle, BadgeCheck, Flag, Globe2, PhoneIncoming, Search, ShieldQuestion, Smartphone, UserRound } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Turnstile, TURNSTILE_SITE_KEY } from "@/components/Turnstile";
import { Button, Card, cn, ErrorBox, inputCls, Label, PageHeader, Pill, SeverityBadge, timeAgo, useToast } from "@/components/ui";
import { apiGet, apiSend, getMe } from "@/lib/api";
import { tr, trf } from "@/lib/i18n";

const EXAMPLES = [
  { n: "+971 50 123 4567", label: "UAE mobile" },
  { n: "+971 00 000 0101", label: "DEMO: reported number" },
  { n: "+882 123 4567", label: "Satellite network" },
  { n: "+44 20 7946 0000", label: "UK landline" },
];
const TONE: Record<string, string> = {
  CRITICAL: "from-red-700 to-red-900", HIGH: "from-orange-600 to-red-800", MEDIUM: "from-amber-500 to-amber-700", LOW: "from-comb to-ink-950",
};

export default function CallerId() {
  const toast = useToast();
  const [number, setNumber] = useState("");
  const [res, setRes] = useState<any>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cats, setCats] = useState<{ key: string; name: string }[]>([]);
  const [rep, setRep] = useState({ category: "banking", description: "" });
  const [bot, setBot] = useState("");
  const [sending, setSending] = useState(false);
  const investigator = ["analyst", "admin"].includes(getMe()?.role || "");

  useEffect(() => { apiGet("/api/phone/categories").then(setCats).catch(() => {}); }, []);

  const lookup = async (n = number) => {
    if (!n.trim()) return;
    setNumber(n);
    setBusy(true);
    setErr(null);
    try {
      setRes(await apiGet(`/api/phone/lookup?number=${encodeURIComponent(n)}`));
    } catch (e: any) {
      setErr(e.message);
      setRes(null);
    } finally {
      setBusy(false);
    }
  };

  const report = async () => {
    if (TURNSTILE_SITE_KEY && !bot) return toast("err", tr("Please complete the security check first."));
    setSending(true);
    try {
      const r = await apiSend("/api/phone/report", "POST", { number: res.e164, ...rep, turnstile_token: bot || undefined });
      toast("ok", tr(r.message));
      setRep({ ...rep, description: "" });
      lookup(res.e164);
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setSending(false);
    }
  };

  const risk = res?.risk;
  const reasons = (risk?.findings || []).filter((f: any) => f.weight > 0);
  return (
    <div className="space-y-5">
      <PageHeader title={tr("Caller ID")} icon={PhoneIncoming}
        subtitle={tr("Who is calling, where the number is from, and whether people reported it. Only facts we can back up.")} />

      <Card>
        <form className="flex flex-col gap-3 sm:flex-row" onSubmit={(e) => { e.preventDefault(); lookup(); }}>
          <label htmlFor="num" className="sr-only">{tr("Phone number")}</label>
          <input id="num" dir="ltr" className={cn(inputCls, "text-lg tracking-wide")} placeholder="+971 5X XXX XXXX" value={number} onChange={(e) => setNumber(e.target.value)} />
          <Button variant="primary" loading={busy} type="submit"><Search className="h-4 w-4" /> {tr("Look up")}</Button>
        </form>
        <div className="mt-3 flex flex-wrap gap-2 text-xs">
          {EXAMPLES.map((x) => (
            <button key={x.n} onClick={() => lookup(x.n)} className="rounded-full px-3 py-1 text-ink-300 ring-1 ring-ink-600 hover:bg-ink-800">
              <span dir="ltr">{x.n}</span> · {tr(x.label)}
            </button>
          ))}
        </div>
      </Card>

      {err && <ErrorBox error={err} />}

      {res && (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,420px)_1fr]">
          {/* incoming-call style card */}
          <div className={cn("overflow-hidden rounded-3xl bg-gradient-to-b p-6 text-white shadow-lg", TONE[risk.level] || TONE.LOW)} role={risk.risk_score >= 60 ? "alert" : undefined}>
            <div className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-white/70"><PhoneIncoming className="h-4 w-4" /> {tr("Caller identification")}</div>
            <div className="mt-6 flex justify-center">
              <div className="flex h-20 w-20 items-center justify-center rounded-full bg-white/15 text-4xl">{res.flag || <UserRound className="h-10 w-10" />}</div>
            </div>
            <div className="mt-4 text-center text-3xl font-semibold tracking-wide" dir="ltr">{res.international}</div>
            <div className="mt-1 text-center text-white/80">{res.verified_business || tr("Caller name: Unknown")}</div>
            {res.verified_business && <div className="mt-1 flex items-center justify-center gap-1 text-xs text-emerald-200"><BadgeCheck className="h-4 w-4" /> {tr("Verified business")}</div>}
            <div className="mt-5 rounded-2xl bg-black/20 p-4">
              <div className="text-xs uppercase tracking-widest text-white/60">{tr("3B risk assessment")}</div>
              <div className="mt-1 flex items-baseline justify-between">
                <span className="text-2xl font-bold">{tr(risk.level)}</span>
                <span className="text-sm text-white/80">{risk.risk_score}/100</span>
              </div>
              <div className="mt-2 text-sm text-white/90">
                {res.community.distinct_reporters > 0
                  ? trf("{n} community reports", { n: res.community.distinct_reporters }) + (res.community.demo ? " · DEMO" : "")
                  : tr("No community reports")}
                {res.scam_reports > 0 && <> · {trf("{n} scam reports", { n: res.scam_reports })}</>}
              </div>
              {res.last_reported && <div className="mt-1 text-xs text-white/70">{tr("Last reported")} {timeAgo(res.last_reported)}</div>}
              {risk.risk_score >= 30 && <p className="mt-3 text-sm font-medium">{risk.risk_score >= 60
                ? tr("This number has been associated with multiple suspicious activity reports. Be careful when sharing personal information or making payments.")
                : tr("Some warning signs. Don't share codes or personal details; verify the caller through an official number.")}</p>}
            </div>
            <p className="mt-4 text-center text-[11px] text-white/60">{tr("Caller ID can be spoofed. The country shows where the number range is assigned, not where the caller is.")}</p>
          </div>

          <div className="space-y-4">
            <Card title={tr("Number facts")} subtitle={tr(res.source)}>
              <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
                <Fact icon={Globe2} k={tr("Country (number range)")} v={<>{res.flag} {tr(res.country)}</>} />
                <Fact icon={Smartphone} k={tr("Dialling code")} v={<span dir="ltr">{res.dialing_code}</span>} />
                <Fact icon={Smartphone} k={tr("Line type")} v={tr(res.line_type)} />
                <Fact icon={Smartphone} k={tr("Original network (from number range)")} v={res.original_network || tr("Not available")} />
                <Fact icon={UserRound} k={tr("Caller name")} v={<span className="text-ink-400">{res.caller_name_note}</span>} />
                <Fact icon={ShieldQuestion} k={tr("Valid number")} v={res.valid ? tr("Yes") : tr("No — not a valid number in its country's plan")} />
              </dl>
            </Card>

            <Card title={tr("Why this assessment")} action={<SeverityBadge s={risk.severity} />}>
              {reasons.length === 0 ? <p className="text-sm text-ink-300">{tr("No reports or warnings for this number. Unknown does not mean dangerous — and it does not mean safe.")}</p> : (
                <ul className="space-y-2">{reasons.map((f: any, i: number) => (
                  <li key={i} className="text-sm"><div className="font-medium text-ink-100">{f.title}</div><div className="text-xs text-ink-300">{f.detail}</div></li>
                ))}</ul>
              )}
              {Object.keys(res.community.categories || {}).length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1.5">{Object.entries(res.community.categories).map(([k, v]) => <Pill key={k}>{k} · {String(v)}</Pill>)}</div>
              )}
              <p className="mt-3 text-xs text-ink-400">{tr("Confidence:")} {tr(risk.confidence)} · {tr("Reports are claims by users, not proof. One report never blocks a number for everyone.")}</p>
              {risk.recommended_actions?.[0] && risk.risk_score >= 30 && <p className="mt-2 text-sm text-ink-200">{risk.recommended_actions[0]}</p>}
            </Card>

            {investigator && (res.scam_report_refs?.length > 0 || res.related_numbers?.length > 0) && (
              <Card title={tr("For investigators")}>
                {res.scam_report_refs?.length > 0 && <div className="flex flex-wrap gap-1.5">{res.scam_report_refs.map((r: string) => <Link key={r} href={`/reports/${r}`} className="text-xs text-volt hover:underline">{r}</Link>)}</div>}
                {res.related_numbers?.length > 0 && (
                  <ul className="mt-3 space-y-1 text-sm">{res.related_numbers.map((x: any) => <li key={x.number}><span dir="ltr">{x.number}</span> <span className="text-xs text-ink-400">· {x.via.join(", ")} · {x.note}</span></li>)}</ul>
                )}
              </Card>
            )}

            <Card title={<span className="flex items-center gap-2"><Flag className="h-4 w-4" /> {tr("Report this number")}</span>} subtitle={tr("Your report counts once and is reviewed. Your identity is never shown to anyone.")}>
              <div className="grid gap-3 sm:grid-cols-2">
                <div><Label htmlFor="cat">{tr("What happened")}</Label>
                  <select id="cat" className={inputCls} value={rep.category} onChange={(e) => setRep({ ...rep, category: e.target.value })}>
                    {cats.map((c) => <option key={c.key} value={c.key}>{tr(c.name)}</option>)}
                  </select></div>
                <div><Label htmlFor="desc">{tr("Details (optional)")}</Label>
                  <input id="desc" className={inputCls} maxLength={2000} value={rep.description} onChange={(e) => setRep({ ...rep, description: e.target.value })} /></div>
              </div>
              <div className="mt-3"><Turnstile onToken={(t) => setBot(t || "")} /></div>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <Button variant="primary" loading={sending} onClick={report}><AlertTriangle className="h-4 w-4" /> {tr("Send report")}</Button>
                <Link href="/protection#mistake" className="text-xs text-volt hover:underline">{tr("Is this your number and wrongly reported? Tell us")}</Link>
              </div>
            </Card>
          </div>
        </div>
      )}

      <Card title={tr("Automatic caller ID on your phone")}>
        <p className="text-sm text-ink-300">{tr("A website can't see or block your incoming calls. Automatic warnings need the 3B phone app: on iPhone the Call Directory extension labels or blocks numbers from the shared list (synced in advance, no live lookup during the call); on Android a call-screening app can check the number before it rings. See Phone Protection for the companion app.")}</p>
      </Card>
    </div>
  );
}

function Fact({ icon: Icon, k, v }: { icon: any; k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <Icon className="mt-0.5 h-4 w-4 shrink-0 text-ink-400" />
      <div><dt className="text-xs text-ink-400">{k}</dt><dd className="text-ink-100">{v}</dd></div>
    </div>
  );
}

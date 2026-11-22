"use client";

import { AlertTriangle, Inbox, MessageSquare, Phone, PhoneIncoming, PhoneOff, ShieldAlert, Smartphone } from "lucide-react";
import { useState } from "react";
import { broadcastRefresh, Button, Card, cn, ErrorBox, inputCls, Label, PageHeader, SimBadge } from "@/components/ui";
import { apiGet, apiSend } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { useDemoLabels } from "@/lib/prefs";

const SAMPLE_SMS = [
  { sender: "simkukjin@hanmail.net", body: "[Salik] تنبيه عاجل: لا يزال يوجد رصيد رسوم مرور مستحق بقيمة 4.00 درهم تحت حسابك. يرجى السداد قبل الساعة 11:59 مساءً لتجنب غرامة 50 درهماً.\n[Salik] FINAL REMINDER: a toll balance of AED 4.00 is PENDING. Settle before 11:59 PM TODAY to avoid an AED 50.00 fine.\nTo settle, visit: https://salik.ae.ticka.top" },
  { sender: "+491775111338", body: "You MISSED 1 Call(s) from +491775111338, last call: 22 Sep 2026 at 03:44 PM." },
  { sender: "+44 7963 312359", body: "Hey! EMX has parcel AE58374120M ready for delivery today from 14:00 to 18:00, but we noticed your Emirates ID is not updated. Update now to avoid return: http://emx-delivery-update.top" },
  { sender: "AD-SALIK", body: "Your Salik account was recharged with AED 50. Thank you." },
];

type Msg = { sender: string; body: string; res: any };

export default function PhoneProtection() {
  const [sender, setSender] = useState(SAMPLE_SMS[0].sender);
  const [body, setBody] = useState(SAMPLE_SMS[0].body);
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [folder, setFolder] = useState<"inbox" | "junk">("inbox");
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [caller, setCaller] = useState("+882 1234 5678");
  const [call, setCall] = useState<any>(null);

  const deliver = async () => {
    if (!body.trim()) return setErr(tr("Type the message text."));
    setErr(null);
    setBusy("sms");
    try {
      const res = await apiSend("/api/mobile/sms/classify", "POST", { sender, body });
      setMsgs((m) => [{ sender, body, res }, ...m]);
      setFolder(res.action === "junk" ? "junk" : "inbox");
      broadcastRefresh();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(null);
    }
  };

  const ring = async () => {
    setErr(null);
    setBusy("call");
    try {
      setCall(await apiGet(`/api/mobile/caller-check?number=${encodeURIComponent(caller)}`));
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(null);
    }
  };

  const showSim = useDemoLabels();
  const shown = msgs.filter((m) => (folder === "junk") === (m.res.action === "junk"));
  return (
    <div className="space-y-5">
      <PageHeader title={tr("Phone Protection")} icon={Smartphone}
        subtitle={tr("Scam messages go straight to Junk, and calls from risky numbers show a warning before you answer.")}
        actions={<SimBadge label="Simulation of the mobile app" />} />
      {showSim && <div className="rounded-lg border border-ink-700 bg-ink-850 px-3 py-2 text-xs text-ink-300">
        {tr("This page simulates the phone app using the real 3B analysis. On iPhone, Apple only lets an app filter messages from unknown senders (they go to the Junk folder) and label or block numbers before you answer — it cannot read your other messages or listen to phone calls.")}
      </div>}
      {err && <ErrorBox error={err} />}
      <div className="grid gap-6 xl:grid-cols-2">
        <Card title={<span className="flex items-center gap-2"><MessageSquare className="h-4 w-4 text-volt" />{tr("Incoming text message")}</span>}>
          <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
            <div className="space-y-3">
              <div><Label htmlFor="snd">{tr("From")}</Label><input id="snd" dir="ltr" className={inputCls} value={sender} onChange={(e) => setSender(e.target.value)} /></div>
              <div><Label htmlFor="bdy">{tr("Message")}</Label><textarea id="bdy" dir="auto" className={inputCls + " min-h-32"} value={body} onChange={(e) => setBody(e.target.value)} /></div>
              <div className="flex flex-wrap gap-2">
                <Button variant="primary" loading={busy === "sms"} onClick={deliver}>{tr("Receive message")}</Button>
                {SAMPLE_SMS.map((s, i) => <Button key={i} variant="ghost" className="text-xs" onClick={() => { setSender(s.sender); setBody(s.body); }}>{tr("Example")} {i + 1}</Button>)}
              </div>
            </div>
            <div className="mx-auto w-[260px] rounded-[2rem] border-8 border-ink-100 bg-ink-900 p-2 shadow-lg">
              <div className="mb-2 flex rounded-lg bg-ink-800 p-1 text-xs">
                {(["inbox", "junk"] as const).map((f) => (
                  <button key={f} onClick={() => setFolder(f)} className={cn("flex flex-1 items-center justify-center gap-1 rounded-md py-1", folder === f && "bg-ink-900 font-medium shadow-sm")}>
                    {f === "inbox" ? <Inbox className="h-3.5 w-3.5" /> : <ShieldAlert className="h-3.5 w-3.5 text-crit" />}{f === "inbox" ? tr("Messages") : tr("Junk")}
                    <span className="text-ink-400">{msgs.filter((m) => (f === "junk") === (m.res.action === "junk")).length}</span>
                  </button>
                ))}
              </div>
              <div className="h-[340px] space-y-2 overflow-y-auto">
                {shown.length === 0 && <p className="pt-10 text-center text-xs text-ink-400">{tr("No messages")}</p>}
                {shown.map((m, i) => (
                  <div key={i} className={cn("rounded-xl p-2 text-xs", m.res.action === "junk" ? "bg-red-50" : "bg-ink-800")}>
                    <div dir="ltr" className="truncate text-start font-semibold text-ink-100">{m.sender || tr("Unknown")}</div>
                    <div dir="auto" className="line-clamp-3 text-ink-300">{m.body}</div>
                    {m.res.action === "junk" && (
                      <div className="mt-1 border-t border-red-200 pt-1 text-crit">
                        <b>3B · {m.res.risk_score}/100</b> — {m.res.classification}
                        <ul className="mt-0.5 list-disc ps-4 text-ink-300">{m.res.reasons.slice(0, 3).map((r: string) => <li key={r}>{r}</li>)}</ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Card>

        <Card title={<span className="flex items-center gap-2"><PhoneIncoming className="h-4 w-4 text-volt" />{tr("Incoming call")}</span>}>
          <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
            <div className="space-y-3">
              <div><Label htmlFor="cl">{tr("Caller's number")}</Label><input id="cl" dir="ltr" className={inputCls} value={caller} onChange={(e) => setCaller(e.target.value)} /></div>
              <div className="flex flex-wrap gap-2">
                <Button variant="primary" loading={busy === "call"} onClick={ring}><Phone className="h-4 w-4" />{tr("Try an incoming call")}</Button>
                {["+882 1234 5678", "+44 7399 367678", "+49 177 5111338", "050 123 4567"].map((n) => <Button key={n} variant="ghost" className="text-xs" onClick={() => setCaller(n)}><span dir="ltr">{n}</span></Button>)}
              </div>
              <p className="text-xs text-ink-400">{tr("The warning is based on the number only (registration country, satellite ranges, 3B scam reports). To analyse what the caller says, use Call Guard with the call on speaker.")}</p>
            </div>
            <div className="mx-auto flex h-[420px] w-[260px] flex-col items-center rounded-[2rem] border-8 border-ink-100 bg-gradient-to-b from-slate-700 to-slate-900 p-4 text-white shadow-lg">
              {call ? (
                <>
                  {call.warn && (
                    <div className={cn("mb-3 w-full rounded-xl p-2 text-center text-xs", call.level === "danger" ? "bg-red-600" : "bg-amber-500")}>
                      <AlertTriangle className="mx-auto mb-1 h-5 w-5" />
                      <div className="font-semibold">{call.label}</div>
                      <div className="mt-1 opacity-90">{call.reasons.slice(0, 2).join(" · ")}</div>
                    </div>
                  )}
                  <div className="mt-4 text-sm opacity-80">{tr(call.registered_region || "")}</div>
                  <div dir="ltr" className="mt-1 text-2xl font-light">{call.number}</div>
                  {call.warn && <p className="mt-3 text-center text-[11px] leading-snug opacity-90">{call.advice}</p>}
                  <div className="mt-auto flex w-full justify-around">
                    <button onClick={() => setCall(null)} className="flex h-14 w-14 items-center justify-center rounded-full bg-red-500" aria-label={tr("Decline")}><PhoneOff /></button>
                    <button onClick={() => setCall(null)} className="flex h-14 w-14 items-center justify-center rounded-full bg-green-500" aria-label={tr("Answer")}><Phone /></button>
                  </div>
                  <p className="mt-2 text-[10px] opacity-60">{call.note}</p>
                </>
              ) : <p className="m-auto text-center text-xs opacity-70">{tr("Press “Try an incoming call”")}</p>}
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

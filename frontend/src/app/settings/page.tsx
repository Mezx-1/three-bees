"use client";

import { Download, KeyRound, PlugZap, RotateCcw, Settings as Gear, Users } from "lucide-react";
import { useEffect, useState } from "react";
import { DemoScenario } from "@/components/DemoScenario";
import { broadcastRefresh, Button, Card, fmtTime, ErrorBox, inputCls, Label, PageHeader, Pill, ScanBar, useApi, useToast } from "@/components/ui";
import { API_URL, apiGet, apiSend } from "@/lib/api";
import { tr, trf, useI18n } from "@/lib/i18n";
import { setDemoLabels, setSimpleMode, useDemoLabels, useSimpleMode } from "@/lib/prefs";

function Toggle({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string }) {
  return (
    <button role="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange(!checked)}
      className={"relative h-6 w-11 rounded-full transition disabled:opacity-40 " + (checked ? "bg-honey-deep" : "bg-ink-600")}>
      <span className={"absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all " + (checked ? "start-[22px]" : "start-0.5")} />
    </button>
  );
}

export default function SettingsPage() {
  const { t, lang, setLang } = useI18n();
  const toast = useToast();
  const st = useApi<any>(() => apiGet("/api/settings"), []);
  const sys = useApi<any>(() => apiGet("/api/system/status"), []);
  const meQ = useApi<any>(() => apiGet("/api/auth/me"), []);
  const [pw, setPw] = useState({ current: "", next: "" });
  const [pair, setPair] = useState<{ code: string; purpose: string; expires_at: string } | null>(null);
  const [threshold, setThreshold] = useState(60);
  const [busy, setBusy] = useState<string | null>(null);
  const demoLabels = useDemoLabels();
  const simple = useSimpleMode();
  useEffect(() => { if (st.data) setThreshold(st.data.auto_incident_threshold); }, [st.data]);
  const role = meQ.data?.role;
  const isAnalyst = role === "admin" || role === "analyst";

  const changePassword = async () => {
    if (pw.next.length < 10) return toast("err", tr("The new password must be at least 10 characters."));
    setBusy("pw");
    try {
      await apiSend("/api/auth/password", "POST", { current_password: pw.current, new_password: pw.next });
      setPw({ current: "", next: "" });
      toast("ok", tr("Password changed."));
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };

  const makeCode = async (purpose: "phone" | "agent") => {
    setBusy("pair-" + purpose);
    try {
      setPair(await apiSend("/api/pairing-codes", "POST", { purpose }));
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };
  const isAdmin = role === "admin";

  const put = async (k: string, body: any) => {
    setBusy(k);
    try {
      st.setData(await apiSend("/api/settings", "PUT", body));
      sys.reload(true);
      toast("ok", "Settings saved.");
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };

  const s = sys.data;
  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_settings")} subtitle={tr("Identity, analysis engine, integrations and demo environment")} icon={Gear} />
      <div className="grid gap-5 xl:grid-cols-2">
        <div className="space-y-5">
          <Card title={<span className="flex items-center gap-2"><Users className="h-4 w-4 text-volt" /> {tr("My account")}</span>}>
            {!meQ.data ? <ScanBar /> : (
              <div className="space-y-3 text-sm">
                <div className="flex items-center gap-3"><div className="flex-1"><div className="text-ink-100">{meQ.data.full_name}</div><div className="text-xs text-ink-400" dir="ltr">{meQ.data.username} · {meQ.data.email}</div></div><Pill>{tr(meQ.data.role)}</Pill></div>
                <div className="grid gap-2 sm:grid-cols-2">
                  <input type="password" dir="ltr" autoComplete="current-password" className={inputCls} placeholder={tr("Current password")} value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} />
                  <input type="password" dir="ltr" autoComplete="new-password" className={inputCls} placeholder={tr("New password (10+ characters)")} value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
                </div>
                <Button className="text-xs" loading={busy === "pw"} disabled={!pw.current || !pw.next} onClick={changePassword}>{tr("Change password")}</Button>
                <p className="text-xs text-ink-400">{tr("Employees can submit and report. Analysts can quarantine, block, manage incidents and endpoints. Admins can change settings and reset the demo.")}</p>
              </div>
            )}
          </Card>
          <Card title={tr("Display")}>
            <div className="flex items-start justify-between gap-4 text-sm">
              <div>
                <div className="font-medium text-ink-100">{tr("Show demo-data labels")}</div>
                <p className="mt-0.5 text-xs text-ink-400">{tr("Marks seeded devices and demo events as simulated. Off by default for presentations; the data stays flagged in the system either way.")}</p>
              </div>
              <Toggle checked={demoLabels} onChange={setDemoLabels} label={tr("Show demo-data labels")} />
            </div>
            <div className="mt-4 flex items-start justify-between gap-4 border-t border-ink-700 pt-4 text-sm">
              <div>
                <div className="font-medium text-ink-100">{tr("Simple mode")}</div>
                <p className="mt-0.5 text-xs text-ink-400">{tr("Bigger text and one clear answer for each check, with a button that reads it aloud. Good for older family members.")}</p>
              </div>
              <Toggle checked={simple} onChange={setSimpleMode} label={tr("Simple mode")} />
            </div>
          </Card>
          <Card title={tr("Pair a device")} subtitle={tr("One-time code for the 3B iPhone app or a laptop agent. Valid for 15 minutes.")}>
            {!isAnalyst ? <p className="text-sm text-ink-400">{tr("Ask an analyst or admin to create a pairing code.")}</p> : (
              <div className="space-y-3">
                <div className="flex flex-wrap gap-2">
                  <Button loading={busy === "pair-phone"} onClick={() => makeCode("phone")}>{tr("Code for an iPhone")}</Button>
                  <Button loading={busy === "pair-agent"} onClick={() => makeCode("agent")}>{tr("Code for a laptop agent")}</Button>
                </div>
                {pair && (
                  <div className="rounded-xl border border-honey/40 bg-wax p-4 text-center">
                    <div className="text-xs text-ink-400">{pair.purpose === "phone" ? tr("Enter this code in the iPhone app → Settings") : tr("Run: python agent/threeb_agent.py --pair CODE --consent")}</div>
                    <div dir="ltr" className="my-2 font-mono text-4xl font-bold tracking-[0.3em] text-volt">{pair.code}</div>
                    <div className="text-xs text-ink-400">{tr("Expires")} {fmtTime(pair.expires_at)} · {tr("can be used once")}</div>
                  </div>
                )}
              </div>
            )}
          </Card>
        </div>

        <Card title={tr("Analysis engine")} subtitle={isAdmin ? tr("Admin") : tr("Read-only — switch to an admin user to change")}>
          {st.error ? <ErrorBox error={st.error} /> : !st.data || !s ? <ScanBar /> : (
            <div className="space-y-4 text-sm">
              <div className="flex items-center justify-between gap-4">
                <div><div className="text-ink-100">{tr("AI analysis (Claude)")}</div><div className="text-xs text-ink-400">{s.ai.available ? `Model ${s.ai.model}` : s.ai.reason}</div></div>
                <Toggle label={tr("AI analysis")} checked={st.data.ai_enabled} disabled={!isAdmin || busy === "ai"} onChange={(v) => put("ai", { ai_enabled: v })} />
              </div>
              {!s.ai.available && !s.ai.model && (
                <div className="flex gap-2 rounded-lg bg-ink-850 p-2.5 text-xs text-ink-300"><KeyRound className="h-4 w-4 shrink-0 text-warn" /><span>{tr("Set ANTHROPIC_API_KEY in backend/.env and restart the backend. Keys are never stored in the browser.")}</span></div>
              )}
              <div className="flex items-center justify-between gap-4">
                <div><div className="text-ink-100">{tr("External lookups")}</div><div className="text-xs text-ink-400">{tr("DNS resolution and IP geolocation (ip-api.com). Sends the looked-up indicator to those services.")}</div></div>
                <Toggle label={tr("External lookups")} checked={st.data.external_lookups} disabled={!isAdmin || busy === "ext"} onChange={(v) => {
                  if (v && !window.confirm(tr("Turn on external lookups?\n\nWhat is sent: public IP addresses seen on monitored devices and in analyses go to ip-api.com (over plain HTTP — the free tier has no HTTPS); domains in analysed links go to your DNS server.\nNever sent: private/LAN addresses, message or email contents, files, names.\nWhy: to show the approximate country, city and network owner of connections.\n\nYour name and the time of consent will be recorded."))) return;
                  put("ext", v ? { external_lookups: true, consent_acknowledged: true } : { external_lookups: false });
                }} />
              </div>
              <p className="-mt-2 text-xs text-ink-400">{st.data.external_lookups_consent ? trf("Enabled with consent by {by} on {at}.", { by: st.data.external_lookups_consent.by, at: fmtTime(st.data.external_lookups_consent.at) }) : tr("Off by default for privacy. Nothing is sent to outside services.")}</p>
              <div>
                <Label htmlFor="th">{tr("Auto-incident threshold (risk score)")}</Label>
                <div className="flex items-center gap-3">
                  <input id="th" type="range" min={30} max={95} value={threshold} disabled={!isAdmin} onChange={(e) => setThreshold(+e.target.value)} className="flex-1 accent-amber-600" />
                  <span className="w-10 font-mono">{threshold}</span>
                  <Button className="h-8 text-xs" disabled={!isAdmin || threshold === st.data.auto_incident_threshold} loading={busy === "th"} onClick={() => put("th", { auto_incident_threshold: threshold })}>{tr("Save")}</Button>
                </div>
              </div>
              <div className="flex items-center justify-between gap-4">
                <div><div className="text-ink-100">{tr("Language")}</div><div className="text-xs text-ink-400">{tr("Arabic switches the layout to RTL. Navigation and key labels are translated; detailed reports remain English in the MVP.")}</div></div>
                <select className={inputCls + " !w-auto"} value={lang} onChange={(e) => setLang(e.target.value as any)}><option value="en">{tr("English")}</option><option value="ar">العربية</option></select>
              </div>
            </div>
          )}
        </Card>

        <Card title={<span className="flex items-center gap-2"><PlugZap className="h-4 w-4 text-volt" /> {tr("Integrations & providers")}</span>}>
          {!s ? <ScanBar /> : (
            <div className="space-y-3 text-sm">
              {[
                ["Microsoft 365 (Graph API)", s.integrations.microsoft_365],
                ["Google Workspace (Gmail API)", s.integrations.google_workspace],
                ["EDR / network isolation", s.integrations.edr_network_isolation],
              ].map(([n, v]: any) => (
                <div key={n} className="flex items-start justify-between gap-3"><div><div className="text-ink-100">{n}</div><div className="text-xs text-ink-400">{v.note}</div></div><Pill className="text-ink-300">{tr("not connected")}</Pill></div>
              ))}
              <hr className="border-ink-700" />
              {Object.entries(s.providers).map(([k, v]: any) => (
                <div key={k} className="flex items-start justify-between gap-3"><div><div className="capitalize text-ink-100">{k}</div>{v.note && <div className="text-xs text-ink-400">{v.note}</div>}</div>
                  <Pill className={v.configured ? "text-safe" : "text-ink-400"}>{v.configured ? "configured" : "not configured"}</Pill></div>
              ))}
              <div className="flex items-start justify-between gap-3"><div><div className="text-ink-100">{tr("Malware sandbox")}</div><div className="text-xs text-ink-400">{s.sandbox.note}</div></div><Pill>{tr("planned")}</Pill></div>
              <p className="text-[11px] text-ink-500">{tr("Backend:")} <span className="font-mono">{API_URL}</span> · {tr("OCR:")} {s.ocr.engine} · ffmpeg: {String(s.media.ffmpeg)} · upload limit {s.max_upload_mb} {tr("MB")}</p>
            </div>
          )}
        </Card>

        <div className="space-y-5">
          <DemoScenario />
          <Card title={tr("Demo environment")}>
            <div className="flex flex-wrap gap-2">
              {["phishing-ceo-fraud.eml", "legitimate-hr.eml", "mailbox-lure.png", "Invoice_Q4_2026.pdf"].map((n) => (
                <a key={n} href={`${API_URL}/api/demo/samples/${n}`} className="inline-flex items-center gap-1.5 rounded-lg bg-ink-700/70 px-3 py-2 text-xs ring-1 ring-ink-600 hover:bg-ink-600"><Download className="h-3.5 w-3.5" /> {n}</a>
              ))}
            </div>
            <p className="mt-2 text-xs text-ink-400">{tr("All samples are harmless test files generated by 3B (the “invoice” is a ZIP containing a comment-only .js file).")}</p>
            <div className="mt-4 border-t border-ink-700 pt-4">
              <Button variant="danger" disabled={!isAdmin} loading={busy === "reset"} onClick={async () => {
                if (!window.confirm(tr("Reset the demo environment? All analyses, incidents, events, blocklist and audit logs will be deleted."))) return;
                setBusy("reset");
                try { const r = await apiSend("/api/demo/reset", "POST"); toast("ok", r.message); broadcastRefresh(); } catch (e: any) { toast("err", e.message); } finally { setBusy(null); }
              }}><RotateCcw className="h-4 w-4" /> {tr("Reset demo environment")}</Button>
              {!isAdmin && <p className="mt-1 text-xs text-ink-500">{tr("Admin only.")}</p>}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

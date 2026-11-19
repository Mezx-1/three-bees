"use client";

import { Download, KeyRound, PlugZap, RotateCcw, Settings as Gear, Users } from "lucide-react";
import { useEffect, useState } from "react";
import { DemoScenario } from "@/components/DemoScenario";
import { broadcastRefresh, Button, Card, fmtTime, ErrorBox, inputCls, Label, PageHeader, Pill, ScanBar, useApi, useToast } from "@/components/ui";
import { API_URL, apiGet, apiSend, getUser, setUser } from "@/lib/api";
import { tr, trf, useI18n } from "@/lib/i18n";

function Toggle({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string }) {
  return (
    <button role="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange(!checked)}
      className={"relative h-6 w-11 rounded-full transition disabled:opacity-40 " + (checked ? "bg-volt" : "bg-ink-600")}>
      <span className={"absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all " + (checked ? "start-[22px]" : "start-0.5")} />
    </button>
  );
}

export default function SettingsPage() {
  const { t, lang, setLang } = useI18n();
  const toast = useToast();
  const st = useApi<any>(() => apiGet("/api/settings"), []);
  const sys = useApi<any>(() => apiGet("/api/system/status"), []);
  const users = useApi<any[]>(() => apiGet("/api/users"), []);
  const [me, setMe] = useState("");
  const [threshold, setThreshold] = useState(60);
  const [busy, setBusy] = useState<string | null>(null);
  useEffect(() => setMe(getUser()), []);
  useEffect(() => { if (st.data) setThreshold(st.data.auto_incident_threshold); }, [st.data]);
  const role = users.data?.find((u) => u.username === me)?.role;
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
        <Card title={<span className="flex items-center gap-2"><Users className="h-4 w-4 text-volt" /> {tr("Identity & roles")}</span>} subtitle={tr("MVP identity: pick a seeded user. Roles are enforced by the backend. SSO (Entra ID) is planned.")}>
          {!users.data ? <ScanBar /> : (
            <ul className="space-y-2">
              {users.data.map((u) => (
                <li key={u.username} className="flex items-center gap-3 rounded-lg border border-ink-700 bg-ink-850/60 p-2.5 text-sm">
                  <div className="flex-1"><div className="text-ink-100">{u.full_name}</div><div className="text-xs text-ink-400">{u.email}</div></div>
                  <Pill className="uppercase">{u.role}</Pill>
                  <Button variant={me === u.username ? "primary" : "subtle"} className="h-8 text-xs" onClick={() => { setMe(u.username); setUser(u.username); broadcastRefresh(); toast("info", `Now acting as ${u.full_name} (${u.role}).`); }}>
                    {me === u.username ? tr("Active") : tr("Use")}
                  </Button>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 text-xs text-ink-400">{tr("Employees can submit and report. Analysts can quarantine, block, manage incidents and endpoints. Admins can change settings and reset the demo.")}</p>
        </Card>

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
                  <input id="th" type="range" min={30} max={95} value={threshold} disabled={!isAdmin} onChange={(e) => setThreshold(+e.target.value)} className="flex-1 accent-blue-600" />
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
            <p className="mt-2 text-xs text-ink-400">{tr("All samples are harmless test files generated by WOLVE (the “invoice” is a ZIP containing a comment-only .js file).")}</p>
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

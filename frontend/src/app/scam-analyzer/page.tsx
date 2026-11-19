"use client";

import { Globe2, Link2, MessageSquareWarning, Phone, ShieldAlert, Sparkles, Upload } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { AnalysisActions } from "@/components/AnalysisActions";
import { FileDrop } from "@/components/FileDrop";
import { ReportView } from "@/components/ReportView";
import { broadcastRefresh, Button, Card, ErrorBox, inputCls, Label, PageHeader, ScanBar, SeverityBadge, Tabs, timeAgo, useApi } from "@/components/ui";
import { apiGet, apiSend, apiUpload } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import type { Analysis } from "@/lib/types";

type Mode = "auto" | "message" | "url" | "phone" | "ip" | "file";
const CHANNELS = [
  { v: "sms", l: "SMS" }, { v: "whatsapp", l: "WhatsApp" }, { v: "chat", l: "Chat / social" }, { v: "email", l: "Email (text or source)" }, { v: "call", l: "Call transcript" }, { v: "message", l: "Other" },
];

export default function ScamAnalyzer() {
  const { t } = useI18n();
  const [mode, setMode] = useState<Mode>("auto");
  const [text, setText] = useState("");
  const [channel, setChannel] = useState("sms");
  const [file, setFile] = useState<File | null>(null);
  const [transcript, setTranscript] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<Analysis | null>(null);
  const [samples, setSamples] = useState<any[]>([]);
  const history = useApi<Analysis[]>(() => apiGet("/api/analyses?kind=message,phone,url,ip,domain&limit=12"), []);

  useEffect(() => { apiGet("/api/demo/samples").then((s) => setSamples(s.messages)).catch(() => {}); }, []);

  const validate = (): string | null => {
    if (mode === "file") return file ? null : "Choose a file to analyse.";
    const v = text.trim();
    if (!v) return "Enter something to analyse.";
    if (v.length > 100000) return "Input is too long (max 100,000 characters).";
    if (mode === "url" && !/\./.test(v)) return "Enter a valid URL or domain.";
    if (mode === "ip" && !/^[0-9a-fA-F:.[\]]+$/.test(v)) return "Enter a valid IPv4 or IPv6 address.";
    if (mode === "phone" && !/^[+\d][\d\s()-]{5,20}$/.test(v)) return "Enter a phone number with digits only (and optional +country code).";
    return null;
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const v = validate();
    if (v) { setErr(v); return; }
    setErr(null);
    setBusy(true);
    setResult(null);
    try {
      let r: Analysis;
      if (mode === "file") {
        const fd = new FormData();
        fd.append("file", file!);
        if (transcript.trim()) fd.append("transcript", transcript);
        r = await apiUpload("/api/analyze/file", fd);
      } else if (mode === "auto") r = await apiSend("/api/analyze/auto", "POST", { text, channel });
      else if (mode === "message") r = await apiSend("/api/analyze/message", "POST", { text, channel });
      else r = await apiSend(`/api/analyze/${mode}`, "POST", { value: text.trim() });
      setResult(r);
      history.reload(true);
      broadcastRefresh();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const placeholder: Record<Mode, string> = {
    auto: "Paste anything: a suspicious SMS, WhatsApp chat, email, URL, phone number or IP address…",
    message: "Paste the message or conversation text…",
    url: "https://example-login-verify.top/account",
    phone: "+971 50 123 4567",
    ip: "203.0.113.45",
    file: "",
  };

  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_scam")} subtitle="Universal threat analysis for messages, links, numbers, IPs, screenshots, recordings and documents" icon={ShieldAlert} />
      <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
        <Card>
          <form onSubmit={submit} className="space-y-4" noValidate>
            <Tabs value={mode} onChange={(m) => { setMode(m); setErr(null); }} items={[
              { value: "auto", label: <span className="flex items-center gap-1.5"><Sparkles className="h-3.5 w-3.5" />Auto-detect</span> },
              { value: "message", label: <span className="flex items-center gap-1.5"><MessageSquareWarning className="h-3.5 w-3.5" />Message</span> },
              { value: "url", label: <span className="flex items-center gap-1.5"><Link2 className="h-3.5 w-3.5" />URL</span> },
              { value: "phone", label: <span className="flex items-center gap-1.5"><Phone className="h-3.5 w-3.5" />Phone</span> },
              { value: "ip", label: <span className="flex items-center gap-1.5"><Globe2 className="h-3.5 w-3.5" />IP</span> },
              { value: "file", label: <span className="flex items-center gap-1.5"><Upload className="h-3.5 w-3.5" />Screenshot / audio / video / file</span> },
            ]} />
            {mode === "file" ? (
              <div className="space-y-3">
                <FileDrop file={file} onFile={setFile} hint="Screenshots, images, audio (mp3/wav/m4a), video (mp4/mov), documents, archives — max 25 MB, analysed statically" />
                <div>
                  <Label htmlFor="tr">Call / audio transcript (optional)</Label>
                  <textarea id="tr" className={inputCls + " min-h-20"} value={transcript} onChange={(e) => setTranscript(e.target.value)}
                    placeholder="Speech-to-text is not installed in this deployment — paste what was said to analyse the conversation." />
                </div>
              </div>
            ) : (
              <>
                {(mode === "auto" || mode === "message") && (
                  <div className="flex flex-wrap items-center gap-3">
                    <Label htmlFor="ch">Channel</Label>
                    <select id="ch" value={channel} onChange={(e) => setChannel(e.target.value)} className={inputCls + " !w-auto"}>
                      {CHANNELS.map((c) => <option key={c.v} value={c.v}>{c.l}</option>)}
                    </select>
                  </div>
                )}
                {mode === "auto" || mode === "message" ? (
                  <textarea aria-label="Content to analyse" dir="auto" className={inputCls + " min-h-44 font-mono text-[13px]"} placeholder={placeholder[mode]} value={text} onChange={(e) => setText(e.target.value)} />
                ) : (
                  <input aria-label="Value to analyse" dir="ltr" className={inputCls + " font-mono"} placeholder={placeholder[mode]} value={text} onChange={(e) => setText(e.target.value)} />
                )}
              </>
            )}
            {err && <ErrorBox error={err} />}
            <div className="flex flex-wrap items-center gap-3">
              <Button type="submit" variant="primary" loading={busy}>{busy ? t("analyzing") : t("analyze")}</Button>
              <span className="text-xs text-ink-400">Deterministic checks always run · AI explains when available · nothing you submit is executed or opened</span>
            </div>
            {busy && <ScanBar />}
          </form>
        </Card>
        <Card title="Try a sample" subtitle="Realistic UAE-context scam messages (fictional)">
          <ul className="space-y-2">
            {samples.map((s) => (
              <li key={s.key}>
                <button onClick={() => { setMode("message"); setChannel(s.channel); setText(s.text); setResult(null); }}
                  className="w-full rounded-lg border border-ink-700 bg-ink-850/60 p-2.5 text-start text-xs hover:border-volt/50">
                  <span className="mb-1 block text-[10px] font-semibold uppercase tracking-wider text-volt">{s.channel}</span>
                  <span dir="auto" className="line-clamp-2 text-ink-200">{s.text}</span>
                </button>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      {result && <ReportView a={result} actions={<AnalysisActions a={result} onChange={setResult} />} />}

      <Card title="Recent analyses">
        {history.error ? <ErrorBox error={history.error} /> : (history.data?.length ?? 0) === 0 ? <p className="text-sm text-ink-400">None yet.</p> : (
          <ul className="divide-y divide-ink-800">
            {history.data!.map((a) => (
              <li key={a.id} className="flex items-center gap-3 py-2 text-sm">
                <SeverityBadge s={a.severity} />
                <span className="w-14 shrink-0 text-xs capitalize text-ink-400">{a.kind}</span>
                <Link href={`/analyses/${a.id}`} className="min-w-0 flex-1 truncate text-ink-100 hover:text-volt" dir="auto">{a.title}</Link>
                <span className="font-mono text-xs text-ink-300">{a.risk_score}</span>
                <span className="w-16 text-end text-xs text-ink-400">{timeAgo(a.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

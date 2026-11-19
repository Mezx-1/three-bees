"use client";

import { Paperclip, ShieldAlert, X } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { AnalysisActions } from "@/components/AnalysisActions";
import { ReportView } from "@/components/ReportView";
import { broadcastRefresh, Button, Card, ErrorBox, inputCls, Label, PageHeader, ScanBar, SeverityBadge, timeAgo, useApi } from "@/components/ui";
import { apiGet, apiSend, apiUpload } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import type { Analysis } from "@/lib/types";

const CHANNELS = [
  { v: "message", l: "Not sure / other" }, { v: "sms", l: "SMS" }, { v: "whatsapp", l: "WhatsApp" }, { v: "chat", l: "Social media / chat" },
  { v: "email", l: "Email" }, { v: "call", l: "Phone call (what they said)" },
];
const MAX_MB = 25;

export default function ScamAnalyzer() {
  const { t } = useI18n();
  const [text, setText] = useState("");
  const [channel, setChannel] = useState("message");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<Analysis | null>(null);
  const [samples, setSamples] = useState<any[]>([]);
  const fileRef = useRef<HTMLInputElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const history = useApi<Analysis[]>(() => apiGet("/api/analyses?kind=message,phone,url,ip,domain,image,file,audio,video&limit=10"), []);

  useEffect(() => { apiGet("/api/demo/samples").then((s) => setSamples(s.messages)).catch(() => {}); }, []);

  const pickFile = (f?: File | null) => {
    if (!f) return;
    if (f.size > MAX_MB * 1024 * 1024) return setErr(`That file is larger than ${MAX_MB} MB.`);
    if (f.size === 0) return setErr("That file is empty.");
    setErr(null);
    setFile(f);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const v = text.trim();
    if (!v && !file) return setErr("Paste something or attach a file first.");
    if (v.length > 100000) return setErr("That text is too long (max 100,000 characters).");
    setErr(null);
    setBusy(true);
    setResult(null);
    try {
      let r: Analysis;
      if (file) {
        const fd = new FormData();
        fd.append("file", file);
        const isMedia = /^(audio|video)\//.test(file.type) || /\.(mp3|wav|m4a|ogg|opus|mp4|mov|webm|amr)$/i.test(file.name);
        if (v) fd.append(isMedia ? "transcript" : "note", v);
        r = await apiUpload("/api/analyze/file", fd);
      } else {
        r = await apiSend("/api/analyze/auto", "POST", { text: v, channel });
      }
      setResult(r);
      history.reload(true);
      broadcastRefresh();
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader title={t("nav_scam")} subtitle="Not sure if something is a scam? Paste it here or attach a screenshot, recording or file." icon={ShieldAlert} />
      <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
        <Card>
          <form onSubmit={submit} className="space-y-4" noValidate>
            <div>
              <Label htmlFor="content">What did you receive?</Label>
              <textarea id="content" dir="auto" className={inputCls + " min-h-40 text-[15px]"} value={text} onChange={(e) => setText(e.target.value)}
                placeholder={file ? "Optional: add context, or what was said in the recording…" : "Paste a message, email, link, phone number or IP address…"} />
            </div>

            <div className="flex flex-wrap items-center gap-3">
              {file ? (
                <span className="inline-flex items-center gap-2 rounded-lg bg-ink-800 px-3 py-2 text-sm text-ink-200">
                  <Paperclip className="h-4 w-4 text-ink-400" /> {file.name} <span className="text-ink-400">({(file.size / 1024).toFixed(0)} KB)</span>
                  <button type="button" aria-label="Remove file" onClick={() => { setFile(null); if (fileRef.current) fileRef.current.value = ""; }} className="rounded p-0.5 hover:bg-ink-700"><X className="h-4 w-4" /></button>
                </span>
              ) : (
                <Button type="button" onClick={() => fileRef.current?.click()}><Paperclip className="h-4 w-4" /> Attach screenshot, recording or file</Button>
              )}
              <input ref={fileRef} type="file" className="hidden" onChange={(e) => pickFile(e.target.files?.[0])} />
              {!file && (
                <label className="flex items-center gap-2 text-sm text-ink-400">
                  Where did it come from?
                  <select value={channel} onChange={(e) => setChannel(e.target.value)} className={inputCls + " !w-auto !py-1.5"}>
                    {CHANNELS.map((c) => <option key={c.v} value={c.v}>{c.l}</option>)}
                  </select>
                </label>
              )}
            </div>

            {err && <ErrorBox error={err} />}
            <div className="flex flex-wrap items-center gap-3">
              <Button type="submit" variant="primary" className="px-6 py-2.5 text-base" loading={busy}>{busy ? "Checking…" : "Check it"}</Button>
              <span className="text-xs text-ink-400">Nothing you submit is opened or run. Files up to {MAX_MB} MB.</span>
            </div>
            {busy && <ScanBar />}
          </form>
        </Card>
        <Card title="Try an example" subtitle="Fictional scam messages">
          <ul className="space-y-2">
            {samples.map((s) => (
              <li key={s.key}>
                <button onClick={() => { setFile(null); setChannel(s.channel); setText(s.text); setResult(null); setErr(null); }}
                  className="w-full rounded-lg border border-ink-700 p-3 text-start text-sm hover:border-volt hover:bg-blue-50/40">
                  <span className="mb-1 block text-xs font-medium capitalize text-volt">{s.channel === "call" ? "Phone call" : s.channel}</span>
                  <span dir="auto" className="line-clamp-2 text-ink-300">{s.text}</span>
                </button>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div ref={resultRef}>{result && <ReportView a={result} actions={<AnalysisActions a={result} onChange={setResult} />} />}</div>

      <Card title="Recently checked">
        {history.error ? <ErrorBox error={history.error} /> : (history.data?.length ?? 0) === 0 ? <p className="text-sm text-ink-400">Nothing checked yet.</p> : (
          <ul className="divide-y divide-ink-700">
            {history.data!.map((a) => (
              <li key={a.id}>
                <Link href={`/analyses/${a.id}`} className="flex items-center gap-3 py-2.5 text-sm hover:bg-ink-850">
                  <SeverityBadge s={a.severity} />
                  <span className="min-w-0 flex-1 truncate text-ink-200" dir="auto">{a.title}</span>
                  <span className="text-xs text-ink-400">{timeAgo(a.created_at)}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

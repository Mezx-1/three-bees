"use client";

import { Check, FileSearch, Minus, X } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { AnalysisActions } from "@/components/AnalysisActions";
import { FileDrop } from "@/components/FileDrop";
import { ReportView } from "@/components/ReportView";
import { broadcastRefresh, Button, Card, ErrorBox, inputCls, Label, PageHeader, Pill, ScanBar, SeverityBadge, timeAgo, useApi } from "@/components/ui";
import { apiGet, apiUpload, fetchSampleFile } from "@/lib/api";
import { useI18n, tr } from "@/lib/i18n";
import type { Analysis } from "@/lib/types";

function Cap({ ok, label, note }: { ok: boolean | null; label: string; note?: string }) {
  return (
    <li className="flex items-start gap-2 text-xs">
      {ok === true ? <Check className="h-4 w-4 shrink-0 text-safe" /> : ok === false ? <X className="h-4 w-4 shrink-0 text-crit" /> : <Minus className="h-4 w-4 shrink-0 text-ink-400" />}
      <span><span className="text-ink-100">{tr(label)}</span>{note && <span className="block text-ink-400">{tr(note)}</span>}</span>
    </li>
  );
}

export default function Forensics() {
  const { t } = useI18n();
  const [file, setFile] = useState<File | null>(null);
  const [transcript, setTranscript] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<Analysis | null>(null);
  const sys = useApi<any>(() => apiGet("/api/system/status"), []);
  const hist = useApi<Analysis[]>(() => apiGet("/api/analyses?kind=file,image,audio,video&limit=15"), []);

  const submit = async () => {
    if (!file) return setErr("Choose a file first.");
    setErr(null);
    setBusy(true);
    setResult(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      if (transcript.trim()) fd.append("transcript", transcript);
      if (note.trim()) fd.append("note", note);
      const r = await apiUpload<Analysis>("/api/analyze/file", fd);
      setResult(r);
      hist.reload(true);
      broadcastRefresh();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const s = sys.data;
  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_forensics")} subtitle={tr("Signature, MIME, archive, macro, PDF, metadata, QR and OCR inspection — plus audio/video metadata and frame analysis")} icon={FileSearch} />
      <div className="grid gap-5 xl:grid-cols-[1fr_320px]">
        <Card title={tr("Upload for inspection")}>
          <div className="space-y-3">
            <FileDrop file={file} onFile={setFile} />
            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <Label htmlFor="tr">{tr("Transcript (audio/video, optional)")}</Label>
                <textarea id="tr" className={inputCls + " min-h-20"} value={transcript} onChange={(e) => setTranscript(e.target.value)} placeholder={tr("What was said in the recording…")} />
              </div>
              <div>
                <Label htmlFor="nt">{tr("Context note (optional)")}</Label>
                <textarea id="nt" className={inputCls + " min-h-20"} value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} placeholder={tr("e.g. Received via WhatsApp from unknown number")} />
              </div>
            </div>
            {err && <ErrorBox error={err} />}
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="primary" loading={busy} onClick={submit}>{busy ? t("analyzing") : tr("Inspect file")}</Button>
              <span className="text-xs text-ink-400">{tr("Samples:")}</span>
              <Button variant="ghost" className="text-xs" onClick={() => fetchSampleFile("mailbox-lure.png").then(setFile).catch((e) => setErr(e.message))}>{tr("Lure image with QR")}</Button>
              <Button variant="ghost" className="text-xs" onClick={() => fetchSampleFile("Invoice_Q4_2026.pdf").then(setFile).catch((e) => setErr(e.message))}>{tr("Disguised “PDF”")}</Button>
            </div>
            {busy && <ScanBar />}
          </div>
        </Card>
        <Card title={tr("Analysis capabilities")} subtitle={tr("What this deployment can and cannot do")}>
          {!s ? <ScanBar /> : (
            <ul className="space-y-2">
              <Cap ok label={tr("File signature & MIME verification")} note="Magic bytes vs extension vs declared type" />
              <Cap ok label={tr("Archive listing, macro & PDF script detection")} />
              <Cap ok label={tr("Hashes (MD5/SHA-1/SHA-256) + local blocklist")} note={s.providers.virustotal.configured ? tr("VirusTotal hash lookup configured") : tr("No external hash reputation configured")} />
              <Cap ok={s.ocr.engine !== "unavailable"} label={`${tr("OCR text extraction")} (${s.ocr.engine})`} />
              <Cap ok label={tr("QR code decoding")} note={s.qr.engine} />
              <Cap ok={s.media.ffprobe} label={tr("Audio/video metadata (ffprobe)")} />
              <Cap ok={s.media.ffmpeg} label={tr("Video frame sampling + OCR")} />
              <Cap ok={false} label={tr("Speech-to-text")} note="Not installed — paste a transcript" />
              <Cap ok={false} label={tr("Synthetic voice / deepfake detection")} note="Not implemented; WOLVE never labels media fake on impressions" />
              <Cap ok={false} label={tr("Dynamic sandbox detonation")} note={s.sandbox.note} />
            </ul>
          )}
        </Card>
      </div>

      {result && <ReportView a={result} actions={<AnalysisActions a={result} onChange={setResult} />} />}

      <Card title={tr("Quarantine vault & history")} subtitle={tr("Files scoring ≥30 are stored with a neutralised .quarantined name — never executed or served back")}>
        {hist.error ? <ErrorBox error={hist.error} /> : (hist.data?.length ?? 0) === 0 ? <p className="text-sm text-ink-400">{tr("No files analysed yet.")}</p> : (
          <ul className="divide-y divide-ink-800">
            {hist.data!.map((a) => (
              <li key={a.id} className="flex items-center gap-3 py-2 text-sm">
                <SeverityBadge s={a.severity} />
                <span className="w-12 shrink-0 text-xs capitalize text-ink-400">{a.kind}</span>
                <Link href={`/analyses/${a.id}`} className="min-w-0 flex-1 truncate font-mono text-ink-100 hover:text-volt">{a.title}</Link>
                {a.quarantined_file && <Pill className="text-violet-700">{tr("quarantined")}</Pill>}
                <span className="font-mono text-xs">{a.risk_score}</span>
                <span className="w-16 text-end text-xs text-ink-400">{timeAgo(a.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

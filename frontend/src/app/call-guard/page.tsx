"use client";

import { Hand, MessageCircleQuestion, Mic, PhoneCall, ShieldCheck, Square, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { AnalysisActions } from "@/components/AnalysisActions";
import { FileDrop } from "@/components/FileDrop";
import { NextSteps, ReportView, verdictOf } from "@/components/ReportView";
import { broadcastRefresh, Button, Card, cn, ErrorBox, inputCls, Label, PageHeader, Pill, ScanBar, ScoreRing, Tabs, useApi } from "@/components/ui";
import { apiGet, apiSend, apiUpload } from "@/lib/api";
import { tr, trf } from "@/lib/i18n";
import type { Analysis } from "@/lib/types";

const CHUNK_MS = 8000;

const CLAIM_LABEL: Record<string, string> = { time: "Time", day: "Day", organisation: "Organisation" };

function ClaimsPanel({ claims }: { claims: any[] }) {
  return (
    <div className="rounded-xl border border-ink-700 bg-white p-4">
      <div className="mb-2 flex items-center gap-2 font-semibold text-ink-100"><ShieldCheck className="h-4 w-4 text-volt" />{tr("Verified facts")}</div>
      {claims.length === 0 ? (
        <p className="text-sm text-ink-400">{tr("No checkable claims yet. Ask: “What time is it there now?” or “Which company are you from?”")}</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {claims.map((c, i) => (
            <li key={i} className={cn("flex items-start gap-2 rounded-lg p-2", c.ok ? "bg-green-50" : "bg-red-50")}>
              <span className={cn("mt-0.5 font-bold", c.ok ? "text-safe" : "text-crit")}>{c.ok ? "✓" : "✗"}</span>
              <div>
                <div className="text-ink-100"><b>{tr(CLAIM_LABEL[c.type] || c.type)}:</b> <span dir="auto">«{c.said}»</span></div>
                <div className={cn("text-xs", c.ok ? "text-ink-400" : "text-crit")}>{c.ok ? tr("Consistent") : tr("Contradicted")} — {c.actual}</div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Three short alarm tones, generated in the browser (no sound file, nothing sent anywhere). */
function playAlarm() {
  try {
    const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
    [0, 0.35, 0.7].forEach((t) => {
      const osc = ctx.createOscillator(), gain = ctx.createGain();
      osc.type = "square";
      osc.frequency.value = 880;
      gain.gain.setValueAtTime(0.0001, ctx.currentTime + t);
      gain.gain.exponentialRampToValueAtTime(0.25, ctx.currentTime + t + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + t + 0.25);
      osc.connect(gain).connect(ctx.destination);
      osc.start(ctx.currentTime + t);
      osc.stop(ctx.currentTime + t + 0.27);
    });
    setTimeout(() => ctx.close(), 1500);
  } catch {
    /* audio unavailable: the visual alarm still shows */
  }
}

function CodeAlarm() {
  return (
    <div role="alert" className="flex items-center gap-4 rounded-xl border-2 border-crit bg-crit p-5 text-white shadow-lg motion-safe:animate-pulse">
      <Hand className="h-12 w-12 shrink-0" />
      <div>
        <div className="text-2xl font-bold">{tr("Stop! Don't give the code")}</div>
        <p className="mt-1 text-sm text-white/90">{tr("A number that looks like a one-time code was heard after the caller asked for a code. If it was your code, hang up and call your bank now to block the card.")}</p>
      </div>
    </div>
  );
}

export default function CallGuard() {
  const [mode, setMode] = useState<"live" | "upload">("live");
  const [consent, setConsent] = useState(false);
  const [number, setNumber] = useState("");
  const [extra, setExtra] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<Analysis | null>(null);
  const [live, setLive] = useState(false);
  const [lines, setLines] = useState<string[]>([]);
  const [seconds, setSeconds] = useState(0);
  const status = useApi<any>(() => apiGet("/api/calls/status"), []);
  const streamRef = useRef<MediaStream | null>(null);
  const recRef = useRef<MediaRecorder | null>(null);
  const sessionRef = useRef<string | null>(null);
  const timerRef = useRef<any>(null);
  const liveRef = useRef(false);

  useEffect(() => () => stopLive(), []); // eslint-disable-line react-hooks/exhaustive-deps

  const codeSpoken = !!result?.report?.call?.code_spoken;
  useEffect(() => {
    if (codeSpoken) playAlarm();
  }, [codeSpoken]);

  const sendChunk = async (blob: Blob) => {
    if (!sessionRef.current || blob.size < 2000) return;
    const fd = new FormData();
    fd.append("audio", blob, "chunk.webm");
    fd.append("consent", "true");
    fd.append("session_id", sessionRef.current);
    if (number.trim()) fd.append("caller_number", number.trim());
    try {
      const r = await apiUpload<any>("/api/calls/analyze", fd);
      if (r.chunk_text) setLines((l) => [...l, r.chunk_text]);
      setResult(r);
      broadcastRefresh();
    } catch (e: any) {
      setErr(e.message);
    }
  };

  // Each chunk is a standalone recording (restart every CHUNK_MS) so the server can decode it on its own.
  const recordChunk = () => {
    const stream = streamRef.current;
    if (!stream || !liveRef.current) return;
    const rec = new MediaRecorder(stream);
    const parts: Blob[] = [];
    rec.ondataavailable = (e) => e.data.size && parts.push(e.data);
    rec.onstop = () => {
      sendChunk(new Blob(parts, { type: rec.mimeType || "audio/webm" }));
      if (liveRef.current) recordChunk();
    };
    recRef.current = rec;
    rec.start();
    setTimeout(() => rec.state === "recording" && rec.stop(), CHUNK_MS);
  };

  const startLive = async () => {
    if (!consent) return setErr(tr("Tick the consent box first."));
    setErr(null);
    setResult(null);
    setLines([]);
    try {
      streamRef.current = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: false, noiseSuppression: true } });
    } catch {
      return setErr(tr("Microphone access was denied or no microphone was found."));
    }
    sessionRef.current = (await apiSend("/api/calls/session", "POST")).session_id;
    liveRef.current = true;
    setLive(true);
    setSeconds(0);
    timerRef.current = setInterval(() => setSeconds((s) => s + 1), 1000);
    recordChunk();
  };

  function stopLive() {
    liveRef.current = false;
    setLive(false);
    if (recRef.current?.state === "recording") recRef.current.stop();
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    clearInterval(timerRef.current);
  }

  const analyseUpload = async () => {
    if (!consent) return setErr(tr("Tick the consent box first."));
    if (!file && !extra.trim()) return setErr(tr("Attach a call recording or type what the caller said."));
    setErr(null);
    setBusy(true);
    setResult(null);
    try {
      const fd = new FormData();
      if (file) fd.append("audio", file);
      fd.append("consent", "true");
      if (number.trim()) fd.append("caller_number", number.trim());
      if (extra.trim()) fd.append("transcript", extra.trim());
      setResult(await apiUpload<Analysis>("/api/calls/analyze", fd));
      broadcastRefresh();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const st = status.data;
  const v = result ? verdictOf(result.risk_score) : null;
  const feats = result?.report?.call?.features || {};
  const caller = result?.report?.call?.caller;
  return (
    <div className="space-y-5">
      <PageHeader title={tr("Call Guard")} icon={PhoneCall}
        subtitle={tr("Is the person on the phone a scammer? 3B listens to what they say and how they say it, and checks their number.")} />

      {codeSpoken && <CodeAlarm />}

      <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
        <Card>
          <div className="space-y-4">
            <Tabs value={mode} onChange={(m) => { if (!live) setMode(m); }} items={[
              { value: "live", label: <span className="flex items-center gap-1.5"><Mic className="h-4 w-4" />{tr("Live call (speakerphone)")}</span> },
              { value: "upload", label: <span className="flex items-center gap-1.5"><Upload className="h-4 w-4" />{tr("Recorded call")}</span> }]} />
            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <Label htmlFor="num">{tr("Caller's number (as shown on your phone)")}</Label>
                <input id="num" dir="ltr" className={inputCls} value={number} onChange={(e) => setNumber(e.target.value)} placeholder="+971 50 123 4567" disabled={live} />
              </div>
            </div>
            {mode === "upload" && (
              <>
                <FileDrop file={file} onFile={setFile} accept="audio/*,video/*,.mp3,.wav,.m4a,.ogg,.opus,.amr,.webm,.mp4" hint={tr("Call recording (mp3, wav, m4a, ogg, amr…), max 25 MB")} />
                <div>
                  <Label htmlFor="tx">{tr("What the caller said (optional)")}</Label>
                  <textarea id="tx" dir="auto" className={inputCls + " min-h-20"} value={extra} onChange={(e) => setExtra(e.target.value)} />
                </div>
              </>
            )}
            <label className="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-ink-200">
              <input type="checkbox" className="mt-1 h-4 w-4 accent-amber-600" checked={consent} onChange={(e) => setConsent(e.target.checked)} disabled={live} />
              <span>{tr("I am a participant in this call and analysing it is allowed. I understand 3B only hears what this computer's microphone picks up (put the call on speaker) — it cannot intercept phone calls.")}</span>
            </label>
            {err && <ErrorBox error={err} />}
            {mode === "live" ? (
              live ? (
                <div className="flex flex-wrap items-center gap-3">
                  <Button variant="danger" className="px-5 py-2.5" onClick={stopLive}><Square className="h-4 w-4" /> {tr("Stop listening")}</Button>
                  <span className="flex items-center gap-2 text-sm font-medium text-crit"><span className="h-2.5 w-2.5 animate-pulse rounded-full bg-crit" />{tr("Listening")} · {Math.floor(seconds / 60)}:{String(seconds % 60).padStart(2, "0")}</span>
                  <span className="text-xs text-ink-400">{trf("Analysis updates every {n} seconds.", { n: CHUNK_MS / 1000 })}</span>
                </div>
              ) : (
                <Button variant="primary" className="px-5 py-2.5 text-base" onClick={startLive}><Mic className="h-4 w-4" /> {tr("Start listening")}</Button>
              )
            ) : (
              <Button variant="primary" className="px-5 py-2.5 text-base" loading={busy} onClick={analyseUpload}>{busy ? tr("Checking…") : tr("Check the call")}</Button>
            )}
            {busy && <ScanBar />}
          </div>
        </Card>
        <Card title={<span className="flex items-center gap-2"><MessageCircleQuestion className="h-4 w-4 text-volt" />{tr("Ask the caller")}</span>}>
          <ul className="space-y-3">
            {(result?.report?.call?.questions || st?.questions || []).map((q: any) => (
              <li key={q.id} className="rounded-lg bg-wax/70 p-3">
                <p dir="auto" className="font-medium text-ink-100">«{q.question}»</p>
                <p className="mt-1 text-xs text-ink-400">{q.listen_for}</p>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-ink-400">{tr("Ask, then stay quiet while the caller answers. The questions change with what the caller says.")}</p>
          <details className="mt-3 text-sm text-ink-300">
            <summary className="flex cursor-pointer items-center gap-1.5 text-xs font-medium text-ink-400"><ShieldCheck className="h-3.5 w-3.5" />{tr("How it works")}</summary>
            <ul className="mt-2 space-y-1.5 text-xs">
              <li>• {tr("Words: speech is turned into text on this computer and checked for scam tactics (OTP requests, fake police/bank, threats, secrecy).")}</li>
              <li>• {tr("Number: where the number is registered and whether it is a known scam number. Caller ID can be faked.")}</li>
              <li>• {tr("Audio is never saved or sent to the cloud.")}</li>
            </ul>
            <Pill className={cn("mt-2 text-xs", st?.speech_to_text?.available ? "text-safe" : "text-crit")}>{tr("Speech-to-text")}: {st?.speech_to_text?.available ? st.speech_to_text.engine : tr("not installed")}</Pill>
          </details>
        </Card>
      </div>

      {(live || lines.length > 0) && result && v && (
        <div className={cn("grid gap-4 rounded-xl border p-5 lg:grid-cols-[auto_1fr_1fr]", v.tone)}>
          <ScoreRing score={result.risk_score} severity={result.severity} size={104} />
          <div>
            <div className={cn("text-2xl font-semibold", v.text)}>{tr(v.label)}</div>
            <p className="mt-1 text-sm text-ink-200">{result.risk_score >= 30 ? result.classification : tr("No scam signs so far — keep listening carefully.")}</p>
            <ul className="mt-2 space-y-1 text-sm text-ink-200">{result.report!.findings.filter((f) => f.weight > 0).slice(0, 4).map((f, i) => <li key={i}>• {f.title}</li>)}</ul>
            <NextSteps next={result.report?.next_steps} compact className="mt-3" />
          </div>
          <div className="space-y-3 text-sm">
            <ClaimsPanel claims={result.report?.call?.claims || []} />
            <div className="mb-1 font-medium text-ink-100">{tr("Live transcript")}</div>
            <div dir="auto" className="max-h-40 overflow-y-auto rounded-lg bg-white/70 p-2 text-ink-200">{lines.join(" ") || "…"}</div>
          </div>
        </div>
      )}

      {result && !live && (
        <>
          <ClaimsPanel claims={result.report?.call?.claims || []} />
          {(caller || Object.keys(feats).length > 0) && (
            <Card title={tr("Caller and voice")}>
              <div className="grid gap-4 md:grid-cols-2 text-sm">
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                  <dt className="text-ink-400">{tr("Number")}</dt><dd dir="ltr" className="text-start font-mono">{caller?.normalized || tr("unknown")}</dd>
                  <dt className="text-ink-400">{tr("Registered to")}</dt><dd>{caller ? tr(caller.registered_region) : "—"}</dd>
                  <dt className="text-ink-400">{tr("Real location")}</dt><dd className="text-ink-300">{tr("Cannot be known from a phone number")}</dd>
                </dl>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                  <dt className="text-ink-400">{tr("Speaking speed")}</dt><dd>{feats.speech_rate_wpm ? trf("{n} words/min", { n: feats.speech_rate_wpm }) : "—"}</dd>
                  <dt className="text-ink-400">{tr("Pitch movement")}</dt><dd>{feats.pitch_variation_semitones ?? "—"}</dd>
                  <dt className="text-ink-400">{tr("Loudness changes")}</dt><dd>{feats.loudness_variation_db != null ? `${feats.loudness_variation_db} dB` : "—"}</dd>
                  <dt className="text-ink-400">{tr("Pauses")}</dt><dd>{feats.pause_ratio != null ? `${Math.round(feats.pause_ratio * 100)}%` : "—"}</dd>
                </dl>
              </div>
              {result.report?.call?.transcript && (
                <div className="mt-3"><div className="mb-1 text-sm font-medium text-ink-100">{tr("Transcript")}</div>
                  <p dir="auto" className="rounded-lg bg-ink-850 p-3 text-sm text-ink-200">{result.report.call.transcript}</p></div>
              )}
            </Card>
          )}
          <ReportView a={result} actions={<AnalysisActions a={result} onChange={setResult} />} />
        </>
      )}
    </div>
  );
}

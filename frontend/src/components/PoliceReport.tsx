"use client";

import { Check, Copy, Download, FileText, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { apiGet } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { Button, ErrorBox } from "./ui";

type Draft = { title: string; sections: { name: string; values: string[] }[]; body: string; footer: string };

/** A short report draft the person can copy or download. Nothing is sent from 3B. */
export function PoliceReport({ id, onClose }: { id: string; onClose: () => void }) {
  const [draft, setDraft] = useState<Draft | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    apiGet<Draft>(`/api/analyses/${id}/police-report`).then(setDraft).catch((e) => setErr(e.message));
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [id, onClose]);

  const copy = async () => {
    if (!draft) return;
    await navigator.clipboard.writeText(draft.body);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  const download = () => {
    if (!draft) return;
    const url = URL.createObjectURL(new Blob(["﻿" + draft.body], { type: "text/plain;charset=utf-8" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: `police-report-${id}.txt` });
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="pr-title">
      <div className="absolute inset-0 bg-hive/60" onClick={onClose} />
      <div className="relative flex max-h-[90vh] w-full max-w-xl flex-col rounded-xl bg-white shadow-xl">
        <div className="flex items-center gap-2 border-b border-ink-700 px-5 py-3">
          <FileText className="h-5 w-5 text-volt" />
          <h2 id="pr-title" className="text-lg font-semibold text-ink-100">{draft?.title || tr("Police report draft")}</h2>
          <button ref={closeRef} onClick={onClose} className="ms-auto rounded-md p-1 text-ink-400 hover:bg-ink-850" aria-label={tr("Close")}><X className="h-5 w-5" /></button>
        </div>
        <div className="overflow-y-auto px-5 py-4">
          {err && <ErrorBox error={err} />}
          {!draft && !err && <p className="text-sm text-ink-400">…</p>}
          {draft && (
            <dl className="space-y-3 text-sm">
              {draft.sections.map((s) => (
                <div key={s.name}>
                  <dt className="text-xs font-medium text-ink-400">{s.name}</dt>
                  {s.values.map((v, i) => <dd key={i} dir="auto" className="break-words text-ink-100">{v}</dd>)}
                </div>
              ))}
            </dl>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2 border-t border-ink-700 px-5 py-3">
          <Button variant="primary" onClick={copy} disabled={!draft}>{copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />} {copied ? tr("Copied") : tr("Copy")}</Button>
          <Button onClick={download} disabled={!draft}><Download className="h-4 w-4" /> {tr("Download")}</Button>
          <p className="w-full text-xs text-ink-400">{tr("This draft is not sent anywhere. Review it, then report through the Abu Dhabi Police app or Aman (8002626).")}</p>
        </div>
      </div>
    </div>
  );
}

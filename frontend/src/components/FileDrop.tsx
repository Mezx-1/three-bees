"use client";

import { tr } from "@/lib/i18n";
import { UploadCloud, X } from "lucide-react";
import { useRef, useState } from "react";
import { cn } from "./ui";

export function FileDrop({ file, onFile, accept, hint, maxMb = 25 }: { file: File | null; onFile: (f: File | null) => void; accept?: string; hint?: string; maxMb?: number }) {
  const ref = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const take = (f?: File | null) => {
    if (!f) return;
    if (f.size > maxMb * 1024 * 1024) {
      setErr(`File is larger than ${maxMb} MB.`);
      return;
    }
    if (f.size === 0) {
      setErr("File is empty.");
      return;
    }
    setErr(null);
    onFile(f);
  };
  return (
    <div>
      <div
        role="button"
        tabIndex={0}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && ref.current?.click()}
        onClick={() => ref.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setOver(true); }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); take(e.dataTransfer.files?.[0]); }}
        className={cn("flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-6 py-8 text-center transition",
          over ? "border-volt bg-volt/5" : "border-ink-600 hover:border-ink-400 bg-ink-850/50")}
      >
        <UploadCloud className="h-8 w-8 text-volt" />
        {file ? (
          <div className="flex items-center gap-2 text-sm text-ink-100">
            <span className="font-medium">{file.name}</span>
            <span className="text-ink-400">({(file.size / 1024).toFixed(1)} {tr("KB)")}</span>
            <button type="button" aria-label={tr("Remove file")} onClick={(e) => { e.stopPropagation(); onFile(null); if (ref.current) ref.current.value = ""; }} className="rounded p-0.5 hover:bg-ink-700"><X className="h-4 w-4" /></button>
          </div>
        ) : (
          <>
            <p className="text-sm text-ink-200">{tr("Drop a file here or")} <span className="text-volt">{tr("browse")}</span></p>
            <p className="text-xs text-ink-400">{hint || `Max ${maxMb} MB. Files are inspected statically and never executed.`}</p>
          </>
        )}
        <input ref={ref} type="file" className="hidden" accept={accept} onChange={(e) => take(e.target.files?.[0])} />
      </div>
      {err && <p className="mt-1 text-xs text-crit">{err}</p>}
    </div>
  );
}

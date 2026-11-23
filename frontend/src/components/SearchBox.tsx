"use client";

import { FileText, Search, Siren, Tag } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { apiGet } from "@/lib/api";
import { tr } from "@/lib/i18n";
import { cn, SeverityBadge } from "./ui";

export type SearchPage = { href: string; label: string; icon: any; keywords: string };
type Hit = { key: string; href: string; icon: any; label: string; sub?: string; severity?: string };
type Results = { analyses: any[]; evidence: any[]; incidents: any[] };

const EVIDENCE_LABEL: Record<string, string> = {
  phone: "Phone", domain: "Domain", url: "Link", email: "Email", hash: "File hash", filename: "File", ip: "IP address",
};

/** One search box for pages, checks, evidence (numbers, links, domains, emails, hashes) and incidents. Ctrl+K or / to focus. */
export function SearchBox({ pages }: { pages: SearchPage[] }) {
  const router = useRouter();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [res, setRes] = useState<Results | null>(null);
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target as HTMLElement)?.tagName) || (e.target as HTMLElement)?.isContentEditable;
      if ((e.key === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing)) {
        e.preventDefault();
        inputRef.current?.focus();
        setOpen(true);
      }
    };
    const onClick = (e: MouseEvent) => { if (!boxRef.current?.contains(e.target as Node)) setOpen(false); };
    window.addEventListener("keydown", onKey);
    window.addEventListener("mousedown", onClick);
    return () => { window.removeEventListener("keydown", onKey); window.removeEventListener("mousedown", onClick); };
  }, []);

  useEffect(() => {
    const term = q.trim();
    if (term.length < 2) return setRes(null);
    let live = true;
    const id = setTimeout(() => {
      apiGet<Results>(`/api/search?q=${encodeURIComponent(term)}`).then((r) => live && setRes(r)).catch(() => live && setRes(null));
    }, 250);
    return () => { live = false; clearTimeout(id); };
  }, [q]);

  const hits = useMemo<Hit[]>(() => {
    const term = q.trim().toLowerCase();
    if (!term) return [];
    const out: Hit[] = pages
      .filter((p) => (p.label + " " + p.keywords).toLowerCase().includes(term))
      .slice(0, 4)
      .map((p) => ({ key: "p" + p.href, href: p.href, icon: p.icon, label: p.label, sub: tr("Page") }));
    res?.analyses.forEach((a) => out.push({ key: "a" + a.id, href: `/analyses/${a.id}`, icon: FileText, label: a.title, sub: `${tr(a.kind)} · ${a.id}`, severity: a.severity }));
    res?.evidence.forEach((e, i) => out.push({ key: "e" + i, href: `/analyses/${e.analysis_id}`, icon: Tag, label: e.value, sub: tr(EVIDENCE_LABEL[e.type] || e.type) }));
    res?.incidents.forEach((x) => out.push({ key: "i" + x.id, href: `/incidents/${x.id}`, icon: Siren, label: x.title, sub: `${tr("Incident")} · ${x.id}`, severity: x.severity }));
    return out;
  }, [q, res, pages]);

  useEffect(() => setSel(0), [hits.length]);

  const go = (h: Hit) => {
    setOpen(false);
    setQ("");
    router.push(h.href);
  };

  return (
    <div ref={boxRef} className="relative w-full max-w-md">
      <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-400" />
      <input
        ref={inputRef}
        type="search"
        value={q}
        onChange={(e) => { setQ(e.target.value); setOpen(true); }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, hits.length - 1)); }
          else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
          else if (e.key === "Enter" && hits[sel]) go(hits[sel]);
          else if (e.key === "Escape") { setOpen(false); inputRef.current?.blur(); }
        }}
        placeholder={tr("Search pages, checks, numbers, links…")}
        aria-label={tr("Search")}
        role="combobox"
        aria-expanded={open && hits.length > 0}
        aria-controls="global-search-results"
        className="w-full rounded-lg border border-ink-600 bg-white py-1.5 pe-12 ps-9 text-sm text-ink-100 placeholder:text-ink-500 focus:border-honey-deep focus:outline-none focus:ring-2 focus:ring-honey/40"
      />
      {!q && <kbd className="pointer-events-none absolute end-2 top-1/2 hidden -translate-y-1/2 rounded border border-ink-600 px-1.5 text-[10px] text-ink-400 sm:block">Ctrl K</kbd>}
      {open && q.trim() && (
        <ul id="global-search-results" role="listbox" className="absolute inset-x-0 top-full z-50 mt-1 max-h-96 overflow-y-auto rounded-lg border border-ink-700 bg-white p-1 shadow-lg">
          {hits.length === 0 ? (
            <li className="px-3 py-2 text-sm text-ink-400">{q.trim().length < 2 ? tr("Keep typing…") : tr("Nothing found.")}</li>
          ) : hits.map((h, i) => (
            <li key={h.key} role="option" aria-selected={i === sel}>
              <button onMouseEnter={() => setSel(i)} onClick={() => go(h)}
                className={cn("flex w-full items-center gap-3 rounded-md px-3 py-2 text-start", i === sel ? "bg-wax" : "hover:bg-ink-850")}>
                <h.icon className="h-4 w-4 shrink-0 text-volt" />
                <span className="min-w-0 flex-1">
                  <span dir="auto" className="block truncate text-sm text-ink-100">{h.label}</span>
                  {h.sub && <span className="block truncate text-xs text-ink-400">{h.sub}</span>}
                </span>
                {h.severity && <SeverityBadge s={h.severity} />}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

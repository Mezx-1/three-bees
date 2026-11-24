"use client";

import { BookOpenCheck, Download, Eye, EyeOff, FileUp, Lightbulb, Plus, Search, X } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { Button, Card, cn, EmptyState, ErrorBox, inputCls, Label, PageHeader, Pill, SeverityBadge, Stat, timeAgo, useApi, useToast } from "@/components/ui";
import { apiGet, apiSend, download, getMe } from "@/lib/api";
import { getLang, tr, trf } from "@/lib/i18n";

const STATUS_TONE: Record<string, string> = { verified: "bg-emerald-50 text-safe", needs_review: "bg-amber-50 text-warn", draft: "bg-ink-800 text-ink-300" };
const STATUS_TEXT: Record<string, string> = { verified: "Verified", needs_review: "Needs review", draft: "Draft" };

export default function Page() {
  return <Suspense><ScamMethods /></Suspense>;
}

function ScamMethods() {
  const toast = useToast();
  const params = useSearchParams();
  const analyst = ["analyst", "admin"].includes(getMe()?.role || "");
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("");
  const [status, setStatus] = useState("");
  const [uae, setUae] = useState(false);
  const [open, setOpen] = useState<string | null>(params.get("id"));
  const [editing, setEditing] = useState<any | null>(null);
  const [importing, setImporting] = useState(false);
  const qs = new URLSearchParams();
  if (q.trim()) qs.set("q", q.trim());
  if (cat) qs.set("category", cat);
  if (status) qs.set("status", status);
  if (uae) qs.set("uae", "true");
  if (analyst) qs.set("include_disabled", "true");
  const stats = useApi<any>(() => apiGet("/api/knowledge/stats"), []);
  const list = useApi<any[]>(() => apiGet(`/api/knowledge/methods?${qs}`), [q, cat, status, uae]);
  const s = stats.data;
  const reload = () => { stats.reload(true); list.reload(true); };

  return (
    <div className="space-y-5">
      <PageHeader title={tr("Scam Methods Library")} icon={BookOpenCheck}
        subtitle={tr("Known scam techniques the engine compares against. A reference, not a rule list: a scam doesn't need to be in here to be caught.")}
        actions={analyst && (
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" onClick={() => setEditing({ review_status: "draft", examples: { en: [""], ar: [""] } })}><Plus className="h-4 w-4" /> {tr("Add method")}</Button>
            <Button onClick={() => setImporting(true)}><FileUp className="h-4 w-4" /> {tr("Import")}</Button>
            <Button variant="ghost" onClick={() => download("/api/knowledge/export?format=json", "3b-scam-methods.json")}><Download className="h-4 w-4" /> JSON</Button>
            <Button variant="ghost" onClick={() => download("/api/knowledge/export?format=csv", "3b-scam-methods.csv")}><Download className="h-4 w-4" /> CSV</Button>
          </div>
        )} />

      {stats.error && <ErrorBox error={stats.error} onRetry={() => stats.reload()} />}
      {s && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label={tr("Methods in the library")} value={s.total} />
            <Stat label={tr("Categories")} value={s.by_category.length} tone="volt" />
            <Stat label={tr("Verified with a source")} value={s.verified} tone="safe" hint={trf("{n} not verified yet", { n: s.unverified })} />
            <Stat label={tr("UAE-focused")} value={s.uae_focus} />
          </div>
          <p className="text-xs text-ink-400">{tr(s.note)}</p>
          <div className="grid gap-4 xl:grid-cols-3">
            <Card title={tr("Methods by category")} className="xl:col-span-2">
              <div className="flex flex-wrap gap-1.5">
                <button onClick={() => setCat("")} className={cn("rounded-full px-3 py-1 text-xs ring-1", !cat ? "bg-comb text-white ring-comb" : "text-ink-300 ring-ink-600")}>{tr("All")}</button>
                {s.by_category.map((c: any) => (
                  <button key={c.key} onClick={() => setCat(c.key === cat ? "" : c.key)}
                    className={cn("rounded-full px-3 py-1 text-xs ring-1", cat === c.key ? "bg-comb text-white ring-comb" : "text-ink-300 ring-ink-600 hover:bg-ink-800")}>
                    {tr(c.name)} · {c.count}
                  </button>
                ))}
              </div>
            </Card>
            <Card title={tr("Seen in investigations")} subtitle={tr("Closest known method in recent analyses")}>
              {s.seen_in_investigations.length === 0 ? <p className="text-sm text-ink-400">{tr("No analyses have matched a method yet.")}</p> : (
                <ul className="space-y-1 text-sm">{s.seen_in_investigations.map((x: any) => (
                  <li key={x.id} className="flex justify-between gap-2"><button className="truncate text-start text-volt hover:underline" onClick={() => setOpen(x.id)}>{x.name}</button><span className="text-ink-400">{x.analyses}</span></li>
                ))}</ul>
              )}
            </Card>
          </div>
        </>
      )}

      <Card>
        <div className="flex flex-col gap-2 md:flex-row md:items-center">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute start-3 top-2.5 h-4 w-4 text-ink-400" />
            <input className={cn(inputCls, "ps-9")} placeholder={tr("Search methods, examples, indicators…")} value={q} onChange={(e) => setQ(e.target.value)} aria-label={tr("Search")} />
          </div>
          <select className={cn(inputCls, "md:w-48")} value={status} onChange={(e) => setStatus(e.target.value)} aria-label={tr("Review status")}>
            <option value="">{tr("Any review status")}</option>
            {Object.entries(STATUS_TEXT).map(([k, v]) => <option key={k} value={k}>{tr(v)}</option>)}
          </select>
          <label className="flex items-center gap-2 text-sm text-ink-300"><input type="checkbox" checked={uae} onChange={(e) => setUae(e.target.checked)} /> {tr("UAE-focused only")}</label>
        </div>
      </Card>

      {list.error && <ErrorBox error={list.error} onRetry={() => list.reload()} />}
      {list.data && list.data.length === 0 && <EmptyState title={tr("No methods match")} icon={Search} />}
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {(list.data || []).map((m) => (
          <button key={m.id} onClick={() => setOpen(m.id)} className={cn("rounded-xl border border-ink-700 bg-ink-900 p-4 text-start transition hover:border-honey", !m.enabled && "opacity-50")}>
            <div className="flex items-start justify-between gap-2">
              <span className="text-sm font-semibold text-ink-100">{getLang() === "ar" && m.name_ar ? m.name_ar : m.name}</span>
              <SeverityBadge s={m.severity} />
            </div>
            <p className="mt-1 line-clamp-2 text-xs text-ink-300">{m.description}</p>
            <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="text-ink-400">{m.id}</span>
              <span className={cn("rounded-full px-2 py-0.5", STATUS_TONE[m.review_status])}>{tr(STATUS_TEXT[m.review_status])}</span>
              {m.uae_focus && <Pill>UAE</Pill>}
              {!m.enabled && <Pill>{tr("Disabled")}</Pill>}
            </div>
          </button>
        ))}
      </div>

      {analyst && <Candidates onChange={reload} />}

      {open && <Detail id={open} analyst={analyst} onClose={() => setOpen(null)} onEdit={(d) => { setOpen(null); setEditing(d); }} onChange={reload} />}
      {editing && <Editor initial={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); toast("ok", tr("Saved")); }} />}
      {importing && <Importer onClose={() => setImporting(false)} onDone={reload} />}
    </div>
  );
}

function Drawer({ title, onClose, children }: { title: React.ReactNode; onClose: () => void; children: React.ReactNode }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40" onClick={onClose}>
      <aside role="dialog" aria-modal="true" className="h-full w-full max-w-2xl overflow-y-auto bg-ink-950 p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-start justify-between gap-3">
          <h2 className="text-lg font-semibold text-ink-100">{title}</h2>
          <button onClick={onClose} aria-label={tr("Close")} className="rounded p-1 text-ink-300 hover:bg-ink-800"><X className="h-5 w-5" /></button>
        </div>
        {children}
      </aside>
    </div>
  );
}

function List({ title, items }: { title: string; items?: string[] }) {
  if (!items?.length) return null;
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-400">{tr(title)}</h3>
      <ul className="mt-1 list-disc space-y-0.5 ps-5 text-sm text-ink-200">{items.map((x, i) => <li key={i}>{x}</li>)}</ul>
    </div>
  );
}

function Detail({ id, analyst, onClose, onEdit, onChange }: { id: string; analyst: boolean; onClose: () => void; onEdit: (d: any) => void; onChange: () => void }) {
  const m = useApi<any>(() => apiGet(`/api/knowledge/methods/${id}`), [id]);
  const toast = useToast();
  const d = m.data?.data;
  const toggle = async () => {
    try {
      await apiSend(`/api/knowledge/methods/${id}/${m.data.enabled ? "disable" : "enable"}`, "POST");
      m.reload(true);
      onChange();
    } catch (e: any) { toast("err", e.message); }
  };
  return (
    <Drawer title={d ? (getLang() === "ar" && d.name_ar ? d.name_ar : d.name) : tr("Loading…")} onClose={onClose}>
      {m.error && <ErrorBox error={m.error} />}
      {d && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-ink-400">{d.id}</span><SeverityBadge s={d.severity} />
            <span className={cn("rounded-full px-2 py-0.5", STATUS_TONE[m.data.review_status])}>{tr(STATUS_TEXT[m.data.review_status])}</span>
            <Pill>{tr(d.category_name || d.category)}</Pill>{d.subcategory && <Pill>{d.subcategory}</Pill>}{d.uae_focus && <Pill>UAE</Pill>}
            <span className="text-ink-400">v{m.data.version}</span>
          </div>
          <p className="text-sm text-ink-200">{d.description}</p>
          <List title="Typical attack sequence" items={d.attack_sequence} />
          <div className="grid gap-4 sm:grid-cols-2">
            <List title="Psychological techniques" items={d.psychological_techniques} />
            <List title="Attacker objectives" items={d.attacker_objectives} />
            <List title="Typical targets" items={d.typical_targets} />
            <List title="Channels" items={d.channels} />
          </div>
          <List title="Behavioural indicators" items={d.behavioral_indicators} />
          <List title="Technical indicators" items={d.technical_indicators} />
          <div className="grid gap-3 sm:grid-cols-2">
            {(d.examples?.en || []).map((x: string, i: number) => <blockquote key={"en" + i} className="rounded-lg bg-ink-900 p-3 text-sm italic text-ink-200 ring-1 ring-ink-700" dir="ltr">“{x}”</blockquote>)}
            {(d.examples?.ar || []).map((x: string, i: number) => <blockquote key={"ar" + i} className="rounded-lg bg-ink-900 p-3 text-sm italic text-ink-200 ring-1 ring-ink-700" dir="rtl">«{x}»</blockquote>)}
          </div>
          {d.examples_are_fictional && <p className="text-xs text-ink-400">{tr("Examples are fictional, written for training. No real victims' information.")}</p>}
          <List title="Variations" items={d.variations} />
          <List title="How 3B detects it" items={d.detection_strategies} />
          <List title="How to protect yourself" items={d.protection_steps} />
          <p className="text-sm text-ink-300"><b>{tr("Impact:")}</b> {d.impact}</p>
          {d.related_methods?.length > 0 && <p className="text-xs text-ink-400">{tr("Related:")} {d.related_methods.join(", ")}</p>}
          <div className="rounded-lg border border-ink-700 p-3 text-xs text-ink-300">
            <b>{tr("Sources:")}</b>{" "}
            {d.sources?.length ? d.sources.map((s: any, i: number) => <span key={i}>{s.url ? <a className="text-volt hover:underline" href={s.url} target="_blank" rel="noreferrer">{s.title || s.url}</a> : s.title}{i < d.sources.length - 1 ? "; " : ""}</span>)
              : tr("None attached yet.")} {d.source_note && <span className="block text-ink-400">{d.source_note}</span>}
            <span className="block text-ink-400">{tr("Last reviewed:")} {d.last_reviewed || tr("not yet")}</span>
          </div>
          {analyst && (
            <div className="flex flex-wrap gap-2 border-t border-ink-700 pt-3">
              <Button onClick={() => onEdit({ ...d, review_status: m.data.review_status })}>{tr("Edit")}</Button>
              <Button variant="ghost" onClick={toggle}>{m.data.enabled ? <><EyeOff className="h-4 w-4" /> {tr("Disable")}</> : <><Eye className="h-4 w-4" /> {tr("Enable")}</>}</Button>
            </div>
          )}
          {m.data.versions && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-400">{tr("Version history")}</h3>
              <ul className="mt-1 space-y-0.5 text-xs text-ink-300">{m.data.versions.map((v: any) => <li key={v.version}>v{v.version} · {tr(STATUS_TEXT[v.review_status] || v.review_status)} · {v.changed_by} · {timeAgo(v.changed_at)} · {v.note}</li>)}</ul>
            </div>
          )}
        </div>
      )}
    </Drawer>
  );
}

const CAT_KEYS = ["banking", "phishing_email", "sms_whatsapp", "government", "delivery", "job", "investment", "romance", "ecommerce", "support", "identity",
  "otp_takeover", "payment_refund", "qr", "tech_support", "deepfake", "bec", "rental", "charity", "emerging"];

function Editor({ initial, onClose, onSaved }: { initial: any; onClose: () => void; onSaved: () => void }) {
  const [d, setD] = useState<any>({ category: "emerging", severity: "medium", ...initial });
  const [cats, setCats] = useState<{ key: string; name: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const [dups, setDups] = useState<any[] | null>(null);
  const toast = useToast();
  useEffect(() => { apiGet("/api/knowledge/categories").then(setCats).catch(() => setCats(CAT_KEYS.map((k) => ({ key: k, name: k })))); }, []);
  const joinList = (v: any) => (Array.isArray(v) ? v.join("\n") : v || "");
  const set = (k: string, v: any) => setD({ ...d, [k]: v });
  const save = async (force = false) => {
    setBusy(true);
    try {
      const body = { ...d, sources: typeof d.sources === "string" ? d.sources.split("\n").filter(Boolean).map((t: string) => (t.startsWith("http") ? { url: t, title: t } : { title: t })) : d.sources };
      if (initial.id) await apiSend(`/api/knowledge/methods/${initial.id}`, "PUT", body);
      else await apiSend(`/api/knowledge/methods${force ? "?force=true" : ""}`, "POST", body);
      onSaved();
    } catch (e: any) {
      if (e.status === 409) {
        try {
          const det = JSON.parse(e.message);
          setDups(det.duplicates || []);
          toast("err", tr(det.message));
        } catch { toast("err", e.message); }
      } else toast("err", e.message);
    } finally { setBusy(false); }
  };
  const area = (k: string, label: string, rows = 3) => (
    <div><Label htmlFor={k}>{tr(label)}</Label><textarea id={k} rows={rows} className={inputCls} value={joinList(d[k])} onChange={(e) => set(k, e.target.value)} /></div>
  );
  return (
    <Drawer title={initial.id ? `${tr("Edit")} ${initial.id}` : tr("Add a scam method")} onClose={onClose}>
      <div className="space-y-3">
        <div><Label htmlFor="name">{tr("Name")}</Label><input id="name" className={inputCls} value={d.name || ""} onChange={(e) => set("name", e.target.value)} /></div>
        <div className="grid gap-3 sm:grid-cols-3">
          <div><Label htmlFor="cat">{tr("Category")}</Label><select id="cat" className={inputCls} value={d.category} onChange={(e) => set("category", e.target.value)}>{cats.map((c) => <option key={c.key} value={c.key}>{tr(c.name)}</option>)}</select></div>
          <div><Label htmlFor="sev">{tr("Severity")}</Label><select id="sev" className={inputCls} value={d.severity} onChange={(e) => set("severity", e.target.value)}>{["low", "medium", "high", "critical"].map((x) => <option key={x} value={x}>{tr(x)}</option>)}</select></div>
          <div><Label htmlFor="st">{tr("Review status")}</Label><select id="st" className={inputCls} value={d.review_status} onChange={(e) => set("review_status", e.target.value)}>{Object.entries(STATUS_TEXT).map(([k, v]) => <option key={k} value={k}>{tr(v)}</option>)}</select></div>
        </div>
        {area("description", "Description")}
        {area("attack_sequence", "Attack sequence (one step per line)")}
        {area("behavioral_indicators", "Behavioural indicators (one per line)")}
        {area("protection_steps", "Protection steps (one per line)")}
        <div><Label htmlFor="exen">{tr("Example in English (fictional)")}</Label><textarea id="exen" rows={2} className={inputCls} dir="ltr" value={d.examples?.en?.[0] || ""} onChange={(e) => set("examples", { ...d.examples, en: [e.target.value] })} /></div>
        <div><Label htmlFor="exar">{tr("Example in Arabic (fictional)")}</Label><textarea id="exar" rows={2} className={inputCls} dir="rtl" value={d.examples?.ar?.[0] || ""} onChange={(e) => set("examples", { ...d.examples, ar: [e.target.value] })} /></div>
        <div><Label htmlFor="src">{tr("Sources (one per line: a URL or a document reference). Required for Verified.")}</Label>
          <textarea id="src" rows={2} className={inputCls} value={Array.isArray(d.sources) ? d.sources.map((s: any) => s.url || s.title).join("\n") : d.sources || ""} onChange={(e) => set("sources", e.target.value)} /></div>
        <label className="flex items-center gap-2 text-sm text-ink-300"><input type="checkbox" checked={!!d.uae_focus} onChange={(e) => set("uae_focus", e.target.checked)} /> {tr("UAE-focused")}</label>
        {dups && dups.length > 0 && (
          <div className="rounded-lg bg-amber-50 p-3 text-sm text-warn">
            {tr("Possible duplicate of:")} {dups.map((x) => `${x.id} (${x.name})`).join(", ")}
            <Button className="ms-2" onClick={() => save(true)}>{tr("Save anyway")}</Button>
          </div>
        )}
        <p className="text-xs text-ink-400">{tr("Only an administrator can mark a method Verified, and only with a source. Reports from users never become methods automatically.")}</p>
        <div className="flex gap-2"><Button variant="primary" loading={busy} onClick={() => save()}>{tr("Save")}</Button><Button variant="ghost" onClick={onClose}>{tr("Cancel")}</Button></div>
      </div>
    </Drawer>
  );
}

function Importer({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [format, setFormat] = useState<"json" | "csv">("json");
  const [content, setContent] = useState("");
  const [res, setRes] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const readFile = async (f?: File | null) => {
    if (!f) return;
    setFormat(f.name.toLowerCase().endsWith(".csv") ? "csv" : "json");
    setContent(await f.text());
  };
  const go = async () => {
    setBusy(true);
    try { setRes(await apiSend("/api/knowledge/import", "POST", { format, content })); onDone(); } catch (e: any) { toast("err", e.message); } finally { setBusy(false); }
  };
  return (
    <Drawer title={tr("Import scam methods")} onClose={onClose}>
      <div className="space-y-3">
        <input type="file" accept=".json,.csv" onChange={(e) => readFile(e.target.files?.[0])} aria-label={tr("Choose a JSON or CSV file")} />
        <select className={inputCls} value={format} onChange={(e) => setFormat(e.target.value as any)} aria-label={tr("Format")}><option value="json">JSON</option><option value="csv">CSV</option></select>
        <textarea rows={10} className={cn(inputCls, "font-mono text-xs")} value={content} onChange={(e) => setContent(e.target.value)} aria-label={tr("Content")} dir="ltr" />
        <p className="text-xs text-ink-400">{tr("Imported methods are saved as Draft or Needs review. Likely duplicates are skipped and listed.")}</p>
        <Button variant="primary" loading={busy} onClick={go} disabled={!content.trim()}>{tr("Import")}</Button>
        {res && <div className="text-sm text-ink-200">{trf("Created {a} · skipped {b} duplicates · {c} errors", { a: res.created.length, b: res.skipped_duplicates.length, c: res.errors.length })}</div>}
      </div>
    </Drawer>
  );
}

function Candidates({ onChange }: { onChange: () => void }) {
  const c = useApi<any[]>(() => apiGet("/api/knowledge/candidates"), []);
  const toast = useToast();
  if (!c.data?.length) return null;
  const act = async (id: number, action: "promote" | "dismiss") => {
    try { await apiSend(`/api/knowledge/candidates/${id}/${action}`, "POST", {}); c.reload(true); onChange(); toast("ok", tr(action === "promote" ? "Saved as a Draft method" : "Dismissed")); } catch (e: any) { toast("err", e.message); }
  };
  return (
    <Card title={<span className="flex items-center gap-2"><Lightbulb className="h-4 w-4 text-honey" /> {tr("Possible new techniques")}</span>}
      subtitle={tr("High-risk analyses with no close match in the library. Kept as candidates until a reviewer decides — never added automatically.")}>
      <ul className="space-y-2">{c.data.map((x) => (
        <li key={x.id} className="rounded-lg border border-ink-700 p-3 text-sm">
          <p className="text-ink-200">{x.excerpt}</p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-ink-400">{x.risk_score}/100 · {timeAgo(x.created_at)}
            <Button className="ms-auto" onClick={() => act(x.id, "promote")}>{tr("Save as Draft method")}</Button>
            <Button variant="ghost" onClick={() => act(x.id, "dismiss")}>{tr("Dismiss")}</Button></div>
        </li>
      ))}</ul>
    </Card>
  );
}

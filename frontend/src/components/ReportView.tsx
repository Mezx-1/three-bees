"use client";

import { AlertOctagon, CheckCircle2, ChevronDown, FileWarning, Footprints, Globe2, Link2, Mail, Paperclip, ScanText } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { tr, trf, useI18n } from "@/lib/i18n";
import type { Analysis, Finding } from "@/lib/types";
import { Button, Card, cn, fmtTime, Pill, ScoreRing, SeverityBadge, SimBadge, SourceBadge, Tabs } from "./ui";

function FindingRow({ f }: { f: Finding }) {
  return (
    <li className="rounded-lg border border-ink-700 bg-ink-850/70 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge s={f.severity} />
        <SourceBadge s={f.source} />
        <span className="text-sm font-medium text-ink-100">{f.title}</span>
        {f.weight > 0 && <span className="ms-auto font-mono text-[11px] text-ink-400" title={tr("Contribution weight to the risk score")}>+{f.weight}</span>}
      </div>
      <p className="mt-1.5 text-xs leading-relaxed text-ink-300">{f.detail}</p>
      {f.evidence && <code className="mt-1.5 block break-all rounded bg-ink-950/70 px-2 py-1 font-mono text-[11px] text-volt/90">{f.evidence}</code>}
    </li>
  );
}

function FindingList({ items, empty }: { items: Finding[]; empty: string }) {
  if (!items.length) return <p className="text-xs text-ink-400">{empty}</p>;
  return <ul className="space-y-2">{items.map((f, i) => <FindingRow key={i} f={f} />)}</ul>;
}

function KV({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,auto)_1fr] gap-x-4 gap-y-1.5 text-xs">
      {rows.filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-ink-400">{tr(k)}</dt>
          <dd className="break-all font-mono text-ink-100">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function Collapse({ title, icon: Icon, children, defaultOpen = false }: { title: string; icon: any; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-ink-700">
      <button onClick={() => setOpen(!open)} aria-expanded={open} className="flex w-full items-center gap-2 px-3 py-2.5 text-start text-sm font-medium text-ink-100 hover:bg-ink-800/60">
        <Icon className="h-4 w-4 text-volt" /> {title}
        <ChevronDown className={cn("ms-auto h-4 w-4 text-ink-400 transition", open && "rotate-180")} />
      </button>
      {open && <div className="border-t border-ink-700 p-3">{children}</div>}
    </div>
  );
}

const AUTH_COLOR: Record<string, string> = { pass: "text-safe", fail: "text-crit", softfail: "text-warn", none: "text-warn", neutral: "text-warn" };

function EmailDetails({ r }: { r: any }) {
  const em = r.email || {};
  const auth = em.authentication || {};
  return (
    <div className="space-y-3">
      <Collapse title={tr("Headers & sender")} icon={Mail} defaultOpen>
        <KV rows={[
          ["From", em.from_name ? `${em.from_name} <${em.from_address}>` : em.from_address],
          ["Reply-To", em.reply_to], ["Return-Path", em.return_path], ["To", (em.to || []).join(", ")], ["Subject", em.subject],
          ["Date", em.date], ["Message-ID", em.message_id], ["X-Mailer", em.x_mailer], ["Received hops", em.received_hops],
        ]} />
        <div className="mt-3 flex flex-wrap gap-2">
          {["spf", "dkim", "dmarc"].map((m) => (
            <span key={m} className="rounded-md bg-ink-850 px-2.5 py-1 text-xs ring-1 ring-ink-600">
              <span className="uppercase text-ink-400">{m}</span>{" "}
              <b className={AUTH_COLOR[auth[m]] || "text-ink-300"}>{auth[m] || "unknown"}</b>
            </span>
          ))}
        </div>
        {em.received_chain?.length > 0 && (
          <details className="mt-3 text-xs text-ink-300"><summary className="cursor-pointer text-ink-400">{tr("Received chain")}</summary>
            <ol className="mt-1 list-decimal space-y-1 ps-5 font-mono text-[11px]">{em.received_chain.map((x: string, i: number) => <li key={i} className="break-all">{x}</li>)}</ol>
          </details>
        )}
      </Collapse>
      {r.attachments?.length > 0 && (
        <Collapse title={`${tr("Attachments & embedded images")} (${r.attachments.length})`} icon={Paperclip} defaultOpen>
          <ul className="space-y-2">
            {r.attachments.map((a: any, i: number) => (
              <li key={i} className="rounded-lg border border-ink-700 bg-ink-850/60 p-3">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <FileWarning className="h-4 w-4 text-ink-400" /><span className="font-medium">{a.filename}</span>
                  <SeverityBadge s={a.severity} /><span className="font-mono text-xs text-ink-400">{a.score}/100</span>
                </div>
                <KV rows={[["Declared MIME", a.declared_mime], ["Real type", a.info.detected_type], ["Size", `${a.info.size} bytes`], ["SHA-256", a.info.hashes.sha256]]} />
                {a.info.archive?.entries?.length > 0 && (
                  <div className="mt-2 text-xs"><span className="text-ink-400">{tr("Archive contents:")}</span>
                    <ul className="mt-1 space-y-0.5 font-mono text-[11px]">{a.info.archive.entries.map((e: any) => <li key={e.name} className={e.flag ? "text-crit" : "text-ink-200"}>{e.name} ({e.size} B){e.flag ? ` — ${e.flag}` : ""}</li>)}</ul>
                  </div>
                )}
                {a.info.qr?.codes?.length > 0 && <p className="mt-2 break-all text-xs"><span className="text-ink-400">{tr("QR code →")}</span> <span className="font-mono text-warn">{a.info.qr.codes.join(", ")}</span></p>}
                {a.info.ocr?.text && <pre className="mt-2 whitespace-pre-wrap rounded bg-ink-950/70 p-2 font-mono text-[11px] text-ink-200"><span className="text-ink-400">{tr("OCR (")}{a.info.ocr.engine}): </span>{a.info.ocr.text}</pre>}
              </li>
            ))}
          </ul>
        </Collapse>
      )}
      {r.body_preview && (
        <Collapse title={tr("Message body (rendered as text — links disabled)")} icon={ScanText}>
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap text-xs text-ink-200">{r.body_preview}</pre>
        </Collapse>
      )}
    </div>
  );
}

function UrlList({ urls }: { urls: any[] }) {
  if (!urls?.length) return null;
  return (
    <Collapse title={`${tr("Links analysed")} (${urls.length})`} icon={Link2} defaultOpen>
      <ul className="space-y-2">
        {urls.map((u, i) => (
          <li key={i} className="rounded-lg border border-ink-700 bg-ink-850/60 p-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge s={u.severity} /><span className="font-mono text-xs text-ink-400">{u.score}/100</span>
              <span className="break-all font-mono text-xs text-ink-100">{u.url}</span>
            </div>
            {u.findings?.length > 0 && <p className="mt-1 text-[11px] text-ink-400">{u.findings.map((f: Finding) => f.title).join(" · ")}</p>}
            {u.intel?.dns && <p className="mt-1 text-[11px] text-ink-400">{tr("DNS:")} {u.intel.dns.nxdomain ? "NXDOMAIN" : Object.entries(u.intel.dns.records || {}).map(([k, v]: any) => `${k} ${v.length}`).join(", ") || u.intel.dns.error || "no records"} · <span className="text-ink-500">{u.intel.dns.source} @ {fmtTime(u.intel.dns.queried_at)}</span></p>}
          </li>
        ))}
      </ul>
    </Collapse>
  );
}

function FileDetails({ r }: { r: any }) {
  const f = r.file;
  if (!f) return null;
  return (
    <div className="space-y-3">
      <Collapse title={tr("File identity")} icon={FileWarning} defaultOpen>
        <KV rows={[["Filename", f.filename], ["Extension", `.${f.extension || "(none)"}`], ["Real type (signature)", f.detected_type], ["Detected MIME", f.detected_mime],
          ["Declared MIME", f.declared_mime], ["Size", `${f.size} bytes`], ["Entropy", `${f.entropy} / 8`], ["MD5", f.hashes.md5], ["SHA-1", f.hashes.sha1], ["SHA-256", f.hashes.sha256]]} />
      </Collapse>
      {f.archive && (
        <Collapse title={`${tr("Archive listing")} (${f.archive.entry_count ?? 0})`} icon={Paperclip} defaultOpen>
          <ul className="space-y-0.5 font-mono text-[11px]">{(f.archive.entries || []).map((e: any) => <li key={e.name} className={e.flag ? "text-crit" : "text-ink-200"}>{e.name} · {e.size} B{e.flag ? ` — ${e.flag}` : ""}</li>)}</ul>
        </Collapse>
      )}
      {f.image && (
        <Collapse title={tr("Image forensics")} icon={ScanText} defaultOpen>
          <KV rows={[["Format", f.image.format], ["Dimensions", f.image.width ? `${f.image.width}×${f.image.height}` : undefined], ["Software", f.image.software],
            ["Appended bytes", f.image.appended_bytes], ["EXIF fields", f.image.exif ? Object.keys(f.image.exif).length : 0], ["QR codes", (f.qr?.codes || []).join(", ") || "none"]]} />
          {f.ocr && <pre className="mt-2 whitespace-pre-wrap rounded bg-ink-950/70 p-2 font-mono text-[11px] text-ink-200"><span className="text-ink-400">{tr("OCR (")}{f.ocr.engine}): </span>{f.ocr.text || f.ocr.note || f.ocr.error || "(no text found)"}</pre>}
          {r.ai_extracted_text && <pre className="mt-2 whitespace-pre-wrap rounded bg-slate-100 p-2 font-mono text-[11px] text-slate-600"><span className="text-slate-600">{tr("AI-read text:")} </span>{r.ai_extracted_text}</pre>}
          {f.image.exif && Object.keys(f.image.exif).length > 0 && (
            <details className="mt-2 text-xs"><summary className="cursor-pointer text-ink-400">{tr("EXIF metadata")}</summary><KV rows={Object.entries(f.image.exif).slice(0, 40) as any} /></details>
          )}
        </Collapse>
      )}
      {f.pdf && <Collapse title={tr("PDF structure")} icon={FileWarning} defaultOpen><KV rows={[["Keywords", JSON.stringify(f.pdf.pdf_keywords)], ["Embedded URIs", (f.pdf.uris || []).join(", ")]]} /></Collapse>}
      {r.media && (
        <Collapse title={tr("Media metadata (ffprobe)")} icon={ScanText} defaultOpen>
          <KV rows={[["Format", r.media.format], ["Duration (s)", r.media.duration], ["Streams", (r.media.streams || []).map((s: any) => `${s.type}:${s.codec}`).join(", ")], ["Frames inspected", r.frames_analyzed]]} />
          {r.frame_ocr_text && <pre className="mt-2 whitespace-pre-wrap rounded bg-ink-950/70 p-2 font-mono text-[11px] text-ink-200"><span className="text-ink-400">{tr("On-screen text:")} </span>{r.frame_ocr_text}</pre>}
        </Collapse>
      )}
    </div>
  );
}

function IntelDetails({ r }: { r: any }) {
  const blocks: React.ReactNode[] = [];
  if (r.ip) {
    const geo = r.intel?.geolocation;
    const rep = r.intel?.reputation;
    blocks.push(
      <Collapse key="ip" title={tr("IP facts")} icon={Globe2} defaultOpen>
        <KV rows={[["Address", r.ip.ip], ["Version", `IPv${r.ip.version}`], ["Public (global)", String(r.ip.is_global)], ["Private", String(r.ip.is_private)],
          ["Documentation range", r.ip.documentation_range ? "yes (RFC 5737)" : undefined]]} />
        {geo && (
          <div className="mt-3 rounded-md bg-ink-850 p-2.5 text-xs">
            <div className="mb-1 font-semibold text-teal-700">{tr("Approximate geolocation —")} {geo.source} · {fmtTime(geo.queried_at)}</div>
            {geo.error ? <p className="text-ink-400">{tr("Unavailable:")} {geo.error}</p> : (
              <KV rows={[["Country", geo.data.country], ["Region / City", `${geo.data.regionName || ""} / ${geo.data.city || ""}`], ["ISP", geo.data.isp], ["Org", geo.data.org], ["ASN", geo.data.as],
                ["Proxy/VPN", String(geo.data.proxy)], ["Hosting", String(geo.data.hosting)]]} />
            )}
          </div>
        )}
        {rep && <p className="mt-2 text-xs text-ink-400">{tr("Reputation (")}{rep.source}): {rep.error ? rep.error : `${tr("abuse score")} ${rep.data?.abuseConfidenceScore}/100`}</p>}
      </Collapse>,
    );
  }
  if (r.url) {
    blocks.push(
      <Collapse key="url" title={tr("URL structure")} icon={Link2} defaultOpen>
        <KV rows={[["URL", r.url.url], ["Scheme", r.url.scheme], ["Host", r.url.host], ["Registered domain", r.url.registered_domain], ["TLD", r.url.tld], ["Punycode decoded", r.url.punycode_decoded], ["Path", r.url.path]]} />
        {r.intel?.dns && (
          <div className="mt-3 rounded-md bg-ink-850 p-2.5 text-xs">
            <div className="mb-1 font-semibold text-teal-700">{tr("DNS —")} {r.intel.dns.source} · {fmtTime(r.intel.dns.queried_at)}</div>
            {r.intel.dns.nxdomain ? <p className="text-warn">{tr("NXDOMAIN — domain does not resolve")}</p> : r.intel.dns.error ? <p className="text-ink-400">{r.intel.dns.error}</p> :
              <KV rows={Object.entries(r.intel.dns.records || {}).map(([k, v]: any) => [k, v.join(", ")]) as any} />}
          </div>
        )}
      </Collapse>,
    );
  }
  if (r.phone) {
    blocks.push(
      <Collapse key="phone" title={tr("Phone number facts")} icon={Globe2} defaultOpen>
        <KV rows={[["Normalised", r.phone.normalized], ["Calling code", r.phone.country_code ? `+${r.phone.country_code}` : "—"], ["Range registered to", r.phone.registered_region], ["Format hint", r.phone.line_type_hint]]} />
      </Collapse>,
    );
  }
  return <>{blocks}</>;
}

const VERDICT = {
  danger: { label: "Dangerous", tone: "border-red-200 bg-red-50", text: "text-crit", icon: AlertOctagon,
    advice: "Don't click links, scan QR codes, open attachments, reply, send money or share any codes." },
  suspicious: { label: "Suspicious", tone: "border-amber-200 bg-amber-50", text: "text-warn", icon: AlertOctagon,
    advice: "Be careful. Check with the sender through a phone number or address you already know." },
  clear: { label: "No clear threat found", tone: "border-green-200 bg-green-50", text: "text-safe", icon: CheckCircle2,
    advice: "Nothing strongly suspicious was found — but stay careful with unexpected requests for money, passwords or codes." },
};

export function verdictOf(score: number) {
  return score >= 60 ? VERDICT.danger : score >= 30 ? VERDICT.suspicious : VERDICT.clear;
}

/** Plain-language summary shown first, for employees and analysts alike. */
function Verdict({ a, actions }: { a: Analysis; actions?: React.ReactNode }) {
  const r = a.report!;
  const v = verdictOf(a.risk_score);
  const reasons = r.findings.filter((f) => f.weight > 0).slice(0, 4);
  const Icon = v.icon;
  return (
    <section className={cn("rounded-xl border p-5", v.tone)} role={a.risk_score >= 60 ? "alert" : undefined}>
      <div className="flex flex-wrap items-start gap-5">
        <ScoreRing score={a.risk_score} severity={a.severity} size={104} />
        <div className="min-w-0 flex-1">
          <div className={cn("flex items-center gap-2 text-2xl font-semibold", v.text)}><Icon className="h-6 w-6" /> {tr(v.label)}</div>
          <p className="mt-1 text-base text-ink-100">{a.risk_score >= 30 ? r.classification : tr("Looks normal based on the checks we ran")}</p>
          <p className="mt-1 text-sm text-ink-300">{tr(v.advice)}</p>
          <p className="mt-2 truncate text-xs text-ink-400" title={a.title}>{a.title}</p>
        </div>
      </div>
      {reasons.length > 0 && (
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <div>
            <h3 className="text-sm font-semibold text-ink-100">{a.risk_score >= 30 ? tr("Why") : tr("What we noticed (minor)")}</h3>
            <ul className="mt-1.5 space-y-1 text-sm text-ink-200">
              {reasons.map((f, i) => <li key={i} className="flex gap-2"><span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-current opacity-60" />{f.title}</li>)}
            </ul>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-ink-100">{tr("What to do")}</h3>
            <ul className="mt-1.5 space-y-1 text-sm text-ink-200">
              {r.recommended_actions.slice(0, 3).map((x) => <li key={x} className="flex gap-2"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-safe" />{x}</li>)}
            </ul>
          </div>
        </div>
      )}
      <NextSteps next={r.next_steps} className="mt-4" />
      {actions && <div className="mt-4 flex flex-wrap gap-2 border-t border-black/5 pt-4">{actions}</div>}
    </section>
  );
}

type NextStep = { id: string; step: string; why: string; advice: string };

/** The scammer's likely next move, predicted from the tactics already seen. */
export function NextSteps({ next, compact, className }: { next?: { note: string; items: NextStep[] }; compact?: boolean; className?: string }) {
  if (!next?.items?.length) return null;
  const items = compact ? next.items.slice(0, 1) : next.items;
  return (
    <div className={cn("rounded-lg border border-honey/40 bg-wax/70 p-3", className)}>
      <h3 className="flex items-center gap-2 text-sm font-semibold text-ink-100">
        <Footprints className="h-4 w-4 text-volt" />{tr("What the scammer will likely try next")}
      </h3>
      <ul className="mt-2 space-y-2.5 text-sm">
        {items.map((s) => (
          <li key={s.id}>
            <p className="font-medium text-ink-100">{s.step}</p>
            {!compact && <p className="mt-0.5 text-xs text-ink-400">{s.why}</p>}
            <p className="mt-1 flex gap-1.5 text-ink-200"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-safe" />{s.advice}</p>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-xs italic text-ink-400">{next.note}</p>
    </div>
  );
}

export function ReportView({ a, actions }: { a: Analysis; actions?: React.ReactNode }) {
  const { t } = useI18n();
  const r = a.report!;
  const [showDetails, setShowDetails] = useState(false);
  const [tab, setTab] = useState<"all" | "verified" | "heuristic" | "ai">("all");
  const lists = { all: r.findings, verified: [...r.verified_findings], heuristic: r.heuristic_findings, ai: r.ai_findings };
  const ai = r.ai;
  return (
    <div className="fade-up space-y-4">
      <Verdict a={a} actions={actions} />

      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-xs text-ink-400">
        <SeverityBadge s={a.severity} />
        <span>{tr("Confidence:")} {tr(`confidence_${a.confidence}`)}</span>
        <span className="capitalize">· {tr(a.kind)}</span>
        {a.kind === "email" && <span className="capitalize">· {tr("Status:")} {tr(a.status)}</span>}
        {a.demo && <SimBadge label="demo data" />}
        <span>· {fmtTime(a.created_at)}</span>
        {a.incident_id && <Link className="text-volt hover:underline" href={`/incidents/${a.incident_id}`}>· {tr("Incident")} {a.incident_id}</Link>}
        <Button variant="subtle" className="ms-auto" onClick={() => setShowDetails(!showDetails)} aria-expanded={showDetails}>
          <ChevronDown className={cn("h-4 w-4 transition", showDetails && "rotate-180")} />
          {showDetails ? tr("Hide technical details") : trf("Show technical details ({n} checks)", { n: r.findings.length })}
        </Button>
      </div>

      {ai?.assessment && (
        <Card title={<span className="flex items-center gap-2">{tr("Assessment summary")} <SourceBadge s="ai" /></span>}>
          <p className="text-sm text-ink-200">{ai.assessment.summary}</p>
          {ai.assessment.impersonated_entity && <p className="mt-2 text-sm text-ink-300">{tr("Pretending to be:")} <b>{ai.assessment.impersonated_entity}</b></p>}
          {ai.assessment.manipulation_indicators?.length > 0 && <p className="mt-2 text-xs text-warn">{tr("Possible manipulation signs:")} {ai.assessment.manipulation_indicators.join("; ")}</p>}
          <p className="mt-2 text-xs text-ink-400">{trf("Written by the AI model ({model}). It is an opinion, not proof — the checks below are what the score is built on.", { model: ai.model || "" })}</p>
        </Card>
      )}

      {showDetails && (
        <div className="fade-up grid gap-4 xl:grid-cols-[1.4fr_1fr]">
          <div className="space-y-4">
            <Card title={`${tr("All checks")} (${r.findings.length})`} action={
              <Tabs value={tab} onChange={setTab} items={[
                { value: "all", label: tr("All") }, { value: "verified", label: `${tr("Confirmed")} ${r.verified_findings.length}` },
                { value: "heuristic", label: `${tr("Patterns")} ${r.heuristic_findings.length}` },
                ...(r.ai_findings.length ? [{ value: "ai" as const, label: `${tr("AI")} ${r.ai_findings.length}` }] : [])]} />}>
              <p className="mb-3 text-xs text-ink-400">{tr("Confirmed = technical facts checked directly. Pattern = common scam signs that can also appear in normal messages.")}</p>
              <FindingList items={lists[tab]} empty="Nothing in this category." />
            </Card>
            {a.kind === "email" && <EmailDetails r={r} />}
            {["file", "image", "audio", "video"].includes(a.kind) && <FileDetails r={r} />}
            <UrlList urls={r.urls} />
            <IntelDetails r={r} />
          </div>
          <div className="space-y-4">
            <Card title={t("recommended")}>
              <ul className="space-y-2 text-sm">{r.recommended_actions.map((x) => <li key={x} className="flex gap-2"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-safe" /><span className="text-ink-200">{x}</span></li>)}</ul>
            </Card>
            {r.social_engineering_techniques.length > 0 && (
              <Card title={tr("Pressure tactics used")}>
                <div className="flex flex-wrap gap-1.5">{r.social_engineering_techniques.map((x) => <Pill key={x}>{x}</Pill>)}</div>
              </Card>
            )}
            <Card title={t("limitations")}>
              <ul className="list-disc space-y-1 ps-4 text-xs text-ink-300">{r.limitations.map((x) => <li key={x}>{x}</li>)}</ul>
              <p className="mt-3 text-xs italic text-ink-400">{r.score_note}</p>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}

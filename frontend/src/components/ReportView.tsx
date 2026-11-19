"use client";

import { AlertOctagon, Bot, CheckCircle2, ChevronDown, FileWarning, Globe2, Link2, ListChecks, Mail, Paperclip, ScanText, ShieldQuestion } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { useI18n } from "@/lib/i18n";
import type { Analysis, Finding } from "@/lib/types";
import { Card, cn, fmtTime, Pill, ScoreRing, SeverityBadge, SourceBadge, Tabs } from "./ui";

function FindingRow({ f }: { f: Finding }) {
  return (
    <li className="rounded-lg border border-ink-700 bg-ink-850/70 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge s={f.severity} />
        <SourceBadge s={f.source} />
        <span className="text-sm font-medium text-ink-100">{f.title}</span>
        {f.weight > 0 && <span className="ms-auto font-mono text-[11px] text-ink-400" title="Contribution weight to the risk score">+{f.weight}</span>}
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
          <dt className="text-ink-400">{k}</dt>
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
      <Collapse title="Headers & sender" icon={Mail} defaultOpen>
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
          <details className="mt-3 text-xs text-ink-300"><summary className="cursor-pointer text-ink-400">Received chain</summary>
            <ol className="mt-1 list-decimal space-y-1 ps-5 font-mono text-[11px]">{em.received_chain.map((x: string, i: number) => <li key={i} className="break-all">{x}</li>)}</ol>
          </details>
        )}
      </Collapse>
      {r.attachments?.length > 0 && (
        <Collapse title={`Attachments & embedded images (${r.attachments.length})`} icon={Paperclip} defaultOpen>
          <ul className="space-y-2">
            {r.attachments.map((a: any, i: number) => (
              <li key={i} className="rounded-lg border border-ink-700 bg-ink-850/60 p-3">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <FileWarning className="h-4 w-4 text-ink-400" /><span className="font-medium">{a.filename}</span>
                  <SeverityBadge s={a.severity} /><span className="font-mono text-xs text-ink-400">{a.score}/100</span>
                </div>
                <KV rows={[["Declared MIME", a.declared_mime], ["Real type", a.info.detected_type], ["Size", `${a.info.size} bytes`], ["SHA-256", a.info.hashes.sha256]]} />
                {a.info.archive?.entries?.length > 0 && (
                  <div className="mt-2 text-xs"><span className="text-ink-400">Archive contents:</span>
                    <ul className="mt-1 space-y-0.5 font-mono text-[11px]">{a.info.archive.entries.map((e: any) => <li key={e.name} className={e.flag ? "text-crit" : "text-ink-200"}>{e.name} ({e.size} B){e.flag ? ` — ${e.flag}` : ""}</li>)}</ul>
                  </div>
                )}
                {a.info.qr?.codes?.length > 0 && <p className="mt-2 break-all text-xs"><span className="text-ink-400">QR code →</span> <span className="font-mono text-warn">{a.info.qr.codes.join(", ")}</span></p>}
                {a.info.ocr?.text && <pre className="mt-2 whitespace-pre-wrap rounded bg-ink-950/70 p-2 font-mono text-[11px] text-ink-200"><span className="text-ink-400">OCR ({a.info.ocr.engine}): </span>{a.info.ocr.text}</pre>}
              </li>
            ))}
          </ul>
        </Collapse>
      )}
      {r.body_preview && (
        <Collapse title="Message body (rendered as text — links disabled)" icon={ScanText}>
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap text-xs text-ink-200">{r.body_preview}</pre>
        </Collapse>
      )}
    </div>
  );
}

function UrlList({ urls }: { urls: any[] }) {
  if (!urls?.length) return null;
  return (
    <Collapse title={`Links analysed (${urls.length})`} icon={Link2} defaultOpen>
      <ul className="space-y-2">
        {urls.map((u, i) => (
          <li key={i} className="rounded-lg border border-ink-700 bg-ink-850/60 p-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge s={u.severity} /><span className="font-mono text-xs text-ink-400">{u.score}/100</span>
              <span className="break-all font-mono text-xs text-ink-100">{u.url}</span>
            </div>
            {u.findings?.length > 0 && <p className="mt-1 text-[11px] text-ink-400">{u.findings.map((f: Finding) => f.title).join(" · ")}</p>}
            {u.intel?.dns && <p className="mt-1 text-[11px] text-ink-400">DNS: {u.intel.dns.nxdomain ? "NXDOMAIN" : Object.entries(u.intel.dns.records || {}).map(([k, v]: any) => `${k} ${v.length}`).join(", ") || u.intel.dns.error || "no records"} · <span className="text-ink-500">{u.intel.dns.source} @ {fmtTime(u.intel.dns.queried_at)}</span></p>}
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
      <Collapse title="File identity" icon={FileWarning} defaultOpen>
        <KV rows={[["Filename", f.filename], ["Extension", `.${f.extension || "(none)"}`], ["Real type (signature)", f.detected_type], ["Detected MIME", f.detected_mime],
          ["Declared MIME", f.declared_mime], ["Size", `${f.size} bytes`], ["Entropy", `${f.entropy} / 8`], ["MD5", f.hashes.md5], ["SHA-1", f.hashes.sha1], ["SHA-256", f.hashes.sha256]]} />
      </Collapse>
      {f.archive && (
        <Collapse title={`Archive listing (${f.archive.entry_count ?? 0})`} icon={Paperclip} defaultOpen>
          <ul className="space-y-0.5 font-mono text-[11px]">{(f.archive.entries || []).map((e: any) => <li key={e.name} className={e.flag ? "text-crit" : "text-ink-200"}>{e.name} · {e.size} B{e.flag ? ` — ${e.flag}` : ""}</li>)}</ul>
        </Collapse>
      )}
      {f.image && (
        <Collapse title="Image forensics" icon={ScanText} defaultOpen>
          <KV rows={[["Format", f.image.format], ["Dimensions", f.image.width ? `${f.image.width}×${f.image.height}` : undefined], ["Software", f.image.software],
            ["Appended bytes", f.image.appended_bytes], ["EXIF fields", f.image.exif ? Object.keys(f.image.exif).length : 0], ["QR codes", (f.qr?.codes || []).join(", ") || "none"]]} />
          {f.ocr && <pre className="mt-2 whitespace-pre-wrap rounded bg-ink-950/70 p-2 font-mono text-[11px] text-ink-200"><span className="text-ink-400">OCR ({f.ocr.engine}): </span>{f.ocr.text || f.ocr.note || f.ocr.error || "(no text found)"}</pre>}
          {r.ai_extracted_text && <pre className="mt-2 whitespace-pre-wrap rounded bg-fuchsia-950/30 p-2 font-mono text-[11px] text-fuchsia-200"><span className="text-fuchsia-400">AI-read text: </span>{r.ai_extracted_text}</pre>}
          {f.image.exif && Object.keys(f.image.exif).length > 0 && (
            <details className="mt-2 text-xs"><summary className="cursor-pointer text-ink-400">EXIF metadata</summary><KV rows={Object.entries(f.image.exif).slice(0, 40) as any} /></details>
          )}
        </Collapse>
      )}
      {f.pdf && <Collapse title="PDF structure" icon={FileWarning} defaultOpen><KV rows={[["Keywords", JSON.stringify(f.pdf.pdf_keywords)], ["Embedded URIs", (f.pdf.uris || []).join(", ")]]} /></Collapse>}
      {r.media && (
        <Collapse title="Media metadata (ffprobe)" icon={ScanText} defaultOpen>
          <KV rows={[["Format", r.media.format], ["Duration (s)", r.media.duration], ["Streams", (r.media.streams || []).map((s: any) => `${s.type}:${s.codec}`).join(", ")], ["Frames inspected", r.frames_analyzed]]} />
          {r.frame_ocr_text && <pre className="mt-2 whitespace-pre-wrap rounded bg-ink-950/70 p-2 font-mono text-[11px] text-ink-200"><span className="text-ink-400">On-screen text: </span>{r.frame_ocr_text}</pre>}
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
      <Collapse key="ip" title="IP facts" icon={Globe2} defaultOpen>
        <KV rows={[["Address", r.ip.ip], ["Version", `IPv${r.ip.version}`], ["Public (global)", String(r.ip.is_global)], ["Private", String(r.ip.is_private)],
          ["Documentation range", r.ip.documentation_range ? "yes (RFC 5737)" : undefined]]} />
        {geo && (
          <div className="mt-3 rounded-md bg-ink-850 p-2.5 text-xs">
            <div className="mb-1 font-semibold text-teal-300">Approximate geolocation — {geo.source} · {fmtTime(geo.queried_at)}</div>
            {geo.error ? <p className="text-ink-400">Unavailable: {geo.error}</p> : (
              <KV rows={[["Country", geo.data.country], ["Region / City", `${geo.data.regionName || ""} / ${geo.data.city || ""}`], ["ISP", geo.data.isp], ["Org", geo.data.org], ["ASN", geo.data.as],
                ["Proxy/VPN", String(geo.data.proxy)], ["Hosting", String(geo.data.hosting)]]} />
            )}
          </div>
        )}
        {rep && <p className="mt-2 text-xs text-ink-400">Reputation ({rep.source}): {rep.error ? rep.error : `abuse score ${rep.data?.abuseConfidenceScore}/100`}</p>}
      </Collapse>,
    );
  }
  if (r.url) {
    blocks.push(
      <Collapse key="url" title="URL structure" icon={Link2} defaultOpen>
        <KV rows={[["URL", r.url.url], ["Scheme", r.url.scheme], ["Host", r.url.host], ["Registered domain", r.url.registered_domain], ["TLD", r.url.tld], ["Punycode decoded", r.url.punycode_decoded], ["Path", r.url.path]]} />
        {r.intel?.dns && (
          <div className="mt-3 rounded-md bg-ink-850 p-2.5 text-xs">
            <div className="mb-1 font-semibold text-teal-300">DNS — {r.intel.dns.source} · {fmtTime(r.intel.dns.queried_at)}</div>
            {r.intel.dns.nxdomain ? <p className="text-warn">NXDOMAIN — domain does not resolve</p> : r.intel.dns.error ? <p className="text-ink-400">{r.intel.dns.error}</p> :
              <KV rows={Object.entries(r.intel.dns.records || {}).map(([k, v]: any) => [k, v.join(", ")]) as any} />}
          </div>
        )}
      </Collapse>,
    );
  }
  if (r.phone) {
    blocks.push(
      <Collapse key="phone" title="Phone number facts" icon={Globe2} defaultOpen>
        <KV rows={[["Normalised", r.phone.normalized], ["Calling code", r.phone.country_code ? `+${r.phone.country_code}` : "—"], ["Range registered to", r.phone.registered_region], ["Format hint", r.phone.line_type_hint]]} />
      </Collapse>,
    );
  }
  return <>{blocks}</>;
}

export function EmployeeWarning({ a }: { a: Analysis }) {
  if (!["high", "critical"].includes(a.severity)) return null;
  return (
    <div role="alert" className="flex gap-3 rounded-xl border border-crit/50 bg-gradient-to-r from-crit/20 to-crit/5 p-4">
      <AlertOctagon className="h-6 w-6 shrink-0 text-crit" />
      <div>
        <p className="font-semibold text-white">Warning: this {a.kind === "email" ? "email" : "content"} shows strong signs of {a.classification.toLowerCase()}.</p>
        <p className="mt-1 text-sm text-rose-100/90">Do not click its links, scan its QR codes, open attachments, reply, send money or share any codes. IT security has been notified{a.incident_id ? ` (incident ${a.incident_id})` : ""}.</p>
      </div>
    </div>
  );
}

export function ReportView({ a, actions }: { a: Analysis; actions?: React.ReactNode }) {
  const { t } = useI18n();
  const r = a.report!;
  const [tab, setTab] = useState<"all" | "verified" | "heuristic" | "ai">("all");
  const intel = r.findings.filter((f) => f.source === "intel");
  const lists = { all: r.findings, verified: [...r.verified_findings], heuristic: r.heuristic_findings, ai: r.ai_findings };
  const ai = r.ai;
  return (
    <div className="fade-up space-y-4">
      <EmployeeWarning a={a} />
      <Card>
        <div className="flex flex-wrap items-center gap-6">
          <ScoreRing score={a.risk_score} severity={a.severity} />
          <div className="min-w-0 flex-1 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge s={a.severity} />
              <Pill>{a.kind}</Pill>
              <Pill>{t("confidence")}: {a.confidence}</Pill>
              {a.demo && <Pill className="text-violet-300">demo data</Pill>}
              {a.status && a.kind === "email" && <Pill className="capitalize">{a.status}</Pill>}
            </div>
            <h2 className="break-words text-lg font-semibold text-white">{r.classification}</h2>
            <p className="truncate text-sm text-ink-300" title={a.title}>{a.title}</p>
            {r.threat_categories.length > 1 && <p className="text-xs text-ink-400">Also indicates: {r.threat_categories.slice(1, 6).join(", ")}</p>}
            <p className="text-xs text-ink-500">{a.id} · {fmtTime(a.created_at)} · submitted by {a.submitted_by}
              {a.incident_id && <> · <Link className="text-volt hover:underline" href={`/incidents/${a.incident_id}`}>Incident {a.incident_id}</Link></>}</p>
          </div>
          {actions && <div className="flex w-full flex-wrap gap-2 md:w-auto md:max-w-xs md:justify-end">{actions}</div>}
        </div>
        <p className="mt-3 border-t border-ink-700/60 pt-2 text-[11px] italic text-ink-400">{r.score_note}</p>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
        <div className="space-y-4">
          <Card title={`Evidence (${r.findings.length} findings)`} action={
            <Tabs value={tab} onChange={setTab} items={[
              { value: "all", label: "All" }, { value: "verified", label: `Verified ${r.verified_findings.length}` },
              { value: "heuristic", label: `Heuristic ${r.heuristic_findings.length}` }, { value: "ai", label: `AI ${r.ai_findings.length}` }]} />}>
            <FindingList items={lists[tab]} empty={tab === "ai" ? "No AI findings (AI unavailable or not used)." : "No findings in this category."} />
            {intel.length > 0 && tab === "verified" && <p className="mt-2 text-[11px] text-ink-400">Includes external intelligence results, shown with their source.</p>}
          </Card>
          {a.kind === "email" && <EmailDetails r={r} />}
          {["file", "image", "audio", "video"].includes(a.kind) && <FileDetails r={r} />}
          <UrlList urls={r.urls} />
          <IntelDetails r={r} />
        </div>
        <div className="space-y-4">
          <Card title={<span className="flex items-center gap-2"><Bot className="h-4 w-4 text-fuchsia-300" /> {t("ai_assessment")}</span>}>
            {ai?.assessment ? (
              <div className="space-y-2 text-sm">
                <p className="text-ink-100">{ai.assessment.summary}</p>
                {ai.assessment.impersonated_entity && <p className="text-xs text-ink-300">Impersonating: <b>{ai.assessment.impersonated_entity}</b></p>}
                {ai.assessment.social_engineering_techniques?.length > 0 && (
                  <div className="flex flex-wrap gap-1">{ai.assessment.social_engineering_techniques.map((x: string) => <Pill key={x}>{x}</Pill>)}</div>
                )}
                {ai.assessment.manipulation_indicators?.length > 0 && <p className="text-xs text-warn">Manipulation indicators: {ai.assessment.manipulation_indicators.join("; ")}</p>}
                <p className="text-[11px] text-ink-500">Model {ai.model} · AI score {ai.assessment.risk_score} · model confidence {ai.assessment.confidence}. AI output is an assessment, not proof.</p>
              </div>
            ) : (
              <div className="flex gap-2 text-sm text-ink-300">
                <ShieldQuestion className="h-5 w-5 shrink-0 text-ink-400" />
                <div>
                  <p className="font-medium text-ink-200">AI analysis unavailable for this item</p>
                  <p className="mt-1 text-xs text-ink-400">{ai?.error || ai?.reason || "Not used for this analysis type."} The verdict above comes from WOLVE&apos;s deterministic engine only.</p>
                </div>
              </div>
            )}
          </Card>
          {r.social_engineering_techniques.length > 0 && (
            <Card title="Social engineering techniques">
              <div className="flex flex-wrap gap-1.5">{r.social_engineering_techniques.map((x) => <Pill key={x} className="text-warn">{x}</Pill>)}</div>
            </Card>
          )}
          <Card title={<span className="flex items-center gap-2"><ListChecks className="h-4 w-4 text-safe" /> {t("recommended")}</span>}>
            <ul className="space-y-2 text-sm">{r.recommended_actions.map((x) => <li key={x} className="flex gap-2"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-safe" /><span className="text-ink-200">{x}</span></li>)}</ul>
          </Card>
          <Card title={t("limitations")}>
            <ul className="list-disc space-y-1 ps-4 text-xs text-ink-300">{r.limitations.map((x) => <li key={x}>{x}</li>)}</ul>
          </Card>
        </div>
      </div>
    </div>
  );
}

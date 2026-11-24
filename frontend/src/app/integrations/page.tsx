"use client";

import { Plug, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Button, Card, cn, ErrorBox, PageHeader, Spinner, useApi, useToast } from "@/components/ui";
import { apiGet, apiSend } from "@/lib/api";
import { tr } from "@/lib/i18n";

const STATUS: Record<string, [string, string]> = {
  connected: ["Connected", "bg-green-50 text-safe"],
  degraded: ["Degraded", "bg-amber-50 text-warn"],
  unavailable: ["Unavailable", "bg-red-50 text-crit"],
  not_configured: ["Not configured", "bg-ink-850 text-ink-400"],
  unknown: ["Not checked yet", "bg-ink-850 text-ink-300"],
  disabled: ["Turned off", "bg-ink-850 text-ink-400"],
};

function Badge({ s }: { s: string }) {
  const [label, tone] = STATUS[s] || [s, "bg-ink-850 text-ink-300"];
  return <span className={cn("rounded-full px-2.5 py-0.5 text-xs font-medium", tone)}>{tr(label)}</span>;
}

function Row({ name, what, status, extra }: { name: string; what: string; status: string; extra?: React.ReactNode }) {
  return (
    <li className="flex flex-wrap items-start gap-3 border-b border-ink-800 py-3 last:border-0">
      <div className="min-w-0 flex-1">
        <div className="font-medium text-ink-100">{name}</div>
        <div className="text-xs text-ink-400">{tr(what)}</div>
        {extra && <div className="mt-1 text-xs text-ink-300">{extra}</div>}
      </div>
      <Badge s={status} />
    </li>
  );
}

export default function Integrations() {
  const toast = useToast();
  const { data, error, loading, setData } = useApi<any>(() => apiGet("/api/integrations"), []);
  const [busy, setBusy] = useState(false);
  const check = async () => {
    setBusy(true);
    try {
      setData(await apiSend("/api/integrations/check", "POST"));
      toast("ok", tr("Checks finished."));
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(false);
    }
  };
  const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : null);
  return (
    <div className="space-y-5">
      <PageHeader title={tr("Integrations")} icon={Plug}
        subtitle={tr("Which outside services 3B is connected to. A service shows Connected only after a real request succeeds — never just because a key exists.")}
        actions={<Button variant="primary" loading={busy} onClick={check}><RefreshCw className="h-4 w-4" /> {tr("Run checks")}</Button>} />
      {loading && !data && <Spinner />}
      {error && <ErrorBox error={error} />}
      {data && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title={tr("Link reputation")} subtitle={data.external_lookups ? tr("Used when links are checked.") : tr("External lookups are off in Settings, so these are not queried during checks.")}>
            <ul>
              {data.threat_intel.map((p: any) => (
                <Row key={p.provider} name={p.label} what={p.covers} status={p.status}
                  extra={<>{p.last_success && <span>{tr("Last success:")} {when(p.last_success)} </span>}
                    {p.last_error && <span className="text-crit">· {tr(p.last_error.message || "")}</span>}
                    {p.rate_limited && <span className="text-warn"> · {tr("Rate limit reached")}</span>}</>} />
              ))}
            </ul>
          </Card>
          <Card title={tr("Sign-in, bot check and AI")}>
            <ul>
              <Row name="Firebase Authentication" what="Email sign-in, password reset; tokens verified by the 3B server" status={data.firebase.status}
                extra={data.firebase.project && <span dir="ltr" className="font-mono">{data.firebase.project}</span>} />
              <Row name="Cloudflare Turnstile" what="Bot check on Report a Scam, verified by the 3B server" status={data.turnstile.status}
                extra={data.turnstile.detail && tr(data.turnstile.detail)} />
              <Row name={data.ai.provider === "gemini" ? "Google Gemini" : data.ai.provider === "claude" ? "Anthropic Claude" : "AI"}
                what="Optional explanation layer; capped at 30 points" status={data.ai.status}
                extra={<>{data.ai.model && <span dir="ltr" className="font-mono">{data.ai.model}</span>} {tr(data.ai.note)}</>} />
              <Row name="Cloudflare Tunnel" what="Public https link to this 3B server" status={data.public_url.status}
                extra={data.public_url.url && <a dir="ltr" className="font-mono text-volt hover:underline" href={data.public_url.url}>{data.public_url.url}</a>} />
            </ul>
          </Card>
        </div>
      )}
      <p className="text-xs text-ink-400">{tr("Keys live only in the server's backend/.env file and are never sent to the browser. Not listed or unavailable never means safe.")}</p>
    </div>
  );
}

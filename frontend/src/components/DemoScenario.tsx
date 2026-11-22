"use client";

import { tr } from "@/lib/i18n";
import { useDemoLabels } from "@/lib/prefs";
import { CheckCircle2, Circle, FlaskConical, Play } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { apiSend } from "@/lib/api";
import { broadcastRefresh, Button, Card, cn, SimBadge, useToast } from "./ui";

type StepState = { done: boolean; info?: React.ReactNode };

export function DemoScenario() {
  const toast = useToast();
  const showSim = useDemoLabels();
  const [busy, setBusy] = useState<string | null>(null);
  const [emailId, setEmailId] = useState<string | null>(null);
  const [incId, setIncId] = useState<string | null>(null);
  const [steps, setSteps] = useState<Record<string, StepState>>({});

  const mark = (k: string, info?: React.ReactNode) => setSteps((s) => ({ ...s, [k]: { done: true, info } }));

  const run = async (k: string, fn: () => Promise<void>) => {
    setBusy(k);
    try {
      await fn();
      broadcastRefresh();
    } catch (e: any) {
      toast("err", e.message);
    } finally {
      setBusy(null);
    }
  };

  const items = [
    {
      k: "email", title: tr("Suspicious email arrives"), desc: tr("The CEO-impersonation email (spoofed sender, urgent payment, lure image with QR code, disguised attachment) goes through the real email pipeline."),
      action: () => run("email", async () => {
        const a = await apiSend("/api/demo/scenario/email", "POST");
        setEmailId(a.id);
        setIncId(a.incident_id);
        mark("email", <>{tr("Risk")} <b>{a.risk_score}/100</b> · {a.classification} · <Link className="text-volt underline" href={`/analyses/${a.id}`}>{tr("open report")}</Link>{a.incident_id && <> · {tr("incident")} <Link className="text-volt underline" href={`/incidents/${a.incident_id}`}>{a.incident_id}</Link></>}</>);
        toast("ok", `Email analysed: ${a.severity.toUpperCase()} (${a.risk_score}/100). Incident ${a.incident_id ?? "not"} created.`);
      }),
    },
    {
      k: "quarantine", title: tr("Analyst quarantines the message"), desc: tr("Moves the email to 3B quarantine (local demo environment — no live mailbox is connected)."), needs: "email",
      action: () => run("quarantine", async () => {
        const r = await apiSend(`/api/emails/${emailId}/action`, "POST", { action: "quarantine" });
        mark("quarantine", r.message);
        toast("ok", "Email quarantined in 3B.");
      }),
    },
    {
      k: "endpoint", title: tr("Endpoint reports activity"), desc: tr(showSim ? "Simulated telemetry from ALN-FIN-LT07: outlook.exe → wscript.exe runs the hidden script, then an outbound connection to the phishing domain." : "Telemetry from ALN-FIN-LT07: outlook.exe → wscript.exe runs the hidden script, then an outbound connection to the phishing domain."), needs: "email", sim: true,
      action: () => run("endpoint", async () => {
        const r = await apiSend("/api/demo/scenario/endpoint", "POST");
        const corr = r.results.find((x: any) => x.correlation.incident_id);
        const obs = r.results.reduce((n: number, x: any) => n + x.correlation.links.filter((l: any) => l.type === "observed").length, 0);
        mark("endpoint", <>{r.results.length} {showSim ? "simulated events" : "events"} · {obs} observed indicator matches{corr && <> · {tr("correlated into")} <Link className="text-volt underline" href={`/incidents/${corr.correlation.incident_id}`}>{corr.correlation.incident_id}</Link></>}</>);
        if (corr) setIncId(corr.correlation.incident_id);
        toast("ok", "Endpoint events ingested and correlated with the email incident.");
      }),
    },
    {
      k: "graph", title: tr("Review the correlated attack chain"), desc: tr("Open the threat graph: email → attachment hash → endpoint process → outbound connection."), needs: "endpoint",
      action: () => { mark("graph"); window.location.href = incId ? `/graph?incident=${incId}` : "/graph"; },
    },
  ];

  return (
    <Card title={<span className="flex items-center gap-2"><FlaskConical className="h-4 w-4 text-volt" /> {tr("Demo attack scenario")}</span>}
      subtitle={showSim ? tr("Safe, repeatable: harmless test files, documentation-range IPs, simulated endpoint events") : undefined} action={<SimBadge label={tr("Controlled demo")} />}>
      <ol className="space-y-3">
        {items.map((it, i) => {
          const st = steps[it.k];
          const blocked = it.needs && !steps[it.needs]?.done;
          return (
            <li key={it.k} className="flex gap-3">
              <div className="pt-0.5">{st?.done ? <CheckCircle2 className="h-5 w-5 text-safe" /> : <Circle className="h-5 w-5 text-ink-500" />}</div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-ink-100">{i + 1}. {it.title}</span>
                  {it.sim && <SimBadge />}
                </div>
                <p className="text-xs text-ink-400">{it.desc}</p>
                {st?.info && <p className="mt-1 text-xs text-ink-200">{st.info}</p>}
              </div>
              <Button variant={st?.done ? "ghost" : "primary"} className={cn("h-8 shrink-0 !px-3 text-xs")} disabled={!!blocked} loading={busy === it.k} onClick={it.action}
                title={blocked ? tr("Complete the previous step first") : undefined}>
                <Play className="h-3.5 w-3.5" /> {st?.done ? tr("Run again") : tr("Run")}
              </Button>
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

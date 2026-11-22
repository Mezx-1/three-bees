"use client";

import "@xyflow/react/dist/style.css";
import { Background, Controls, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { AtSign, Bug, Cpu, FileCode2, Fingerprint, Globe2, Hash, Link2, Mail, Network as NetIcon, Phone, Siren, User } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Card, EmptyState, ErrorBox, inputCls, PageHeader, Pill, ScanBar, SEV_HEX, SeverityBadge, SimBadge, useApi } from "@/components/ui";
import { apiGet } from "@/lib/api";
import { useI18n, tr } from "@/lib/i18n";
import { useDemoLabels } from "@/lib/prefs";

const TYPE_META: Record<string, { icon: any; color: string; col: number; label: string }> = {
  incident: { icon: Siren, color: "#d92d20", col: 0, label: "Incident" },
  email: { icon: Mail, color: "#a15c07", col: 1, label: "Email" },
  message: { icon: Mail, color: "#a15c07", col: 1, label: "Message" },
  file: { icon: FileCode2, color: "#a15c07", col: 1, label: "File" },
  image: { icon: FileCode2, color: "#a15c07", col: 1, label: "Image" },
  url: { icon: Link2, color: "#b54708", col: 2, label: "URL" },
  domain: { icon: Globe2, color: "#b54708", col: 2, label: "Domain" },
  ip: { icon: NetIcon, color: "#b54708", col: 2, label: "IP" },
  hash: { icon: Hash, color: "#6941c6", col: 2, label: "File hash" },
  filename: { icon: Fingerprint, color: "#6941c6", col: 2, label: "Filename" },
  phone: { icon: Phone, color: "#b54708", col: 2, label: "Phone" },
  endpoint_event: { icon: Bug, color: "#e04f16", col: 3, label: "Endpoint event" },
  device: { icon: Cpu, color: "#0e7490", col: 4, label: "Device" },
};
const emailMeta = { icon: AtSign, color: "#0369a1", col: 2, label: "Email address" };
const personMeta = { icon: User, color: "#067647", col: 2, label: "Person" };

function EntityNode({ data }: NodeProps) {
  const d = data as any;
  const meta = d.meta;
  const Icon = meta.icon;
  const showSim = useDemoLabels();
  return (
    <div className="rounded-lg border bg-ink-900 px-2.5 py-2 shadow-sm" style={{ borderColor: d.malicious || d.severity === "critical" ? "#d92d20" : meta.color + "88", minWidth: 170, maxWidth: 220 }}>
      <Handle type="target" position={Position.Left} style={{ background: meta.color, width: 6, height: 6 }} />
      <div className="flex items-center gap-1.5 text-xs font-medium" style={{ color: meta.color }}>
        <Icon className="h-3.5 w-3.5" /> {tr(meta.label)}
        {d.malicious && <span className="ms-auto rounded bg-crit/20 px-1 text-[9px] text-crit">{tr("malicious")}</span>}
        {showSim && d.simulated && <span className="ms-auto rounded bg-ink-800 px-1 text-[9px] text-ink-400">{tr("sim")}</span>}
      </div>
      <div className="mt-0.5 break-all font-mono text-[11px] leading-snug text-ink-100">{d.label}</div>
      {d.severity && <div className="mt-1 h-1 rounded" style={{ background: SEV_HEX[d.severity] }} />}
      <Handle type="source" position={Position.Right} style={{ background: meta.color, width: 6, height: 6 }} />
    </div>
  );
}
const nodeTypes = { entity: EntityNode };

export default function GraphPage() {
  const { t } = useI18n();
  const [incident, setIncident] = useState<string>("");
  const [picked, setPicked] = useState<any>(null);
  const incidents = useApi<any[]>(() => apiGet("/api/incidents"), []);
  const graph = useApi<any>(() => apiGet(`/api/graph${incident ? `?incident_id=${incident}` : ""}`), [incident]);

  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get("incident");
    if (q) setIncident(q);
  }, []);

  const { nodes, edges } = useMemo(() => {
    const g = graph.data;
    if (!g) return { nodes: [] as Node[], edges: [] as Edge[] };
    const cols: Record<number, number> = {};
    const nodes: Node[] = g.nodes.map((n: any) => {
      let meta = TYPE_META[n.type] || TYPE_META.file;
      if (n.type === "email" && n.id.startsWith("email:")) meta = emailMeta;
      if (n.id.startsWith("email:") && g.edges.some((e: any) => e.target === n.id && e.label === "owned by")) meta = personMeta;
      const col = meta.col;
      const row = (cols[col] = (cols[col] ?? -1) + 1);
      return { id: n.id, type: "entity", position: { x: col * 270, y: row * 92 }, data: { ...n, meta } };
    });
    // vertically centre each column
    const maxRows = Math.max(...Object.values(cols), 0);
    nodes.forEach((n) => {
      const col = (n.data as any).meta.col;
      n.position.y += ((maxRows - cols[col]) * 92) / 2;
    });
    // Draw every edge left→right by column so the attack chain reads as a flow (semantics kept in the label).
    const colOf = new Map(nodes.map((n) => [n.id, (n.data as any).meta.col as number]));
    const edges: Edge[] = g.edges.map((e: any) => {
      const flip = (colOf.get(e.source) ?? 0) > (colOf.get(e.target) ?? 0);
      return { e, source: flip ? e.target : e.source, target: flip ? e.source : e.target };
    }).map(({ e, source, target }: any) => ({
      id: e.id, source, target, label: e.label, animated: e.kind === "inferred",
      style: { stroke: e.kind === "inferred" ? "#b54708" : "#94a3b8", strokeWidth: 1.5, strokeDasharray: e.kind === "inferred" ? "6 4" : undefined },
      labelStyle: { fill: "#475467", fontSize: 10 }, markerEnd: { type: MarkerType.ArrowClosed, color: e.kind === "inferred" ? "#b54708" : "#0e7490" },
    }));
    return { nodes, edges };
  }, [graph.data]);

  const refFor = (n: any) => {
    if (!n) return null;
    if (n.type === "incident") return `/incidents/${n.label}`;
    if (n.ref) return `/analyses/${n.ref}`;
    if (n.type === "device") return `/endpoints`;
    return null;
  };

  return (
    <div className="space-y-5">
      <PageHeader title={t("nav_graph")} subtitle={tr("Entities and relationships across emails, files, infrastructure and endpoints")} icon={NetIcon}
        actions={
          <select aria-label={tr("Incident")} className={inputCls + " !w-auto"} value={incident} onChange={(e) => { setIncident(e.target.value); setPicked(null); }}>
            <option value="">{tr("Latest incidents (up to 8)")}</option>
            {(incidents.data || []).map((i) => <option key={i.id} value={i.id}>{i.id} · {i.severity} · {i.title.slice(0, 50)}</option>)}
          </select>
        } />
      <div className="flex flex-wrap items-center gap-3 text-xs text-ink-300">
        <span className="flex items-center gap-2"><span className="inline-block h-0.5 w-8 bg-volt" /> {tr("Observed — present in evidence/telemetry")}</span>
        <span className="flex items-center gap-2"><span className="inline-block h-0.5 w-8 border-t-2 border-dashed border-warn" /> {tr("Inferred — linked by 3B without a shared artefact")}</span>
        <span className="flex items-center gap-1"><span className="inline-block h-3 w-3 rounded border border-crit" /> {tr("Malicious indicator")}</span>
      </div>
      <div className="grid gap-4 xl:grid-cols-[1fr_300px]">
        <div className="h-[640px] overflow-hidden rounded-xl border border-ink-700 bg-ink-900">
          {graph.error ? <div className="p-4"><ErrorBox error={graph.error} onRetry={() => graph.reload()} /></div> : graph.loading && !graph.data ? <div className="p-4"><ScanBar /></div> :
            nodes.length === 0 ? <div className="p-6"><EmptyState title={tr("No incidents to graph yet")} icon={NetIcon}>{tr("Run the demo scenario or analyse a high-risk email to create an incident.")}</EmptyState></div> : (
              <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView minZoom={0.2} onNodeClick={(_, n) => setPicked(n.data)} proOptions={{ hideAttribution: true }} style={{ background: "#fbfcfd" }}>
                <Background color="#d0d7e1" bgColor="#fbfcfd" gap={24} />
                <Controls />
              </ReactFlow>
            )}
        </div>
        <Card title={tr("Entity details")}>
          {!picked ? <p className="text-sm text-ink-400">{tr("Click a node to inspect it.")}</p> : (
            <div className="space-y-2 text-sm">
              <Pill>{tr(picked.meta.label)}</Pill>
              <p className="break-all font-mono text-xs text-ink-100">{picked.title || picked.label}</p>
              {picked.severity && <SeverityBadge s={picked.severity} />}
              {picked.malicious && <p className="text-xs text-crit">{tr("Flagged malicious by analysis or blocklist.")}</p>}
              {picked.simulated && <SimBadge />}
              {picked.status && <p className="text-xs text-ink-300">{tr("Status:")} {picked.status}</p>}
              {refFor(picked) && <Link href={refFor(picked)!} className="inline-block text-xs text-volt hover:underline">{tr("Open →")}</Link>}
              <p className="pt-2 text-[11px] text-ink-500">{tr("Connected edges:")} {edges.filter((e) => e.source === picked.id || e.target === picked.id).length}</p>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

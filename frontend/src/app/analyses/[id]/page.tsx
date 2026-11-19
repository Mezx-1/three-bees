"use client";

import { tr } from "@/lib/i18n";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { use } from "react";
import { AnalysisActions } from "@/components/AnalysisActions";
import { ReportView } from "@/components/ReportView";
import { ErrorBox, Spinner, useApi } from "@/components/ui";
import { apiGet } from "@/lib/api";
import type { Analysis } from "@/lib/types";

export default function AnalysisPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data, error, loading, reload, setData } = useApi<Analysis>(() => apiGet(`/api/analyses/${id}`), [id]);
  return (
    <div className="space-y-4">
      <button onClick={() => history.back()} className="inline-flex items-center gap-1 text-sm text-ink-300 hover:text-ink-100"><ArrowLeft className="h-4 w-4 rtl:rotate-180" /> {tr("Back")}</button>
      {loading && !data && <Spinner label={tr("Loading report…")} />}
      {error && <ErrorBox error={error} onRetry={() => reload()} />}
      {data && <ReportView a={data} actions={<AnalysisActions a={data} onChange={(a) => setData(a)} />} />}
      {data?.incident_id && <p className="text-xs text-ink-400">{tr("Linked to")} <Link className="text-volt hover:underline" href={`/incidents/${data.incident_id}`}>{tr("incident")} {data.incident_id}</Link>.</p>}
    </div>
  );
}

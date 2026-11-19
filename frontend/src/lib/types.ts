export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  title: string;
  detail: string;
  category: string;
  severity: Severity;
  weight: number;
  source: "verified" | "heuristic" | "intel" | "ai";
  tags: string[];
  evidence?: string | null;
}

export interface Report {
  risk_score: number;
  severity: Severity;
  classification: string;
  threat_categories: string[];
  confidence: "low" | "medium" | "high";
  findings: Finding[];
  verified_findings: Finding[];
  heuristic_findings: Finding[];
  ai_findings: Finding[];
  social_engineering_techniques: string[];
  recommended_actions: string[];
  limitations: string[];
  score_note: string;
  ai?: { available: boolean; model?: string | null; reason?: string | null; error?: string | null; assessment?: any };
  [k: string]: any;
}

export interface Analysis {
  id: string;
  kind: string;
  title: string;
  classification: string;
  risk_score: number;
  severity: Severity;
  confidence: string;
  status: string;
  submitted_by: string;
  recipient?: string | null;
  incident_id?: string | null;
  demo: boolean;
  quarantined_file: boolean;
  created_at: string;
  from?: string;
  from_name?: string;
  report?: Report;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: string;
  source: string;
  risk_score: number;
  assigned_to?: string | null;
  escalated: boolean;
  correlated: boolean;
  demo: boolean;
  created_at: string;
  updated_at: string;
  summary: string;
  ai_explanation?: string | null;
  recommended_response?: string[];
  timeline?: { id: number; type: string; message: string; actor: string; created_at: string; data: any }[];
}

export interface Device {
  id: string;
  hostname: string;
  os: string;
  owner_email?: string | null;
  ip_address?: string | null;
  agent_version: string;
  source: "agent" | "simulated" | "manual";
  status: string;
  risk_score: number;
  last_seen?: string | null;
  system_info: Record<string, any>;
}

export interface EndpointEvent {
  id: number;
  device_id: string;
  event_type: string;
  severity: Severity;
  title: string;
  details: Record<string, any>;
  simulated: boolean;
  risk_score: number;
  findings: Finding[];
  incident_id?: string | null;
  created_at: string;
}

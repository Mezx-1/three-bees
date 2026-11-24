/* Labels shared by the Report a Scam form and the investigator pages. Keys match the backend. */
export const CATEGORIES: Record<string, string> = {
  bank_impersonation: "Fake bank call or message",
  government_impersonation: "Fake police or government",
  toll_fine: "Fake toll or traffic fine",
  delivery: "Fake parcel or delivery fee",
  job: "Fake job offer",
  investment: "Fake investment or crypto",
  shopping: "Fake online shop",
  romance: "Romance or friendship scam",
  qr: "QR code scam",
  account_takeover: "Account takeover",
  phishing_email: "Phishing email",
  other: "Other",
};

export const CHANNELS: Record<string, string> = {
  sms: "SMS", whatsapp: "WhatsApp", call: "Phone call", email: "Email", website: "Website", social: "Social media", other: "Other",
};

export const STATUSES: Record<string, string> = {
  submitted: "Submitted", under_review: "Under review", escalated: "Escalated", resolved: "Resolved", rejected: "Rejected",
};

export const STATUS_TONE: Record<string, string> = {
  submitted: "bg-ink-850 text-ink-200", under_review: "bg-amber-50 text-warn", escalated: "bg-red-50 text-crit",
  resolved: "bg-green-50 text-safe", rejected: "bg-ink-850 text-ink-400",
};

export const EMIRATES = ["Abu Dhabi", "Dubai", "Sharjah", "Ajman", "Umm Al Quwain", "Ras Al Khaimah", "Fujairah", "Al Ain"];

export const DEMO_LABEL = "DEMO DATA — FICTIONAL — NOT REAL INCIDENTS";

export type ReportRow = {
  reference: string; data_mode: "user" | "demo"; category: string; channel: string; phone?: string | null; url?: string | null;
  domain?: string | null; incident_date?: string | null; amount_lost?: number | null; currency: string; emirate?: string | null;
  status: string; risk_score: number; severity: string; flagged: boolean; has_evidence: boolean; created_at: string;
  [k: string]: any;
};

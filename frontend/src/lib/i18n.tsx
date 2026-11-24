"use client";

import { createContext, Fragment, useContext, useEffect, useState } from "react";
import { AR, AR_PATTERNS } from "./ar";

export type Lang = "en" | "ar";

/** Arabic is the default interface language. */
export const DEFAULT_LANG: Lang = "ar";

let currentLang: Lang = DEFAULT_LANG;

/**
 * Translate an English UI string. Keys are the English text itself, so untranslated strings
 * simply fall back to English. Usable anywhere (components, helpers) without a hook — the
 * provider remounts the tree when the language changes.
 */
export function tr(en: string): string {
  if (!en || currentLang === "en") return en;
  const hit = AR[en];
  if (hit !== undefined) return hit;
  for (const [rx, rep] of AR_PATTERNS) if (rx.test(en)) return en.replace(rx, rep);
  return en;
}

/** Translate with {placeholders}. */
export function trf(en: string, vars: Record<string, string | number>): string {
  let s = tr(en);
  for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, String(v));
  return s;
}

export const getLang = () => currentLang;

const dict = {
  brand_tag: "Think like a wolf. Detect before the attack.",
  nav_command: "Command Center",
  nav_scam: "Scam Analyzer",
  nav_calls: "Call Guard",
  nav_phone: "Phone Protection",
  nav_email: "Email Security",
  nav_forensics: "File & Image Forensics",
  nav_endpoints: "Endpoint Protection",
  nav_network: "Network Intelligence",
  nav_graph: "Threat Intelligence Graph",
  nav_incidents: "Incident Management",
  nav_prevention: "Prevention Center",
  nav_settings: "Settings",
  nav_report: "Report a Scam",
  nav_reports: "Scam Reports",
  nav_learn: "Learn About Scams",
  section_detect: "Detect",
  section_respond: "Respond",
  section_system: "System",
  acting_as: "User",
  analyze: "Analyze",
  analyzing: "Analyzing…",
  risk_score: "Risk score",
  severity: "Severity",
  classification: "Classification",
  confidence: "Confidence",
  recommended: "Recommended actions",
  limitations: "Evidence & analysis limitations",
  verified: "Verified technical findings",
  heuristic: "Heuristic indicators",
  ai_assessment: "AI assessment",
  no_data: "Nothing here yet",
  security_status: "Security status",
} as const;

export type DictKey = keyof typeof dict;

const Ctx = createContext<{ lang: Lang; setLang: (l: Lang) => void; t: (k: DictKey) => string }>({
  lang: DEFAULT_LANG,
  setLang: () => {},
  t: (k) => tr(dict[k]),
});

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>(DEFAULT_LANG);
  useEffect(() => {
    try {
      const saved = localStorage.getItem("3b.lang.v2") as Lang | null;
      if (saved === "ar" || saved === "en") setLangState(saved);
    } catch {}
  }, []);
  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  }, [lang]);
  const setLang = (l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem("3b.lang.v2", l);
    } catch {}
  };
  currentLang = lang; // set before children render so tr() uses the active language
  return (
    <Ctx.Provider value={{ lang, setLang, t: (k) => tr(dict[k]) }}>
      <Fragment key={lang}>{children}</Fragment>
    </Ctx.Provider>
  );
}

export const useI18n = () => useContext(Ctx);

/** Locale for dates and numbers. */
export const locale = () => (currentLang === "ar" ? "ar-AE" : "en-GB");

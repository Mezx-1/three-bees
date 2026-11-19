"use client";

import { createContext, useContext, useEffect, useState } from "react";

type Lang = "en" | "ar";

const dict = {
  en: {
    brand_tag: "Think like a wolf. Detect before the attack.",
    nav_command: "Command Center",
    nav_scam: "Scam Analyzer",
    nav_email: "Email Security",
    nav_forensics: "File & Image Forensics",
    nav_endpoints: "Endpoint Protection",
    nav_network: "Network Intelligence",
    nav_graph: "Threat Intelligence Graph",
    nav_incidents: "Incident Management",
    nav_prevention: "Prevention Center",
    nav_settings: "Settings",
    section_detect: "Detect",
    section_respond: "Respond",
    section_system: "System",
    acting_as: "Acting as",
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
  },
  ar: {
    brand_tag: "فكّر كالذئب. اكتشف قبل الهجوم.",
    nav_command: "مركز القيادة",
    nav_scam: "محلل الاحتيال",
    nav_email: "أمن البريد الإلكتروني",
    nav_forensics: "تحليل الملفات والصور",
    nav_endpoints: "حماية الأجهزة",
    nav_network: "استخبارات الشبكة",
    nav_graph: "مخطط استخبارات التهديدات",
    nav_incidents: "إدارة الحوادث",
    nav_prevention: "مركز الوقاية والاستجابة",
    nav_settings: "الإعدادات",
    section_detect: "الكشف",
    section_respond: "الاستجابة",
    section_system: "النظام",
    acting_as: "المستخدم الحالي",
    analyze: "تحليل",
    analyzing: "جارٍ التحليل…",
    risk_score: "درجة الخطورة",
    severity: "مستوى الخطورة",
    classification: "التصنيف",
    confidence: "مستوى الثقة",
    recommended: "الإجراءات الموصى بها",
    limitations: "حدود الأدلة والتحليل",
    verified: "نتائج تقنية مؤكدة",
    heuristic: "مؤشرات استدلالية",
    ai_assessment: "تقييم الذكاء الاصطناعي",
    no_data: "لا توجد بيانات بعد",
    security_status: "الحالة الأمنية",
  },
} as const;

export type DictKey = keyof (typeof dict)["en"];

const Ctx = createContext<{ lang: Lang; setLang: (l: Lang) => void; t: (k: DictKey) => string }>({
  lang: "en",
  setLang: () => {},
  t: (k) => dict.en[k],
});

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>("en");
  useEffect(() => {
    try {
      const saved = localStorage.getItem("wolve.lang") as Lang | null;
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
      localStorage.setItem("wolve.lang", l);
    } catch {}
  };
  return <Ctx.Provider value={{ lang, setLang, t: (k) => dict[lang][k] ?? dict.en[k] }}>{children}</Ctx.Provider>;
}

export const useI18n = () => useContext(Ctx);

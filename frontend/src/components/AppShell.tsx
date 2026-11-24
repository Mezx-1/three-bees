"use client";

import { Accessibility, Activity, ClipboardList, Plug, FileWarning, GraduationCap, LogOut, PhoneCall, Smartphone, Cpu, FileSearch, Globe2, LayoutDashboard, Mail, Menu, Network, Settings, ShieldAlert, ShieldCheck, Siren, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { apiGet, apiSend, getMe, getToken, type Me, setSession } from "@/lib/api";
import { DictKey, useI18n, tr } from "@/lib/i18n";
import { firebaseSignOut } from "@/lib/firebase";
import { setSimpleMode, useSimpleMode } from "@/lib/prefs";
import { BeeMark } from "./BeeMark";
import { SearchBox } from "./SearchBox";
import { cn, hexPoints } from "./ui";

// Extra words people might type to find a page (English + Arabic).
const PAGE_KEYWORDS: Record<string, string> = {
  "/": "dashboard home overview الرئيسية لوحة",
  "/scam-analyzer": "message sms whatsapp link url text screenshot رسالة رابط واتساب صورة نص احتيال",
  "/call-guard": "call phone voice listen microphone otp code مكالمة صوت متصل ميكروفون رمز",
  "/phone": "number caller iphone رقم جوال آيفون",
  "/email-security": "email mail eml phishing attachment إيميل بريد مرفق تصيد",
  "/forensics": "file image pdf attachment qr ملف صورة مرفق",
  "/endpoints": "laptop device computer agent firewall لابتوب جهاز حاسوب",
  "/network": "ip domain dns network عنوان دومين شبكة",
  "/graph": "graph map links correlation مخطط ربط خريطة",
  "/incidents": "incident case report police حادثة بلاغ قضية شرطة",
  "/prevention": "block blocklist prevent حظر منع",
  "/settings": "settings language users demo إعدادات لغة مستخدمين",
  "/integrations": "integrations firebase cloudflare virustotal urlhaus api تكاملات ربط",
  "/report": "report scam complaint police بلاغ إبلاغ شكوى احتيال",
  "/reports": "reports investigator cases demo data بلاغات تحقيق قضايا",
  "/learn": "learn education quiz awareness توعية تعلم اختبار",
};

const NAV: { section: DictKey; items: { href: string; key: DictKey; icon: any }[] }[] = [
  { section: "section_detect", items: [
    { href: "/", key: "nav_command", icon: LayoutDashboard },
    { href: "/scam-analyzer", key: "nav_scam", icon: ShieldAlert },
    { href: "/call-guard", key: "nav_calls", icon: PhoneCall },
    { href: "/phone", key: "nav_phone", icon: Smartphone },
    { href: "/email-security", key: "nav_email", icon: Mail },
    { href: "/forensics", key: "nav_forensics", icon: FileSearch },
    { href: "/endpoints", key: "nav_endpoints", icon: Cpu },
    { href: "/network", key: "nav_network", icon: Globe2 },
    { href: "/report", key: "nav_report", icon: FileWarning },
    { href: "/learn", key: "nav_learn", icon: GraduationCap },
  ]},
  { section: "section_respond", items: [
    { href: "/graph", key: "nav_graph", icon: Network },
    { href: "/reports", key: "nav_reports", icon: ClipboardList },
    { href: "/incidents", key: "nav_incidents", icon: Siren },
    { href: "/prevention", key: "nav_prevention", icon: ShieldCheck },
  ]},
  { section: "section_system", items: [{ href: "/settings", key: "nav_settings", icon: Settings }, { href: "/integrations", key: "nav_integrations", icon: Plug }] },
];


export function AppShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { t, lang, setLang } = useI18n();
  const [open, setOpen] = useState(false);
  const [me, setMe] = useState<Me | null>(null);
  const [offline, setOffline] = useState(false);
  const isLogin = path.startsWith("/login");
  const simple = useSimpleMode();
  useEffect(() => { document.documentElement.classList.toggle("simple", simple); }, [simple]);

  useEffect(() => {
    if (isLogin) return;
    if (!getToken()) {
      window.location.href = "/login";
      return;
    }
    setMe(getMe());
    const load = () => {
      apiGet<Me>("/api/auth/me").then((u) => { setMe(u); setOffline(false); })
        .catch((e) => setOffline(e?.status === 0));
    };
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, [isLogin]);

  const signOut = async () => {
    try { await apiSend("/api/auth/logout", "POST"); } catch {}
    await firebaseSignOut();
    setSession(null, null);
    window.location.href = "/login";
  };
  useEffect(() => setOpen(false), [path]);

  const active = (href: string) => (href === "/" ? path === "/" : path === href || path.startsWith(href + "/"));

  if (isLogin) return <>{children}</>;

  const sidebar = (
    <nav className="flex h-full flex-col gap-6 overflow-y-auto px-3 py-5" aria-label={tr("Main")}>
      <Link href="/" className="flex items-center gap-3 rounded-lg px-2 focus-visible:outline-2 focus-visible:outline-honey">
        <BeeMark className="h-10 w-10" />
        <div>
          <div className="font-display text-lg font-semibold leading-tight text-white" style={{ fontVariationSettings: '"HEXP" 60' }}>Three Bees</div>
          <div className="text-xs leading-tight text-slate-400">{tr("Security Center")}</div>
        </div>
      </Link>
      {NAV.map((sec) => (
        <div key={sec.section}>
          <div className="mb-1.5 px-3 text-[11px] font-medium uppercase tracking-wider text-slate-500">{t(sec.section)}</div>
          <ul className="space-y-0.5">
            {sec.items.map((it) => (
              <li key={it.href}>
                <Link href={it.href} aria-current={active(it.href) ? "page" : undefined}
                  className={cn("group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition focus-visible:outline-2 focus-visible:outline-honey",
                    active(it.href) ? "bg-comb font-medium text-white" : "text-slate-300 hover:bg-comb/70 hover:text-white")}>
                  <it.icon className={cn("h-4 w-4", active(it.href) ? "text-honey" : "text-slate-400 group-hover:text-slate-200")} />
                  {t(it.key)}
                  {active(it.href) && (
                    <svg viewBox="0 0 10 10" className="ms-auto h-2.5 w-2.5" aria-hidden="true"><polygon points={hexPoints(5, 5, 5)} fill="var(--color-honey)" /></svg>
                  )}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <p className="mt-auto px-3 text-xs leading-relaxed text-slate-500">
        {tr("Results are based on the evidence found and can't catch every attack.")}
      </p>
    </nav>
  );

  return (
    <div className="flex min-h-screen">
      <aside className="hive-pattern sticky top-0 hidden h-screen w-64 shrink-0 lg:block">{sidebar}</aside>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-hive/50" onClick={() => setOpen(false)} />
          <aside className="hive-pattern absolute inset-y-0 start-0 w-72">
            <button className="absolute end-3 top-3 text-slate-300" aria-label={tr("Close menu")} onClick={() => setOpen(false)}><X className="h-5 w-5" /></button>
            {sidebar}
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-ink-700 bg-ink-900/95 px-4 py-2.5">
          <button className="rounded-md p-1.5 text-ink-300 hover:bg-ink-800 lg:hidden" aria-label={tr("Open menu")} onClick={() => setOpen(true)}><Menu className="h-5 w-5" /></button>
          <SearchBox pages={NAV.flatMap((s) => s.items).map((it) => ({ href: it.href, label: t(it.key), icon: it.icon, keywords: PAGE_KEYWORDS[it.href] || "" }))} />
          {offline && (
            <span className="flex shrink-0 items-center gap-1.5 rounded-full bg-red-50 px-2.5 py-1 text-xs font-medium text-crit"><Activity className="h-3.5 w-3.5" /> {tr("Can't reach the server — start the backend")}</span>
          )}
          <div className="ms-auto flex items-center gap-2">
            <button onClick={() => setSimpleMode(!simple)} aria-pressed={simple}
              className={cn("flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-sm ring-1", simple ? "bg-honey text-hive ring-honey" : "text-ink-300 ring-ink-600 hover:bg-ink-800")}>
              <Accessibility className="h-4 w-4" /> <span className="hidden whitespace-nowrap md:inline">{tr("Simple mode")}</span>
            </button>
            <button onClick={() => setLang(lang === "en" ? "ar" : "en")} className="rounded-lg px-2.5 py-1.5 text-sm text-ink-300 ring-1 ring-ink-600 hover:bg-ink-800" aria-label={tr("Switch language")}>
              {lang === "en" ? "العربية" : tr("English")}
            </button>
            {me && (
              <span className="hidden whitespace-nowrap text-sm text-ink-300 xl:inline">{me.full_name} · <span className="text-ink-400">{tr(me.role)}</span></span>
            )}
            <button onClick={signOut} className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-sm text-ink-300 ring-1 ring-ink-600 hover:bg-ink-800">
              <LogOut className="h-4 w-4" /> <span className="hidden whitespace-nowrap md:inline">{tr("Sign out")}</span>
            </button>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1500px] flex-1 px-4 py-6 md:px-6">{children}</main>
      </div>
    </div>
  );
}

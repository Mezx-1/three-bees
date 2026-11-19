"use client";

import { Activity, Bug, Cpu, FileSearch, Globe2, LayoutDashboard, Mail, Menu, Network, Settings, ShieldAlert, ShieldCheck, Siren, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { apiGet, getUser, setUser } from "@/lib/api";
import { DictKey, useI18n } from "@/lib/i18n";
import { WolfMark } from "./WolfMark";
import { cn } from "./ui";

const NAV: { section: DictKey; items: { href: string; key: DictKey; icon: any }[] }[] = [
  { section: "section_detect", items: [
    { href: "/", key: "nav_command", icon: LayoutDashboard },
    { href: "/scam-analyzer", key: "nav_scam", icon: ShieldAlert },
    { href: "/email-security", key: "nav_email", icon: Mail },
    { href: "/forensics", key: "nav_forensics", icon: FileSearch },
    { href: "/endpoints", key: "nav_endpoints", icon: Cpu },
    { href: "/network", key: "nav_network", icon: Globe2 },
  ]},
  { section: "section_respond", items: [
    { href: "/graph", key: "nav_graph", icon: Network },
    { href: "/incidents", key: "nav_incidents", icon: Siren },
    { href: "/prevention", key: "nav_prevention", icon: ShieldCheck },
  ]},
  { section: "section_system", items: [{ href: "/settings", key: "nav_settings", icon: Settings }] },
];

type U = { username: string; full_name: string; role: string };

export function AppShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { t, lang, setLang } = useI18n();
  const [open, setOpen] = useState(false);
  const [users, setUsers] = useState<U[]>([]);
  const [me, setMe] = useState("omar.analyst");
  const [sys, setSys] = useState<any>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    setMe(getUser());
    const load = () => {
      apiGet<U[]>("/api/users").then((u) => { setUsers(u); setOffline(false); }).catch(() => setOffline(true));
      apiGet("/api/system/status").then(setSys).catch(() => setOffline(true));
    };
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, []);
  useEffect(() => setOpen(false), [path]);

  const active = (href: string) => (href === "/" ? path === "/" : path.startsWith(href));
  const meUser = users.find((u) => u.username === me);

  const sidebar = (
    <nav className="flex h-full flex-col gap-6 overflow-y-auto px-3 py-5" aria-label="Main">
      <Link href="/" className="flex items-center gap-3 px-2">
        <WolfMark />
        <div>
          <div className="text-lg font-bold tracking-[0.2em] text-white">WOLVE<span className="text-volt"> AI</span></div>
          <div className="text-[10px] leading-tight text-ink-400">{t("brand_tag")}</div>
        </div>
      </Link>
      {NAV.map((sec) => (
        <div key={sec.section}>
          <div className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-500">{t(sec.section)}</div>
          <ul className="space-y-0.5">
            {sec.items.map((it) => (
              <li key={it.href}>
                <Link href={it.href} aria-current={active(it.href) ? "page" : undefined}
                  className={cn("group flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition",
                    active(it.href) ? "bg-volt/10 text-white ring-1 ring-volt/30" : "text-ink-300 hover:bg-ink-800 hover:text-ink-100")}>
                  <it.icon className={cn("h-4 w-4", active(it.href) ? "text-volt" : "text-ink-400 group-hover:text-ink-200")} />
                  {t(it.key)}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <div className="mt-auto rounded-lg border border-ink-700 bg-ink-850 p-3 text-[11px] text-ink-400">
        <div className="mb-1 flex items-center gap-1.5 font-semibold text-ink-300"><Bug className="h-3.5 w-3.5" /> Hackathon MVP</div>
        Detection is evidence-based and cannot catch every attack. Simulated data is always labelled.
      </div>
    </nav>
  );

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-e border-ink-800 bg-ink-900/70 backdrop-blur lg:block">{sidebar}</aside>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 start-0 w-72 border-e border-ink-700 bg-ink-900">
            <button className="absolute end-3 top-3 text-ink-300" aria-label="Close menu" onClick={() => setOpen(false)}><X className="h-5 w-5" /></button>
            {sidebar}
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-ink-800 bg-ink-950/80 px-4 py-2.5 backdrop-blur">
          <button className="rounded-md p-1.5 text-ink-300 hover:bg-ink-800 lg:hidden" aria-label="Open menu" onClick={() => setOpen(true)}><Menu className="h-5 w-5" /></button>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {offline ? (
              <span className="flex items-center gap-1.5 rounded-md bg-crit/15 px-2 py-1 text-crit ring-1 ring-crit/40"><Activity className="h-3.5 w-3.5" /> Backend offline</span>
            ) : (
              <span className="flex items-center gap-1.5 rounded-md bg-safe/10 px-2 py-1 text-safe ring-1 ring-safe/30"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-safe" /> Engine online</span>
            )}
            {sys && (
              <>
                <span className={cn("rounded-md px-2 py-1 ring-1", sys.ai.available ? "bg-fuchsia-500/10 text-fuchsia-300 ring-fuchsia-400/30" : "bg-ink-800 text-ink-400 ring-ink-600")}
                  title={sys.ai.reason || sys.ai.model}>AI: {sys.ai.available ? "online" : "offline"}</span>
                <span className="hidden rounded-md bg-ink-800 px-2 py-1 text-ink-300 ring-1 ring-ink-600 sm:inline" title="OCR engine">OCR: {sys.ocr.engine}</span>
              </>
            )}
          </div>
          <div className="ms-auto flex items-center gap-2">
            <button onClick={() => setLang(lang === "en" ? "ar" : "en")} className="rounded-md px-2 py-1 text-xs font-semibold text-ink-200 ring-1 ring-ink-600 hover:bg-ink-800" aria-label="Switch language">
              {lang === "en" ? "العربية" : "English"}
            </button>
            <label className="flex items-center gap-2 text-xs text-ink-400">
              <span className="hidden sm:inline">{t("acting_as")}</span>
              <select value={me} onChange={(e) => { setMe(e.target.value); setUser(e.target.value); }}
                className="rounded-md border border-ink-600 bg-ink-850 px-2 py-1 text-xs text-ink-100 focus:border-volt focus:outline-none">
                {users.length === 0 && <option value={me}>{me}</option>}
                {users.map((u) => <option key={u.username} value={u.username}>{u.full_name} · {u.role}</option>)}
              </select>
            </label>
            {meUser && <span className="hidden rounded bg-ink-800 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-volt ring-1 ring-volt/30 md:inline">{meUser.role}</span>}
          </div>
        </header>
        <main className="grid-bg mx-auto w-full max-w-[1500px] flex-1 px-4 py-6 md:px-6">{children}</main>
      </div>
    </div>
  );
}

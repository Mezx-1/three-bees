"use client";

import { Activity, PhoneCall, Smartphone, Cpu, FileSearch, Globe2, LayoutDashboard, Mail, Menu, Network, Settings, ShieldAlert, ShieldCheck, Siren, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { apiGet, getUser, setUser } from "@/lib/api";
import { DictKey, useI18n, tr } from "@/lib/i18n";
import { WolfMark } from "./WolfMark";
import { cn } from "./ui";

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
    const [offline, setOffline] = useState(false);

  useEffect(() => {
    setMe(getUser());
    const load = () => {
      apiGet<U[]>("/api/users").then((u) => { setUsers(u); setOffline(false); }).catch(() => setOffline(true));
    };
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, []);
  useEffect(() => setOpen(false), [path]);

  const active = (href: string) => (href === "/" ? path === "/" : path.startsWith(href));

  const sidebar = (
    <nav className="flex h-full flex-col gap-6 overflow-y-auto px-3 py-5" aria-label={tr("Main")}>
      <Link href="/" className="flex items-center gap-3 px-2">
        <WolfMark />
        <div>
          <div className="text-lg font-bold tracking-wide text-ink-100">{tr("WOLVE")}</div>
          <div className="text-xs leading-tight text-ink-400">{tr("Security Center")}</div>
        </div>
      </Link>
      {NAV.map((sec) => (
        <div key={sec.section}>
          <div className="mb-1.5 px-3 text-xs font-medium text-ink-400">{t(sec.section)}</div>
          <ul className="space-y-0.5">
            {sec.items.map((it) => (
              <li key={it.href}>
                <Link href={it.href} aria-current={active(it.href) ? "page" : undefined}
                  className={cn("group flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition",
                    active(it.href) ? "bg-blue-50 font-medium text-volt" : "text-ink-300 hover:bg-ink-800 hover:text-ink-100")}>
                  <it.icon className={cn("h-4 w-4", active(it.href) ? "text-volt" : "text-ink-400 group-hover:text-ink-200")} />
                  {t(it.key)}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <p className="mt-auto px-3 text-xs leading-relaxed text-ink-400">
        {tr("Results are based on the evidence found and can't catch every attack. Demo data is always marked.")}
      </p>
    </nav>
  );

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-e border-ink-700 bg-ink-900 lg:block">{sidebar}</aside>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/30" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 start-0 w-72 border-e border-ink-700 bg-ink-900">
            <button className="absolute end-3 top-3 text-ink-300" aria-label={tr("Close menu")} onClick={() => setOpen(false)}><X className="h-5 w-5" /></button>
            {sidebar}
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-ink-700 bg-ink-900/95 px-4 py-2.5">
          <button className="rounded-md p-1.5 text-ink-300 hover:bg-ink-800 lg:hidden" aria-label={tr("Open menu")} onClick={() => setOpen(true)}><Menu className="h-5 w-5" /></button>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {offline ? (
              <span className="flex items-center gap-1.5 rounded-full bg-red-50 px-2.5 py-1 font-medium text-crit"><Activity className="h-3.5 w-3.5" /> {tr("Can't reach the server — start the backend")}</span>
            ) : (
              <span className="flex items-center gap-1.5 text-ink-400"><span className="h-2 w-2 rounded-full bg-green-500" /> {tr("Connected")}</span>
            )}
          </div>
          <div className="ms-auto flex items-center gap-2">
            <button onClick={() => setLang(lang === "en" ? "ar" : "en")} className="rounded-lg px-2.5 py-1.5 text-sm text-ink-300 ring-1 ring-ink-600 hover:bg-ink-800" aria-label={tr("Switch language")}>
              {lang === "en" ? "العربية" : tr("English")}
            </button>
            <label className="flex items-center gap-2 text-sm text-ink-400">
              <span className="hidden sm:inline">{t("acting_as")}</span>
              <select value={me} onChange={(e) => { setMe(e.target.value); setUser(e.target.value); }}
                className="rounded-lg border border-ink-600 bg-ink-900 px-2.5 py-1.5 text-sm text-ink-100 focus:border-volt focus:outline-none">
                {users.length === 0 && <option value={me}>{me}</option>}
                {users.map((u) => <option key={u.username} value={u.username}>{u.full_name} · {u.role}</option>)}
              </select>
            </label>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1500px] flex-1 px-4 py-6 md:px-6">{children}</main>
      </div>
    </div>
  );
}

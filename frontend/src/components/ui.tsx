"use client";

import clsx from "clsx";
import { AlertTriangle, CheckCircle2, FlaskConical, Info, Loader2, X } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { Severity } from "@/lib/types";

export const cn = clsx;

export function timeAgo(iso?: string | null) {
  if (!iso) return "—";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function fmtTime(iso?: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export const SEV_STYLE: Record<string, string> = {
  critical: "bg-crit/15 text-crit ring-crit/40",
  high: "bg-high/15 text-high ring-high/40",
  medium: "bg-warn/15 text-warn ring-warn/40",
  low: "bg-safe/10 text-safe ring-safe/30",
  info: "bg-ink-600/40 text-ink-300 ring-ink-500/40",
};
export const SEV_HEX: Record<string, string> = { critical: "#f43f5e", high: "#fb923c", medium: "#f59e0b", low: "#22c55e", info: "#5b6f95" };

export function Card({ className, children, title, action, subtitle }: { className?: string; children: React.ReactNode; title?: React.ReactNode; action?: React.ReactNode; subtitle?: React.ReactNode }) {
  return (
    <section className={cn("rounded-xl border border-ink-700 bg-ink-900/80 shadow-[0_0_0_1px_rgba(255,255,255,0.01)] backdrop-blur", className)}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 border-b border-ink-700/70 px-4 py-3">
          <div>
            <h2 className="text-sm font-semibold tracking-wide text-ink-100">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-ink-400">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

type BtnVariant = "primary" | "ghost" | "danger" | "subtle" | "success" | "warn";
export function Button({ variant = "subtle", loading, className, children, disabled, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant; loading?: boolean }) {
  const v: Record<BtnVariant, string> = {
    primary: "bg-volt text-ink-950 hover:bg-cyan-300 font-semibold",
    ghost: "bg-transparent text-ink-200 hover:bg-ink-700/60",
    subtle: "bg-ink-700/70 text-ink-100 hover:bg-ink-600 ring-1 ring-inset ring-ink-600",
    danger: "bg-crit/90 text-white hover:bg-crit",
    success: "bg-safe/90 text-ink-950 hover:bg-safe font-semibold",
    warn: "bg-warn/90 text-ink-950 hover:bg-warn font-semibold",
  };
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={cn("inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm transition disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-volt", v[variant], className)}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
}

export function SeverityBadge({ s, className }: { s: Severity | string; className?: string }) {
  return <span className={cn("inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider ring-1", SEV_STYLE[s] || SEV_STYLE.info, s === "critical" && "pulse-crit", className)}>{s}</span>;
}

export function Pill({ children, className, title }: { children: React.ReactNode; className?: string; title?: string }) {
  return <span title={title} className={cn("inline-flex items-center gap-1 rounded-md bg-ink-700/70 px-2 py-0.5 text-[11px] font-medium text-ink-200 ring-1 ring-ink-600", className)}>{children}</span>;
}

export function SimBadge({ label = "Simulated" }: { label?: string }) {
  return (
    <Pill className="bg-violet-500/15 text-violet-300 ring-violet-400/40" title="Generated for demonstration — not real telemetry">
      <FlaskConical className="h-3 w-3" /> {label}
    </Pill>
  );
}

const SOURCE_STYLE: Record<string, [string, string]> = {
  verified: ["Verified", "bg-azure/15 text-sky-300 ring-azure/40"],
  heuristic: ["Heuristic", "bg-ink-600/50 text-ink-200 ring-ink-500"],
  intel: ["External intel", "bg-teal-500/15 text-teal-300 ring-teal-400/40"],
  ai: ["AI-generated", "bg-fuchsia-500/15 text-fuchsia-300 ring-fuchsia-400/40"],
};
export function SourceBadge({ s }: { s: string }) {
  const [label, cls] = SOURCE_STYLE[s] || [s, SOURCE_STYLE.heuristic[1]];
  return <span className={cn("inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ring-1", cls)}>{label}</span>;
}

const STATUS_STYLE: Record<string, string> = {
  open: "text-crit", investigating: "text-warn", contained: "text-sky-300", resolved: "text-safe", false_positive: "text-ink-300",
  new: "text-ink-200", suspicious: "text-warn", quarantined: "text-violet-300", safe: "text-safe", reported: "text-sky-300",
  healthy: "text-safe", at_risk: "text-warn", compromised: "text-crit", isolation_recommended: "text-high", offline: "text-ink-400",
};
export function StatusDot({ s }: { s: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium capitalize", STATUS_STYLE[s] || "text-ink-200")}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {s.replace(/_/g, " ")}
    </span>
  );
}

export function ScoreRing({ score, severity, size = 116 }: { score: number; severity: string; size?: number }) {
  const r = 46;
  const c = 2 * Math.PI * r;
  const color = SEV_HEX[severity] || SEV_HEX.info;
  return (
    <div className="relative" style={{ width: size, height: size }} role="img" aria-label={`Risk score ${score} of 100`}>
      <svg viewBox="0 0 110 110" className="h-full w-full -rotate-90">
        <circle cx="55" cy="55" r={r} fill="none" stroke="#16223a" strokeWidth="9" />
        <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth="9" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c - (c * score) / 100} style={{ transition: "stroke-dashoffset 0.9s ease" }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-3xl font-bold" style={{ color }}>{score}</span>
        <span className="text-[10px] uppercase tracking-widest text-ink-400">/ 100</span>
      </div>
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-ink-300">
      <Loader2 className="h-4 w-4 animate-spin text-volt" /> {label || "Loading…"}
    </div>
  );
}

export function ScanBar() {
  return <div className="scan-bar relative h-1 w-full overflow-hidden rounded bg-ink-700" />;
}

export function EmptyState({ icon: Icon = Info, title, children }: { icon?: any; title: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-ink-600 px-6 py-10 text-center">
      <Icon className="h-7 w-7 text-ink-400" />
      <p className="text-sm font-medium text-ink-200">{title}</p>
      {children && <div className="max-w-md text-xs text-ink-400">{children}</div>}
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-lg border border-crit/40 bg-crit/10 p-3 text-sm text-rose-200">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-crit" />
      <div className="flex-1">{error}</div>
      {onRetry && <Button variant="ghost" className="!px-2 !py-1 text-xs" onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export function PageHeader({ title, subtitle, icon: Icon, actions }: { title: string; subtitle?: string; icon?: any; actions?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="flex items-center gap-3">
        {Icon && (
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-volt/10 ring-1 ring-volt/30">
            <Icon className="h-5 w-5 text-volt" />
          </div>
        )}
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-white">{title}</h1>
          {subtitle && <p className="text-sm text-ink-300">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export const inputCls = "w-full rounded-lg border border-ink-600 bg-ink-850 px-3 py-2 text-sm text-ink-100 placeholder:text-ink-400 focus:border-volt focus:outline-none focus:ring-1 focus:ring-volt";

export function Label({ children, htmlFor }: { children: React.ReactNode; htmlFor?: string }) {
  return <label htmlFor={htmlFor} className="mb-1 block text-xs font-medium uppercase tracking-wider text-ink-300">{children}</label>;
}

export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: { value: T; label: React.ReactNode }[] }) {
  return (
    <div role="tablist" className="inline-flex flex-wrap gap-1 rounded-lg bg-ink-850 p-1 ring-1 ring-ink-700">
      {items.map((it) => (
        <button key={it.value} role="tab" aria-selected={value === it.value} onClick={() => onChange(it.value)}
          className={cn("rounded-md px-3 py-1.5 text-sm transition", value === it.value ? "bg-ink-600 text-white shadow" : "text-ink-300 hover:text-ink-100")}>
          {it.label}
        </button>
      ))}
    </div>
  );
}

export function Stat({ label, value, icon: Icon, tone = "default", hint }: { label: string; value: React.ReactNode; icon?: any; tone?: "default" | "crit" | "warn" | "safe" | "volt"; hint?: string }) {
  const tones = { default: "text-white", crit: "text-crit", warn: "text-warn", safe: "text-safe", volt: "text-volt" };
  return (
    <div className="rounded-xl border border-ink-700 bg-ink-900/80 p-4">
      <div className="flex items-center justify-between text-xs uppercase tracking-wider text-ink-400">
        {label}
        {Icon && <Icon className="h-4 w-4 text-ink-400" />}
      </div>
      <div className={cn("mt-2 font-mono text-3xl font-semibold", tones[tone])}>{value}</div>
      {hint && <div className="mt-1 text-xs text-ink-400">{hint}</div>}
    </div>
  );
}

// ---- data hook ------------------------------------------------------------
export function useApi<T>(fn: () => Promise<T>, deps: unknown[] = [], pollMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      setData(await fnRef.current());
      setError(null);
    } catch (e: any) {
      setError(e?.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    load();
    const onUser = () => load(true);
    window.addEventListener("wolve-user", onUser);
    window.addEventListener("wolve-refresh", onUser);
    let t: any;
    if (pollMs) t = setInterval(() => load(true), pollMs);
    return () => {
      window.removeEventListener("wolve-user", onUser);
      window.removeEventListener("wolve-refresh", onUser);
      if (t) clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, error, loading, reload: load, setData };
}

export const broadcastRefresh = () => window.dispatchEvent(new Event("wolve-refresh"));

// ---- toasts ----------------------------------------------------------------
type Toast = { id: number; kind: "ok" | "err" | "info"; text: string };
const ToastCtx = createContext<(kind: Toast["kind"], text: string) => void>(() => {});
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((kind: Toast["kind"], text: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div aria-live="polite" className="pointer-events-none fixed bottom-4 end-4 z-50 flex w-96 max-w-[calc(100vw-2rem)] flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} className={cn("pointer-events-auto fade-up flex items-start gap-2 rounded-lg border p-3 text-sm shadow-xl backdrop-blur",
            t.kind === "ok" && "border-safe/40 bg-ink-850/95 text-ink-100", t.kind === "err" && "border-crit/50 bg-ink-850/95 text-rose-200", t.kind === "info" && "border-volt/40 bg-ink-850/95 text-ink-100")}>
            {t.kind === "ok" ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-safe" /> : t.kind === "err" ? <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-crit" /> : <Info className="mt-0.5 h-4 w-4 shrink-0 text-volt" />}
            <span className="flex-1">{t.text}</span>
            <button aria-label="Dismiss" onClick={() => setToasts((x) => x.filter((y) => y.id !== t.id))}><X className="h-4 w-4 text-ink-400" /></button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}
export const useToast = () => useContext(ToastCtx);

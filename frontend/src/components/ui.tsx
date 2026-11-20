"use client";

import clsx from "clsx";
import { AlertTriangle, CheckCircle2, FlaskConical, Info, Loader2, X } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { locale, tr, trf } from "@/lib/i18n";
import type { Severity } from "@/lib/types";

export const cn = clsx;

export function timeAgo(iso?: string | null) {
  if (!iso) return "—";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 45) return tr("just now");
  if (s < 3600) return trf("{n}m ago", { n: Math.round(s / 60) });
  if (s < 86400) return trf("{n}h ago", { n: Math.round(s / 3600) });
  return trf("{n}d ago", { n: Math.round(s / 86400) });
}

export function fmtTime(iso?: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(locale(), { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export const SEV_STYLE: Record<string, string> = {
  critical: "bg-crit/15 text-crit ring-crit/40",
  high: "bg-high/15 text-high ring-high/40",
  medium: "bg-warn/15 text-warn ring-warn/40",
  low: "bg-safe/10 text-safe ring-safe/30",
  info: "bg-ink-800 text-ink-300 ring-ink-600",
};
export const SEV_HEX: Record<string, string> = { critical: "#d92d20", high: "#e04f16", medium: "#dc6803", low: "#079455", info: "#98a2b3" };

export function Card({ className, children, title, action, subtitle }: { className?: string; children: React.ReactNode; title?: React.ReactNode; action?: React.ReactNode; subtitle?: React.ReactNode }) {
  return (
    <section className={cn("rounded-xl border border-ink-700 bg-ink-900 shadow-[0_1px_2px_rgba(16,24,40,0.05)]", className)}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 border-b border-ink-700/70 px-4 py-3">
          <div>
            <h2 className="text-[15px] font-semibold text-ink-100">{title}</h2>
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
    primary: "bg-volt text-white hover:bg-blue-800 font-medium shadow-sm",
    ghost: "bg-transparent text-ink-300 hover:bg-ink-800 hover:text-ink-100",
    subtle: "bg-ink-900 text-ink-200 hover:bg-ink-800 ring-1 ring-inset ring-ink-600 shadow-sm",
    danger: "bg-crit text-white hover:bg-red-700",
    success: "bg-safe text-white hover:bg-green-800 font-medium",
    warn: "bg-amber-600 text-white hover:bg-amber-700 font-medium",
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
  return <span className={cn("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ring-1 ring-inset", SEV_STYLE[s] || SEV_STYLE.info, className)}>{tr(s)}</span>;
}

export function Pill({ children, className, title }: { children: React.ReactNode; className?: string; title?: string }) {
  return <span title={title} className={cn("inline-flex items-center gap-1 rounded-full bg-ink-800 px-2.5 py-0.5 text-xs font-medium text-ink-300 ring-1 ring-inset ring-ink-700", className)}>{children}</span>;
}

export function SimBadge({ label = "Simulated" }: { label?: string }) {
  label = tr(label);
  return (
    <Pill className="bg-violet-50 text-violet-700 ring-violet-200" title={tr("Generated for demonstration — not real telemetry")}>
      <FlaskConical className="h-3 w-3" /> {label}
    </Pill>
  );
}

const SOURCE_STYLE: Record<string, [string, string]> = {
  verified: ["Confirmed", "bg-azure/15 text-sky-700 ring-azure/40"],
  heuristic: ["Pattern", "bg-ink-800 text-ink-300 ring-ink-600"],
  intel: ["External source", "bg-teal-50 text-teal-700 ring-teal-200"],
  ai: ["AI opinion", "bg-slate-100 text-slate-600 ring-slate-300"],
};
export function SourceBadge({ s }: { s: string }) {
  const [label, cls] = SOURCE_STYLE[s] || [s, SOURCE_STYLE.heuristic[1]];
  return <span className={cn("inline-flex rounded px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", cls)}>{tr(label)}</span>;
}

const STATUS_STYLE: Record<string, string> = {
  open: "text-crit", investigating: "text-warn", contained: "text-sky-700", resolved: "text-safe", false_positive: "text-ink-300",
  new: "text-ink-200", suspicious: "text-warn", quarantined: "text-violet-700", safe: "text-safe", reported: "text-sky-700",
  healthy: "text-safe", at_risk: "text-warn", compromised: "text-crit", isolation_recommended: "text-high", offline: "text-ink-400",
};
export function StatusDot({ s }: { s: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium capitalize", STATUS_STYLE[s] || "text-ink-200")}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {tr(s.replace(/_/g, " "))}
    </span>
  );
}

export function ScoreRing({ score, severity, size = 116 }: { score: number; severity: string; size?: number }) {
  const r = 46;
  const c = 2 * Math.PI * r;
  const color = SEV_HEX[severity] || SEV_HEX.info;
  return (
    <div className="relative" style={{ width: size, height: size }} role="img" aria-label={trf("Risk score {score} of 100", { score })}>
      <svg viewBox="0 0 110 110" className="h-full w-full -rotate-90">
        <circle cx="55" cy="55" r={r} fill="none" stroke="#eef1f5" strokeWidth="9" />
        <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth="9" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c - (c * score) / 100} style={{ transition: "stroke-dashoffset 0.9s ease" }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-semibold tabular-nums" style={{ color }}>{score}</span>
        <span className="text-xs text-ink-400">{tr("out of 100")}</span>
      </div>
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-ink-300">
      <Loader2 className="h-4 w-4 animate-spin text-volt" /> {label || tr("Loading…")}
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
    <div role="alert" className="flex items-start gap-3 rounded-lg border border-crit/40 bg-crit/10 p-3 text-sm text-rose-700">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-crit" />
      <div className="flex-1">{tr(error)}</div>
      {onRetry && <Button variant="ghost" className="!px-2 !py-1 text-xs" onClick={onRetry}>{tr("Retry")}</Button>}
    </div>
  );
}

export function PageHeader({ title, subtitle, icon: Icon, actions }: { title: string; subtitle?: string; icon?: any; actions?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="flex items-center gap-3">
        {Icon && (
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-50 text-volt">
            <Icon className="h-5 w-5 text-volt" />
          </div>
        )}
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-ink-100">{title}</h1>
          {subtitle && <p className="text-sm text-ink-300">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export const inputCls = "w-full rounded-lg border border-ink-600 bg-ink-900 px-3 py-2 text-sm text-ink-100 shadow-sm placeholder:text-ink-500 focus:border-volt focus:outline-none focus:ring-1 focus:ring-volt";

export function Label({ children, htmlFor }: { children: React.ReactNode; htmlFor?: string }) {
  return <label htmlFor={htmlFor} className="mb-1.5 block text-sm font-medium text-ink-200">{children}</label>;
}

export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: { value: T; label: React.ReactNode }[] }) {
  return (
    <div role="tablist" className="inline-flex flex-wrap gap-1 rounded-lg bg-ink-800 p-1">
      {items.map((it) => (
        <button key={it.value} role="tab" aria-selected={value === it.value} onClick={() => onChange(it.value)}
          className={cn("rounded-md px-3 py-1.5 text-sm transition", value === it.value ? "bg-ink-900 font-medium text-ink-100 shadow-sm" : "text-ink-300 hover:text-ink-100")}>
          {it.label}
        </button>
      ))}
    </div>
  );
}

export function Stat({ label, value, icon: Icon, tone = "default", hint }: { label: string; value: React.ReactNode; icon?: any; tone?: "default" | "crit" | "warn" | "safe" | "volt"; hint?: string }) {
  const tones = { default: "text-ink-100", crit: "text-crit", warn: "text-warn", safe: "text-safe", volt: "text-volt" };
  return (
    <div className="rounded-xl border border-ink-700 bg-ink-900 p-4 shadow-[0_1px_2px_rgba(16,24,40,0.05)]">
      <div className="flex items-center justify-between text-sm text-ink-400">
        {label}
        {Icon && <Icon className="h-4 w-4 text-ink-400" />}
      </div>
      <div className={cn("mt-2 text-3xl font-semibold tabular-nums", tones[tone])}>{value}</div>
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
    window.addEventListener("3b-user", onUser);
    window.addEventListener("3b-refresh", onUser);
    let t: any;
    if (pollMs) t = setInterval(() => load(true), pollMs);
    return () => {
      window.removeEventListener("3b-user", onUser);
      window.removeEventListener("3b-refresh", onUser);
      if (t) clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, error, loading, reload: load, setData };
}

export const broadcastRefresh = () => window.dispatchEvent(new Event("3b-refresh"));

// ---- toasts ----------------------------------------------------------------
type Toast = { id: number; kind: "ok" | "err" | "info"; text: string };
const ToastCtx = createContext<(kind: Toast["kind"], text: string) => void>(() => {});
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((kind: Toast["kind"], text: string) => {
    const id = Date.now() + Math.random();
    text = tr(text);
    setToasts((t) => [...t, { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div aria-live="polite" className="pointer-events-none fixed bottom-4 end-4 z-50 flex w-96 max-w-[calc(100vw-2rem)] flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} className={cn("pointer-events-auto fade-up flex items-start gap-2 rounded-lg border p-3 text-sm shadow-lg",
            t.kind === "ok" && "border-ink-700 bg-ink-900 text-ink-100", t.kind === "err" && "border-crit/30 bg-ink-900 text-rose-700", t.kind === "info" && "border-ink-700 bg-ink-900 text-ink-100")}>
            {t.kind === "ok" ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-safe" /> : t.kind === "err" ? <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-crit" /> : <Info className="mt-0.5 h-4 w-4 shrink-0 text-volt" />}
            <span className="flex-1">{t.text}</span>
            <button aria-label={tr("Dismiss")} onClick={() => setToasts((x) => x.filter((y) => y.id !== t.id))}><X className="h-4 w-4 text-ink-400" /></button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}
export const useToast = () => useContext(ToastCtx);

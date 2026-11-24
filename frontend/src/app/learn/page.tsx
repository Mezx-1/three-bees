"use client";

import { AudioLines, Briefcase, CheckCircle2, GraduationCap, KeyRound, Landmark, MailWarning, MessagesSquare, PhoneCall, QrCode, ShoppingCart, TrendingUp, UserX, Video, XCircle } from "lucide-react";
import { useState } from "react";
import { Button, Card, cn, PageHeader } from "@/components/ui";
import { tr, useI18n } from "@/lib/i18n";
import { QUIZZES, TOPICS } from "@/lib/learn";

const ICONS: Record<string, any> = { LuMailWarning: MailWarning, LuPhoneCall: PhoneCall, LuLandmark: Landmark, LuBriefcase: Briefcase,
  LuShoppingCart: ShoppingCart, LuTrendingUp: TrendingUp, LuUserX: UserX, LuMessagesSquare: MessagesSquare, LuAudioLines: AudioLines,
  LuVideo: Video, LuQrCode: QrCode, LuKeyRound: KeyRound };

function QuizCard({ i }: { i: number }) {
  const { lang } = useI18n();
  const q = QUIZZES[i];
  const [pick, setPick] = useState<number | null>(null);
  const L = (t: { en: string; ar: string }) => t[lang];
  return (
    <div className="rounded-xl border border-ink-700 bg-ink-900 p-4">
      <p className="font-medium text-ink-100">{i + 1}. {L(q.q)}</p>
      <div className="mt-3 grid gap-2">
        {q.options.map((o, k) => {
          const chosen = pick === k, right = k === q.answer;
          return (
            <button key={k} disabled={pick !== null} onClick={() => setPick(k)}
              className={cn("flex items-center gap-2 rounded-lg border px-3 py-2 text-start text-sm transition",
                pick === null ? "border-ink-600 hover:border-honey hover:bg-wax/60" : right ? "border-green-300 bg-green-50 text-safe" : chosen ? "border-red-300 bg-red-50 text-crit" : "border-ink-700 text-ink-400")}>
              {pick !== null && right && <CheckCircle2 className="h-4 w-4 shrink-0" />}
              {pick !== null && chosen && !right && <XCircle className="h-4 w-4 shrink-0" />}
              {L(o)}
            </button>
          );
        })}
      </div>
      {pick !== null && (
        <p className={cn("mt-3 rounded-lg p-3 text-sm", pick === q.answer ? "bg-green-50 text-ink-100" : "bg-amber-50 text-ink-100")}>
          <b>{pick === q.answer ? tr("Correct.") : tr("Not quite.")}</b> {L(q.why)}
        </p>
      )}
    </div>
  );
}

export default function Learn() {
  const { lang } = useI18n();
  const [open, setOpen] = useState<string>(TOPICS[0].id);
  const L = (t: { en: string; ar: string }) => t[lang];
  const t = TOPICS.find((x) => x.id === open)!;
  const Icon = ICONS[t.icon];
  return (
    <div className="space-y-5">
      <PageHeader title={tr("Learn About Scams")} icon={GraduationCap}
        subtitle={tr("How common scams work, the warning signs, and what to do. All examples are fictional.")} />
      <div className="grid gap-5 xl:grid-cols-[280px_1fr]">
        <nav aria-label={tr("Scam types")} className="grid grid-cols-2 gap-1.5 sm:grid-cols-3 xl:grid-cols-1">
          {TOPICS.map((x) => {
            const I = ICONS[x.icon];
            return (
              <button key={x.id} onClick={() => setOpen(x.id)} aria-current={open === x.id}
                className={cn("flex items-center gap-2 rounded-lg px-3 py-2 text-start text-sm", open === x.id ? "bg-hive text-white" : "text-ink-200 hover:bg-ink-850")}>
                <I className={cn("h-4 w-4 shrink-0", open === x.id ? "text-honey" : "text-ink-400")} />{L(x.title)}
              </button>
            );
          })}
        </nav>
        <Card>
          <div className="flex items-center gap-3">
            <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-hive"><Icon className="h-5 w-5 text-honey" /></span>
            <h2 className="text-2xl font-semibold text-ink-100">{L(t.title)}</h2>
          </div>
          <p className="mt-3 text-base text-ink-100">{L(t.what)}</p>
          <p className="mt-1 text-sm text-ink-300">{L(t.how)}</p>
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <div className="rounded-lg bg-red-50 p-3"><h3 className="text-sm font-semibold text-crit">{tr("Warning signs")}</h3>
              <ul className="mt-1.5 space-y-1 text-sm text-ink-200">{t.signs.map((s, i) => <li key={i}>• {L(s)}</li>)}</ul></div>
            <div className="rounded-lg bg-green-50 p-3"><h3 className="text-sm font-semibold text-safe">{tr("How to stay safe")}</h3>
              <ul className="mt-1.5 space-y-1 text-sm text-ink-200">{t.tips.map((s, i) => <li key={i}>• {L(s)}</li>)}</ul></div>
            <div className="rounded-lg bg-wax p-3"><h3 className="text-sm font-semibold text-volt">{tr("If it happened to you")}</h3>
              <ul className="mt-1.5 space-y-1 text-sm text-ink-200">{t.affected.map((s, i) => <li key={i}>• {L(s)}</li>)}</ul></div>
          </div>
          <div className="mt-4 rounded-lg border border-dashed border-ink-600 p-3 text-sm">
            <span className="text-xs font-medium text-ink-400">{tr("Example (fictional)")}</span>
            <p dir="auto" className="mt-1 italic text-ink-200">{L(t.example)}</p>
          </div>
          <p className="mt-4 text-xs text-ink-400">{tr("Urgent? Call 999. To report a scam use the Abu Dhabi Police app or Aman 8002626.")}</p>
        </Card>
      </div>
      <Card title={tr("Test yourself")} subtitle={tr("Short fictional scenarios. Pick an answer to see why.")}>
        <div className="grid gap-3 lg:grid-cols-2">{QUIZZES.map((_, i) => <QuizCard key={i} i={i} />)}</div>
      </Card>
    </div>
  );
}

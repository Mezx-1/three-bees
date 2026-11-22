"use client";

import { useState } from "react";
import { BeeMark } from "@/components/BeeMark";
import { Button, ErrorBox, inputCls, Label } from "@/components/ui";
import { apiSend, setSession } from "@/lib/api";
import { tr, useI18n } from "@/lib/i18n";

export default function LoginPage() {
  const { lang, setLang } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) return setErr(tr("Enter your user name and password."));
    setBusy(true);
    setErr(null);
    try {
      const r = await apiSend<any>("/api/auth/login", "POST", { username: username.trim(), password });
      setSession(r.token, r.user);
      window.location.href = "/";
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="hive-pattern flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-5 rounded-2xl bg-ink-900 p-8 shadow-2xl shadow-black/30" noValidate>
        <div className="flex flex-col items-center gap-2 text-center">
          <BeeMark className="h-14 w-14" />
          <div className="font-display text-2xl font-semibold text-ink-100" style={{ fontVariationSettings: '"HEXP" 60' }}>Three Bees</div>
          <div className="text-sm text-ink-400">{tr("Sign in to the security center")}</div>
        </div>
        <div>
          <Label htmlFor="u">{tr("User name")}</Label>
          <input id="u" dir="ltr" autoComplete="username" className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        </div>
        <div>
          <Label htmlFor="p">{tr("Password")}</Label>
          <input id="p" dir="ltr" type="password" autoComplete="current-password" className={inputCls} value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        {err && <ErrorBox error={err} />}
        <Button type="submit" variant="primary" className="w-full py-2.5" loading={busy}>{tr("Sign in")}</Button>
        <button type="button" onClick={() => setLang(lang === "ar" ? "en" : "ar")} className="block w-full text-center text-xs text-ink-400 hover:text-ink-200">
          {lang === "ar" ? "English" : "العربية"}
        </button>
      </form>
    </div>
  );
}

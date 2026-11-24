"use client";

import { useState } from "react";
import { BeeMark } from "@/components/BeeMark";
import { Button, ErrorBox, inputCls, Label, Tabs } from "@/components/ui";
import { apiSend, setSession } from "@/lib/api";
import { firebaseConfigured, firebaseError, firebaseRegister, firebaseReset, firebaseSignIn } from "@/lib/firebase";
import { tr, useI18n } from "@/lib/i18n";

export default function LoginPage() {
  const { lang, setLang } = useI18n();
  const [method, setMethod] = useState<"email" | "account">(firebaseConfigured() ? "email" : "account");
  const [mode, setMode] = useState<"signin" | "register">("signin");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const finish = async (idToken: string) => {
    const r = await apiSend<any>("/api/auth/firebase", "POST", { id_token: idToken });
    setSession(r.token, r.user);
    window.location.href = "/";
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setInfo(null);
    setBusy(true);
    try {
      if (method === "account") {
        if (!username.trim() || !password) return setErr(tr("Enter your user name and password."));
        const r = await apiSend<any>("/api/auth/login", "POST", { username: username.trim(), password });
        setSession(r.token, r.user);
        window.location.href = "/";
        return;
      }
      if (!email.trim() || !password) return setErr(tr("Enter your email and password."));
      let token: string;
      try {
        token = mode === "register" ? await firebaseRegister(email.trim(), password) : await firebaseSignIn(email.trim(), password);
      } catch (fe: any) {
        return setErr(tr(firebaseError(fe)));
      }
      if (mode === "register") setInfo(tr("Account created. We sent you an email to verify your address."));
      await finish(token);
    } catch (e: any) {
      setErr(tr(e.message));
    } finally {
      setBusy(false);
    }
  };

  const reset = async () => {
    setErr(null);
    if (!email.trim()) return setErr(tr("Type your email first, then press Forgot password."));
    try {
      await firebaseReset(email.trim());
      setInfo(tr("If an account exists for this email, a password-reset link is on its way."));
    } catch (fe: any) {
      setErr(tr(firebaseError(fe)));
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
        {firebaseConfigured() && (
          <Tabs value={method} onChange={(m) => { setMethod(m); setErr(null); setInfo(null); }}
            items={[{ value: "email", label: tr("Email") }, { value: "account", label: tr("3B account") }]} />
        )}
        {method === "account" ? (
          <div>
            <Label htmlFor="u">{tr("User name")}</Label>
            <input id="u" dir="ltr" autoComplete="username" className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
          </div>
        ) : (
          <div>
            <Label htmlFor="e">{tr("Email")}</Label>
            <input id="e" dir="ltr" type="email" autoComplete="email" className={inputCls} value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
          </div>
        )}
        <div>
          <Label htmlFor="p">{tr("Password")}</Label>
          <input id="p" dir="ltr" type="password" autoComplete={mode === "register" ? "new-password" : "current-password"} className={inputCls} value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        {err && <ErrorBox error={err} />}
        {info && <p role="status" className="rounded-lg bg-green-50 p-3 text-sm text-safe">{info}</p>}
        <Button type="submit" variant="primary" className="w-full py-2.5" loading={busy}>
          {method === "email" && mode === "register" ? tr("Create account") : tr("Sign in")}
        </Button>
        {method === "email" && (
          <div className="flex justify-between text-xs">
            <button type="button" className="text-volt hover:underline" onClick={() => setMode(mode === "signin" ? "register" : "signin")}>
              {mode === "signin" ? tr("Create an account") : tr("I already have an account")}
            </button>
            <button type="button" className="text-ink-400 hover:text-ink-200" onClick={reset}>{tr("Forgot password?")}</button>
          </div>
        )}
        {method === "email" && <p className="text-center text-xs text-ink-400">{tr("Sign-in is handled by Google Firebase. New accounts start with the basic role; an administrator can change it.")}</p>}
        <button type="button" onClick={() => setLang(lang === "ar" ? "en" : "ar")} className="block w-full text-center text-xs text-ink-400 hover:text-ink-200">
          {lang === "ar" ? "English" : "العربية"}
        </button>
      </form>
    </div>
  );
}

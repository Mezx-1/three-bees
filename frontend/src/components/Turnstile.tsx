"use client";

import { useEffect, useRef } from "react";
import { getLang } from "@/lib/i18n";

/*
  Cloudflare Turnstile bot check. Renders only when NEXT_PUBLIC_TURNSTILE_SITE_KEY is set; the token it
  produces is checked by the 3B backend (CLOUDFLARE_TURNSTILE_SECRET_KEY) — the browser's word is never trusted.
*/
export const TURNSTILE_SITE_KEY = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || "";

declare global {
  interface Window { turnstile?: any; }
}

let loading: Promise<void> | null = null;
function loadScript(): Promise<void> {
  if (window.turnstile) return Promise.resolve();
  if (!loading) {
    loading = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      s.async = true;
      s.onload = () => resolve();
      s.onerror = () => { loading = null; reject(new Error("Turnstile failed to load")); };
      document.head.appendChild(s);
    });
  }
  return loading;
}

export function Turnstile({ onToken }: { onToken: (token: string | null) => void }) {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!TURNSTILE_SITE_KEY) return;
    let id: string | undefined;
    loadScript().then(() => {
      if (!box.current || !window.turnstile) return;
      id = window.turnstile.render(box.current, {
        sitekey: TURNSTILE_SITE_KEY,
        language: getLang(),
        callback: (t: string) => onToken(t),
        "expired-callback": () => onToken(null),
        "error-callback": () => onToken(null),
      });
    }).catch(() => onToken(null));
    return () => { if (id && window.turnstile) window.turnstile.remove(id); };
  }, [onToken]);
  if (!TURNSTILE_SITE_KEY) return null;
  return <div ref={box} />;
}

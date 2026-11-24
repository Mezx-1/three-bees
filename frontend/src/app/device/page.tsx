"use client";

import { ExternalLink, PhoneCall, PhoneIncoming, RotateCcw, ShieldAlert, Siren, Smartphone } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { BeeMark } from "@/components/BeeMark";
import { tr } from "@/lib/i18n";

/*
  Phone view: the real 3B web app running inside a phone-sized frame (390 × 844, an iPhone-class screen),
  so it can be shown on a laptop or projector exactly as it looks on a phone. On a real phone this page
  simply opens the app full-screen.
*/
const W = 390, H = 844, BEZEL = 14;
const SHORTCUTS = [
  { href: "/", label: "Home", icon: Smartphone },
  { href: "/scam-analyzer", label: "Scam Analyzer", icon: ShieldAlert },
  { href: "/call-guard", label: "Call Guard", icon: PhoneCall },
  { href: "/caller-id", label: "Caller ID", icon: PhoneIncoming },
  { href: "/report", label: "Report a Scam", icon: Siren },
];

export default function DeviceView() {
  const frame = useRef<HTMLIFrameElement>(null);
  const [scale, setScale] = useState(1);
  const [src, setSrc] = useState("/");
  const [clock, setClock] = useState("");

  useEffect(() => {
    if (window.innerWidth < 600) {
      window.location.replace("/");  // already on a phone
      return;
    }
    const fit = () => setScale(Math.min(1, (window.innerHeight - 48) / (H + BEZEL * 2)));
    fit();
    window.addEventListener("resize", fit);
    const tick = () => setClock(new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false }));
    tick();
    const id = setInterval(tick, 15000);
    return () => { window.removeEventListener("resize", fit); clearInterval(id); };
  }, []);

  const go = (href: string) => {
    setSrc(href);
    if (frame.current) frame.current.src = href;
  };

  return (
    <div className="flex min-h-screen items-center justify-center gap-10 bg-[radial-gradient(ellipse_at_top,#1f2a3d,#0b1220)] p-6 text-white">
      <aside className="hidden w-60 shrink-0 flex-col gap-3 lg:flex">
        <div className="flex items-center gap-3"><BeeMark className="h-9 w-9" /><div><div className="text-lg font-semibold">Three Bees</div><div className="text-xs text-white/60">{tr("Phone view")}</div></div></div>
        <p className="text-sm text-white/70">{tr("The real 3B app, shown at phone size. Everything inside works: tap, type, analyse.")}</p>
        <nav className="mt-2 flex flex-col gap-1.5" aria-label={tr("Open in the phone")}>
          {SHORTCUTS.map((s) => (
            <button key={s.href} onClick={() => go(s.href)}
              className="flex items-center gap-2 rounded-lg px-3 py-2 text-start text-sm text-white/85 ring-1 ring-white/10 hover:bg-white/10 focus-visible:outline-2 focus-visible:outline-amber-400">
              <s.icon className="h-4 w-4 text-amber-400" /> {tr(s.label)}
            </button>
          ))}
        </nav>
        <div className="mt-2 flex gap-2">
          <button onClick={() => frame.current?.contentWindow?.location.reload()} className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs text-white/70 ring-1 ring-white/10 hover:bg-white/10"><RotateCcw className="h-3.5 w-3.5" /> {tr("Reload")}</button>
          <a href={src} className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs text-white/70 ring-1 ring-white/10 hover:bg-white/10"><ExternalLink className="h-3.5 w-3.5" /> {tr("Full screen")}</a>
        </div>
      </aside>

      <div style={{ width: (W + BEZEL * 2) * scale, height: (H + BEZEL * 2) * scale }}>
        <div className="origin-top-left" style={{ transform: `scale(${scale})`, width: W + BEZEL * 2, height: H + BEZEL * 2 }}>
          <div className="relative h-full w-full rounded-[56px] bg-[#0a0a0c] shadow-[0_40px_120px_-20px_rgba(0,0,0,.8),inset_0_0_0_2px_#2b2f36]" style={{ padding: BEZEL }}>
            <div className="relative h-full w-full overflow-hidden rounded-[44px] bg-white">
              {/* status bar */}
              <div className="pointer-events-none absolute inset-x-0 top-0 z-10 flex h-11 items-center justify-between px-8 text-[13px] font-semibold text-black">
                <span>{clock}</span>
                <span className="flex items-center gap-1 text-[11px]">5G ▮▮▮ 🔋</span>
              </div>
              <div className="pointer-events-none absolute left-1/2 top-2.5 z-20 h-7 w-28 -translate-x-1/2 rounded-full bg-black" />
              <iframe ref={frame} src="/" title={tr("3B app at phone size")} className="absolute inset-x-0 bottom-0 top-11 h-[calc(100%-44px)] w-full border-0 bg-white" />
              <div className="pointer-events-none absolute bottom-2 left-1/2 z-10 h-1 w-32 -translate-x-1/2 rounded-full bg-black/80" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";

/*
  Per-browser display preference: show or hide the "simulated / demo data" labels.
  Off by default for presenting; the data itself stays flagged as simulated in the
  database and in the API, so turning this on shows every label again.
*/
const KEY = "3b.demoLabels";
const EVENT = "3b-prefs";

export function getDemoLabels(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function setDemoLabels(on: boolean) {
  try {
    localStorage.setItem(KEY, on ? "1" : "0");
  } catch {}
  window.dispatchEvent(new Event(EVENT));
}

export function useDemoLabels(): boolean {
  const [on, setOn] = useState(false);
  useEffect(() => {
    const read = () => setOn(getDemoLabels());
    read();
    window.addEventListener(EVENT, read);
    window.addEventListener("storage", read);
    return () => {
      window.removeEventListener(EVENT, read);
      window.removeEventListener("storage", read);
    };
  }, []);
  return on;
}

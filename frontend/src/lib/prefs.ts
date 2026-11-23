"use client";

import { useEffect, useState } from "react";

/*
  Per-browser display preferences, stored in localStorage (never sent anywhere).
  - demoLabels: show the "simulated / demo data" labels. Off by default for presenting; the
    data itself stays flagged as simulated in the database and in the API.
  - simpleMode: big text and one clear answer per result, read aloud on request — for older
    people or anyone who wants less on screen.
*/
const EVENT = "3b-prefs";

function readFlag(key: string): boolean {
  try {
    return localStorage.getItem(key) === "1";
  } catch {
    return false;
  }
}

function writeFlag(key: string, on: boolean) {
  try {
    localStorage.setItem(key, on ? "1" : "0");
  } catch {}
  window.dispatchEvent(new Event(EVENT));
}

function useFlag(key: string): boolean {
  const [on, setOn] = useState(false);
  useEffect(() => {
    const read = () => setOn(readFlag(key));
    read();
    window.addEventListener(EVENT, read);
    window.addEventListener("storage", read);
    return () => {
      window.removeEventListener(EVENT, read);
      window.removeEventListener("storage", read);
    };
  }, [key]);
  return on;
}

const DEMO = "3b.demoLabels";
export const getDemoLabels = () => readFlag(DEMO);
export const setDemoLabels = (on: boolean) => writeFlag(DEMO, on);
export const useDemoLabels = () => useFlag(DEMO);

const SIMPLE = "3b.simple";
export const setSimpleMode = (on: boolean) => writeFlag(SIMPLE, on);
export const useSimpleMode = () => useFlag(SIMPLE);

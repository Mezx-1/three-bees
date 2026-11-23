"use client";

import { useEffect, useState } from "react";

/*
  Read text aloud with the browser's built-in speech (Web Speech API). It uses the voices
  installed on this computer; nothing is uploaded by 3B. Text is only read when a voice for its
  language exists — an English voice reading Arabic would be unintelligible.
*/
const supported = () => typeof window !== "undefined" && "speechSynthesis" in window;

function voiceFor(lang: "ar" | "en") {
  return supported() ? window.speechSynthesis.getVoices().find((v) => v.lang.toLowerCase().startsWith(lang)) : undefined;
}

/** Whether a voice for this language is installed (voices load asynchronously, so this updates). */
export function useHasVoice(lang: "ar" | "en"): boolean {
  const [has, setHas] = useState(false);
  useEffect(() => {
    if (!supported()) return;
    const check = () => setHas(!!voiceFor(lang));
    check();
    window.speechSynthesis.addEventListener("voiceschanged", check);
    return () => window.speechSynthesis.removeEventListener("voiceschanged", check);
  }, [lang]);
  return has;
}

export function speak(text: string, lang: "ar" | "en") {
  const voice = voiceFor(lang);
  if (!voice) return;
  const synth = window.speechSynthesis;
  synth.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.voice = voice;
  u.lang = voice.lang;
  u.rate = 0.9;
  synth.speak(u);
}

export function stopSpeaking() {
  if (supported()) window.speechSynthesis.cancel();
}

"""Call audio analysis: offline speech-to-text + acoustic tone measurements.

Everything runs locally: audio is decoded with ffmpeg and transcribed with faster-whisper (no cloud).
Tone indicators are weak, explainable measurements (speech rate, pitch movement, loudness) — they are
never used as proof of fraud and never claim a voice is synthetic.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

import numpy as np

from ..config import settings
from .risk import Finding

log = logging.getLogger("threeb.voice")
SR = 16000
STT_MODEL = os.getenv("THREEB_STT_MODEL", "small")  # small: much better Arabic, ~4 s per 8 s chunk on a laptop CPU


def decode_audio(data: bytes, suffix: str = ".webm") -> np.ndarray:
    """Decode any audio/video container to 16 kHz mono float32 using ffmpeg (argument list, no shell)."""
    if not shutil.which("ffmpeg"):
        raise RuntimeError("ffmpeg is not installed")
    with tempfile.TemporaryDirectory(dir=settings.upload_dir / "tmp") as td:
        src = Path(td) / f"in{suffix if suffix.startswith('.') else '.' + suffix}"
        src.write_bytes(data)
        out = subprocess.run(["ffmpeg", "-v", "error", "-i", str(src), "-ac", "1", "-ar", str(SR), "-f", "f32le", "-"],
                             capture_output=True, timeout=120, check=False, shell=False)
        if out.returncode != 0 or not out.stdout:
            raise RuntimeError("Could not decode the audio: " + out.stderr.decode(errors="replace")[:200])
        return np.frombuffer(out.stdout, dtype=np.float32).copy()


@lru_cache(maxsize=1)
def _model():
    from faster_whisper import WhisperModel  # type: ignore

    return WhisperModel(STT_MODEL, device="cpu", compute_type="int8")


def stt_status() -> dict:
    try:
        import faster_whisper  # type: ignore  # noqa: F401

        return {"available": True, "engine": f"faster-whisper ({STT_MODEL}, offline)"}
    except Exception:
        return {"available": False, "engine": None, "note": "pip install faster-whisper to enable offline speech-to-text"}


def transcribe(pcm: np.ndarray) -> dict:
    if not stt_status()["available"]:
        return {"available": False, "text": "", "language": None}
    if len(pcm) < SR * 0.5:
        return {"available": True, "text": "", "language": None}
    try:
        segments, info = _model().transcribe(pcm, beam_size=1, vad_filter=True, condition_on_previous_text=False)
        text = " ".join(s.text.strip() for s in segments).strip()
        return {"available": True, "text": text, "language": info.language, "language_probability": round(info.language_probability, 2)}
    except Exception as exc:
        log.exception("transcription failed")
        return {"available": True, "text": "", "language": None, "error": f"Transcription failed: {exc.__class__.__name__}"}


def _pitch(frame: np.ndarray) -> float | None:
    """Autocorrelation pitch estimate for one 40 ms frame (80–400 Hz), None if unvoiced."""
    frame = frame - frame.mean()
    if np.abs(frame).max() < 1e-3:
        return None
    ac = np.correlate(frame, frame, mode="full")[len(frame) - 1:]
    lo, hi = SR // 400, SR // 80
    if hi >= len(ac) or ac[0] <= 0:
        return None
    lag = lo + int(np.argmax(ac[lo:hi]))
    if ac[lag] / ac[0] < 0.35:  # weak periodicity => unvoiced
        return None
    return SR / lag


def acoustic_features(pcm: np.ndarray, words: int | None = None) -> dict:
    dur = len(pcm) / SR
    if dur < 1:
        return {"duration_s": round(dur, 1), "enough_audio": False}
    hop = int(0.02 * SR)
    win = int(0.04 * SR)
    frames = [pcm[i:i + win] for i in range(0, len(pcm) - win, hop)]
    rms = np.array([np.sqrt(np.mean(f ** 2)) + 1e-9 for f in frames])
    db = 20 * np.log10(rms)
    thr = max(np.percentile(db, 30) + 6, db.max() - 35)
    speech = db > thr
    speech_ratio = float(speech.mean())
    voiced_db = db[speech]
    pitches = [p for f, s in zip(frames, speech) if s and (p := _pitch(f))]
    feats: dict = {"duration_s": round(dur, 1), "enough_audio": speech_ratio * dur >= 3, "speech_ratio": round(speech_ratio, 2),
                   "pause_ratio": round(1 - speech_ratio, 2), "loudness_variation_db": round(float(np.std(voiced_db)), 1) if len(voiced_db) else None}
    if len(pitches) >= 20:
        semis = 12 * np.log2(np.array(pitches) / np.median(pitches))
        feats["median_pitch_hz"] = round(float(np.median(pitches)), 0)
        feats["pitch_variation_semitones"] = round(float(np.std(semis)), 2)
    speech_minutes = speech_ratio * dur / 60
    if words and speech_minutes > 0.05:
        feats["speech_rate_wpm"] = round(words / speech_minutes)
    return feats


def tone_findings(f: dict) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    notes = ["Tone measurements are weak signals: accents, emotions, phone-line quality and normal stress all affect them. They never prove fraud."]
    if not f.get("enough_audio"):
        notes.append("Not enough speech in the audio to measure tone.")
        return findings, notes
    wpm = f.get("speech_rate_wpm")
    if wpm and wpm >= 175:
        findings.append(Finding("Fast, pressured speech", f"The caller speaks at about {wpm} words per minute, faster than typical conversation (~120–160). "
                                "Scammers often talk fast to prevent the listener from thinking.", "voice", "low", 8, "heuristic",
                                ["vishing", "social_engineering"], evidence=f"{wpm} wpm"))
    pv, lv = f.get("pitch_variation_semitones"), f.get("loudness_variation_db")
    if pv is not None and lv is not None and pv >= 4.5 and lv >= 9:
        findings.append(Finding("Raised, agitated voice", f"Large pitch movement ({pv} semitones) and loudness swings ({lv} dB) suggest an agitated or "
                                "insistent tone — a common pressure tactic, but also normal in heated conversations.", "voice", "low", 6, "heuristic",
                                ["vishing", "social_engineering"], evidence=f"pitch ±{pv} st, loudness ±{lv} dB"))
    if pv is not None and pv < 1.2 and f.get("duration_s", 0) >= 20:
        findings.append(Finding("Very flat intonation", f"Pitch barely changes ({pv} semitones). This can happen with scripted reading, recorded "
                                "messages or synthetic voices — and with some normal speakers. Not evidence on its own.", "voice", "info", 3, "heuristic",
                                [], evidence=f"pitch ±{pv} st"))
    if f.get("pause_ratio", 1) < 0.12 and f.get("duration_s", 0) >= 20:
        findings.append(Finding("Almost no pauses", "The caller leaves very little room to respond, a pressure tactic.", "voice", "low", 5, "heuristic",
                                ["social_engineering"], evidence=f"pauses {int(f['pause_ratio'] * 100)}%"))
    return findings, notes

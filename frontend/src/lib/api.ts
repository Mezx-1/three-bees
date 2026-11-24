import { getLang } from "./i18n";

// Empty string = same origin (production behind Caddy); unset = local development backend.
export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const TOKEN_KEY = "3b.token";
const ME_KEY = "3b.me";

export type Me = { username: string; full_name: string; role: string; email: string };

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function getMe(): Me | null {
  try {
    const raw = localStorage.getItem(ME_KEY);
    return raw ? (JSON.parse(raw) as Me) : null;
  } catch {
    return null;
  }
}

export function setSession(token: string | null, me: Me | null) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
    if (me) localStorage.setItem(ME_KEY, JSON.stringify(me));
    else localStorage.removeItem(ME_KEY);
  } catch {}
  window.dispatchEvent(new Event("3b-user"));
}

function onUnauthorized() {
  if (typeof window === "undefined" || window.location.pathname.startsWith("/login")) return;
  setSession(null, null);
  window.location.href = "/login";
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function handle<T>(res: Response): Promise<T> {
  if (res.status === 401) onUnauthorized();
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.detail) msg = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {}
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<T>;
}

function headers(extra?: Record<string, string>) {
  const t = getToken();
  return { ...(t ? { Authorization: `Bearer ${t}` } : {}), "X-3B-Lang": getLang(), ...(extra || {}) } as Record<string, string>;
}

export async function apiGet<T = any>(path: string): Promise<T> {
  try {
    const res = await fetch(`${API_URL}${path}`, { headers: headers(), cache: "no-store" });
    return handle<T>(res);
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(0, `Cannot reach the 3B backend at ${API_URL}. Is it running?`);
  }
}

export async function apiSend<T = any>(path: string, method: "POST" | "PUT" | "PATCH" | "DELETE", body?: unknown): Promise<T> {
  try {
    const res = await fetch(`${API_URL}${path}`, {
      method,
      headers: headers(body !== undefined ? { "Content-Type": "application/json" } : undefined),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return handle<T>(res);
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(0, `Cannot reach the 3B backend at ${API_URL}. Is it running?`);
  }
}

export async function apiUpload<T = any>(path: string, form: FormData): Promise<T> {
  try {
    const res = await fetch(`${API_URL}${path}`, { method: "POST", headers: headers(), body: form });
    return handle<T>(res);
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(0, `Cannot reach the 3B backend at ${API_URL}. Is it running?`);
  }
}

export async function download(path: string, filename: string) {
  const res = await fetch(`${API_URL}${path}`, { headers: headers() });
  if (!res.ok) throw new ApiError(res.status, "Download failed");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export async function fetchSampleFile(name: string): Promise<File> {
  const res = await fetch(`${API_URL}/api/demo/samples/${encodeURIComponent(name)}`);
  if (!res.ok) throw new ApiError(res.status, "Sample not found");
  const blob = await res.blob();
  return new File([blob], name, { type: blob.type });
}

/** Fetch an authenticated file (evidence image, printable report) and return a temporary object URL. */
export async function apiBlobUrl(path: string): Promise<string> {
  const res = await fetch(`${API_URL}${path}`, { headers: headers(), cache: "no-store" });
  if (!res.ok) throw new ApiError(res.status, "Could not load the file");
  return URL.createObjectURL(await res.blob());
}

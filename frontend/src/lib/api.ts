import { getLang } from "./i18n";

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const USER_KEY = "wolve.user";

export function getUser(): string {
  if (typeof window === "undefined") return "omar.analyst";
  try {
    return localStorage.getItem(USER_KEY) || "omar.analyst";
  } catch {
    return "omar.analyst";
  }
}

export function setUser(u: string) {
  try {
    localStorage.setItem(USER_KEY, u);
  } catch {}
  window.dispatchEvent(new Event("wolve-user"));
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function handle<T>(res: Response): Promise<T> {
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
  return { "X-WOLVE-User": getUser(), "X-WOLVE-Lang": getLang(), ...(extra || {}) };
}

export async function apiGet<T = any>(path: string): Promise<T> {
  try {
    const res = await fetch(`${API_URL}${path}`, { headers: headers(), cache: "no-store" });
    return handle<T>(res);
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(0, `Cannot reach the WOLVE backend at ${API_URL}. Is it running?`);
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
    throw new ApiError(0, `Cannot reach the WOLVE backend at ${API_URL}. Is it running?`);
  }
}

export async function apiUpload<T = any>(path: string, form: FormData): Promise<T> {
  try {
    const res = await fetch(`${API_URL}${path}`, { method: "POST", headers: headers(), body: form });
    return handle<T>(res);
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(0, `Cannot reach the WOLVE backend at ${API_URL}. Is it running?`);
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

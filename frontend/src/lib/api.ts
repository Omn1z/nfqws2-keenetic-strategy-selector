// Typed client for the Go JSON backend. A 401 invokes the registered handler
// (App shows the login screen) and rejects the call.

let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

interface ApiError {
  error?: string;
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const opt: RequestInit = { method };
  if (body !== undefined) {
    opt.headers = { "Content-Type": "application/json" };
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  if (res.status === 401) {
    onUnauthorized();
    throw new Error("Требуется вход");
  }
  const txt = await res.text();
  const data = txt ? JSON.parse(txt) : null;
  if (!res.ok) throw new Error((data as ApiError)?.error || res.statusText);
  return data as T;
}

export async function uploadForm<T = unknown>(path: string, form: FormData): Promise<T> {
  const res = await fetch(path, { method: "POST", body: form });
  if (res.status === 401) {
    onUnauthorized();
    throw new Error("Требуется вход");
  }
  const data = (await res.json().catch(() => null)) as (T & ApiError) | null;
  if (!res.ok) throw new Error(data?.error || res.statusText);
  return data as T;
}

export async function downloadFile(url: string, filename: string, opts?: RequestInit): Promise<void> {
  const res = await fetch(url, opts ?? {});
  if (res.status === 401) {
    onUnauthorized();
    throw new Error("Требуется вход");
  }
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = ((await res.json()) as ApiError).error ?? msg;
    } catch {
      /* keep statusText */
    }
    throw new Error(msg);
  }
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/** Download a strategy (+ its blobs) as a ZIP. */
export function exportStrategy(name: string, l7: string, args: string): Promise<void> {
  if (!args) return Promise.reject(new Error("Нет аргументов для экспорта"));
  return downloadFile("/api/strategies/export", `${(name || "strategy").replace(/[^\w-]+/g, "_")}.zip`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, l7, args }),
  });
}

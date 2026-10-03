// Typed client for the Go JSON backend. A 401 invokes the registered handler
// (App shows the login screen) and rejects the call.

let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

interface ApiError {
  error?: string;
}

export class ApiHTTPError extends Error {
  constructor(message: string, public readonly status: number) { super(message); this.name = "ApiHTTPError"; }
}

const AWG_RULES_TIMEOUT_MS = 180_000;
const READ_TIMEOUT_MS = 30_000;
const awgRulesMutation = (method: string, path: string) =>
  method.toUpperCase() === "POST" &&
  /^\/api\/awg2\/routing\/rules(?:\/(?:copy|insert-top|import))?$/.test(path);

export interface ApiOptions {
  /** Text assets use the same authentication, cancellation and read deadline. */
  responseType?: "json" | "text";
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Some POST endpoints only preview or export a supplied draft. */
  readOnly?: boolean;
}

export function api(method: string, path: string, body: unknown, options: ApiOptions & { responseType: "text" }): Promise<string>;
export function api<T = unknown>(method: string, path: string, body?: unknown, options?: ApiOptions): Promise<T>;
export async function api<T = unknown>(method: string, path: string, body?: unknown, options: ApiOptions = {}): Promise<T | string> {
  const opt: RequestInit = { method };
  if (body !== undefined) {
    opt.headers = { "Content-Type": "application/json" };
    opt.body = JSON.stringify(body);
  }
  const readOnly = method.toUpperCase() === "GET" || options.readOnly === true;
  // Provisioning/downloading a VPN engine can legitimately take much longer.
  // Bound reads and the existing routing mutation deadline, not every POST.
  const timeoutMs = options.timeoutMs ?? (readOnly ? READ_TIMEOUT_MS : awgRulesMutation(method, path) ? AWG_RULES_TIMEOUT_MS : 0);
  const controller = new AbortController();
  opt.signal = controller.signal;
  const abort = () => controller.abort(options.signal?.reason);
  if (options.signal?.aborted) abort();
  else options.signal?.addEventListener("abort", abort, { once: true });
  let timedOut = false;
  const timeout = timeoutMs > 0 ? globalThis.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs) : null;
  try {
    const res = await fetch(path, opt);
    if (res.status === 401) {
      onUnauthorized();
      throw new Error("Требуется вход");
    }
    const txt = await res.text();
    const data = res.ok && options.responseType === "text" ? txt : txt ? JSON.parse(txt) : null;
    if (!res.ok) throw new ApiHTTPError((data as ApiError)?.error || res.statusText, res.status);
    return data as T;
  } catch (error) {
    if (timedOut && error instanceof Error && error.name === "AbortError") {
      throw new Error(readOnly
        ? "Роутер не ответил вовремя. Повторите обновление; сохранённые данные остаются на экране."
        : "Роутер не ответил вовремя; проверьте состояние перед повторной попыткой — настройка могла сохраниться.");
    }
    throw error;
  } finally {
    options.signal?.removeEventListener("abort", abort);
    if (timeout !== null) globalThis.clearTimeout(timeout);
  }
}

export async function uploadForm<T = unknown>(path: string, form: FormData): Promise<T> {
  const res = await fetch(path, { method: "POST", body: form });
  if (res.status === 401) {
    onUnauthorized();
    throw new Error("Требуется вход");
  }
  const data = (await res.json().catch(() => null)) as (T & ApiError) | null;
  if (!res.ok) throw new ApiHTTPError(data?.error || res.statusText, res.status);
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

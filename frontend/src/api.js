// Single API client for the Go JSON backend. A 401 triggers the registered
// unauthorized handler (App shows the login screen) and rejects the call.

let onUnauth = () => {};
export function setUnauthorizedHandler(fn) { onUnauth = fn; }

export async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  if (res.status === 401) { onUnauth(); throw new Error("Требуется вход"); }
  const txt = await res.text();
  const data = txt ? JSON.parse(txt) : null;
  if (!res.ok) throw new Error((data && data.error) || res.statusText);
  return data;
}

// uploadForm posts multipart/form-data (file uploads) and returns parsed JSON.
export async function uploadForm(path, formData) {
  const res = await fetch(path, { method: "POST", body: formData });
  if (res.status === 401) { onUnauth(); throw new Error("Требуется вход"); }
  const d = await res.json().catch(() => null);
  if (!res.ok) throw new Error((d && d.error) || res.statusText);
  return d;
}

// exportStrategy downloads a strategy (+ its blobs) as a ZIP.
export function exportStrategy(name, l7, args) {
  if (!args) return Promise.reject(new Error("Нет аргументов для экспорта"));
  return downloadFile("/api/strategies/export", (name || "strategy").replace(/[^\w-]+/g, "_") + ".zip", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, l7, args }),
  });
}

// downloadFile fetches (with the auth cookie) and saves the response as a file.
export async function downloadFile(url, filename, opts) {
  const res = await fetch(url, opts || {});
  if (res.status === 401) { onUnauth(); throw new Error("Требуется вход"); }
  if (!res.ok) { let m = res.statusText; try { m = (await res.json()).error || m; } catch (_) {} throw new Error(m); }
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

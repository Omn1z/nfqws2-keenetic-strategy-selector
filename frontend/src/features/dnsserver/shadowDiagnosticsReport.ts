import type { DnsShadowDiagnosticAttempt, DnsShadowStatus } from "@/types/api";

export function latestShadowAttempt(status?: DnsShadowStatus): DnsShadowDiagnosticAttempt | undefined {
  return status?.diagnostics?.attempts.at(-1);
}

export function shadowDiagnosticState(status?: DnsShadowStatus): "empty" | "running" | "waiting" | "failed" | "success" {
  const trace = status?.diagnostics;
  if (trace?.in_progress) return "running";
  const attempt = latestShadowAttempt(status);
  if (!attempt) return "empty";
  if (attempt.error) {
    if (attempt.next_retry_at && Date.parse(attempt.next_retry_at) > Date.parse(trace!.captured_at)) return "waiting";
    return "failed";
  }
  return attempt.servers.length ? "success" : "empty";
}

export function shadowDiagnosticsReport(status: DnsShadowStatus): string {
  const trace = status.diagnostics;
  if (!trace || trace.version !== 1) throw new Error("Диагностика пока недоступна");
  // Explicit fields keep this report independent from settings, credentials and
  // future additions to the status object. Limits are enforced by the backend.
  return JSON.stringify({
    format: "nfqws2-strategy-shadow-diagnostics",
    version: 1,
    captured_at: trace.captured_at,
    shadow_dns: { enabled: status.enabled, automatic: status.automatic, servers: status.servers, error: status.error },
    diagnostics: {
      version: trace.version, app_version: trace.app_version, platform: trace.platform,
      captured_at: trace.captured_at, in_progress: trace.in_progress,
      attempts: trace.attempts.map((attempt) => ({
        id: attempt.id, started_at: attempt.started_at, finished_at: attempt.finished_at,
        duration_ms: attempt.duration_ms, error: attempt.error, servers: attempt.servers,
        next_retry_at: attempt.next_retry_at,
        events: attempt.events.map((event) => ({ at: event.at, stage: event.stage, message: event.message, duration_ms: event.duration_ms })),
      })),
    },
  }, null, 2);
}

export function downloadShadowDiagnostics(status: DnsShadowStatus): void {
  const report = shadowDiagnosticsReport(status);
  const date = new Date(status.diagnostics!.captured_at);
  const stamp = Number.isNaN(date.getTime()) ? "snapshot" : date.toISOString().slice(0, 19).replace(/[-:]/g, "").replace("T", "-");
  const url = URL.createObjectURL(new Blob([report], { type: "application/json" }));
  const link = document.createElement("a");
  try {
    link.href = url;
    link.download = `shadow-dns-diagnostics-${stamp}.json`;
    document.body.appendChild(link);
    link.click();
  } finally {
    link.remove();
    globalThis.setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
}

function copyUsingSelection(report: string): boolean {
  if (typeof document.execCommand !== "function") return false;
  const previous = document.activeElement as HTMLElement | null;
  const text = document.createElement("textarea");
  text.value = report;
  text.readOnly = true;
  text.tabIndex = -1;
  text.style.cssText = "position:fixed;top:0;left:-9999px;width:1px;height:1px;opacity:0";
  document.body.appendChild(text);
  try {
    text.focus({ preventScroll: true });
    text.select();
    text.setSelectionRange(0, report.length);
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    text.remove();
    try { previous?.focus({ preventScroll: true }); } catch { /* Detached controls need no focus restoration. */ }
  }
}

export async function copyShadowDiagnostics(status: DnsShadowStatus): Promise<"copied" | "downloaded"> {
  const report = shadowDiagnosticsReport(status);
  try {
    await navigator.clipboard.writeText(report);
    return "copied";
  } catch {
    // HTTP router pages usually lack the Clipboard API, but copying a selected
    // textarea within a user gesture still works in their browsers.
    if (copyUsingSelection(report)) return "copied";
    downloadShadowDiagnostics(status);
    return "downloaded";
  }
}

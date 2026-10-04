import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { DnsShadowDiagnosticAttempt, DnsShadowStatus } from "@/types/api";
import { setShadowDiagnosticsEnabled, ShadowDnsDiagnostics } from "./ShadowDnsDiagnostics";
import { copyShadowDiagnostics, downloadShadowDiagnostics, shadowDiagnosticsReport, shadowDiagnosticState } from "./shadowDiagnosticsReport";

const attempt = (overrides: Partial<DnsShadowDiagnosticAttempt> = {}): DnsShadowDiagnosticAttempt => ({
  id: 1, started_at: "2026-10-04T00:00:00Z", finished_at: "2026-10-04T00:00:01.2Z", duration_ms: 1200,
  servers: [], error: "ответ DHCPINFORM не получен: context deadline exceeded", next_retry_at: "2026-10-04T00:00:31.2Z",
  events: [{ at: "2026-10-04T00:00:00.1Z", stage: "dhcp.send", message: "broadcast eth3: 10.101.48.55:68 → 255.255.255.255:67" }, { at: "2026-10-04T00:00:01.2Z", stage: "dhcp.capture", message: "Отправлено: 1; получено: 0", duration_ms: 1200 }],
  ...overrides,
});
const status = (overrides: Partial<DnsShadowStatus> = {}): DnsShadowStatus => ({
  enabled: true, automatic: true, servers: [], error: "context deadline exceeded",
  diagnostics: { version: 1, enabled: true, app_version: "v1.7.42", platform: "linux/arm64", captured_at: "2026-10-04T00:00:02Z", in_progress: false, attempts: [attempt()] },
  ...overrides,
});

test("Shadow diagnostics tolerate an older server and display a passive empty history", () => {
  assert.equal(renderToStaticMarkup(<ShadowDnsDiagnostics status={status({ diagnostics: undefined })} />), "");
  const html = renderToStaticMarkup(<ShadowDnsDiagnostics status={status({ error: undefined, diagnostics: { version: 1, enabled: true, captured_at: "2026-10-04T00:00:00Z", in_progress: false, attempts: [] } })} />);
  assert.match(html, /Попыток ещё нет/);
  assert.match(html, /Открытие и копирование отчёта не запускают проверку/);
  assert.equal(html.includes("open=\"\""), false);
  assert.equal(shadowDiagnosticState(), "empty");
});

test("Shadow diagnostics distinguish a cached failure, a fresh running attempt and an elapsed retry", () => {
  const failed = status();
  const html = renderToStaticMarkup(<ShadowDnsDiagnostics status={failed} />);
  assert.match(html, /role="switch"/);
  assert.match(html, /aria-checked="true"/);
  assert.match(html, /Ожидание повторной попытки/);
  assert.match(html, /при следующем запросе к домену/);
  assert.match(html, /broadcast eth3/);
  assert.match(html, /Отправлено: 1; получено: 0/);
  assert.match(html, /v1\.7\.42/);
  assert.match(html, /linux\/arm64/);
  assert.equal(shadowDiagnosticState(failed), "waiting");
  const running = status({ diagnostics: { ...failed.diagnostics!, in_progress: true, attempts: [attempt(), attempt({ id: 2, started_at: "2026-10-04T00:00:32Z", finished_at: undefined, error: undefined, next_retry_at: undefined, events: [] })] } });
  const runningHTML = renderToStaticMarkup(<ShadowDnsDiagnostics status={running} />);
  assert.equal(shadowDiagnosticState(running), "running");
  assert.match(runningHTML, /Ошибка выше относится к предыдущей попытке/);
  assert.match(runningHTML, /Поиск DNS выполняется/);
  assert.match(runningHTML, /Предыдущие попытки \(1\)/);
  assert.equal(shadowDiagnosticState(status({ diagnostics: { ...failed.diagnostics!, captured_at: "2026-10-04T00:00:31.2Z" } })), "failed");
});

test("Shadow diagnostics show accepted servers and safely escape diagnostic text", () => {
  const success = status({ error: undefined, servers: ["192.0.2.53:53"], diagnostics: { version: 1, enabled: true, captured_at: "2026-10-04T00:00:02Z", in_progress: false, attempts: [attempt({ error: undefined, next_retry_at: undefined, servers: ["192.0.2.53:53"], events: [{ at: "2026-10-04T00:00:01Z", stage: "native", message: "<script>untrusted</script>" }] })] } });
  const html = renderToStaticMarkup(<ShadowDnsDiagnostics status={success} />);
  assert.equal(shadowDiagnosticState(success), "success");
  assert.match(html, /DNS обнаружены/);
  assert.match(html, /Найдены DNS:/);
  assert.match(html, /192\.0\.2\.53:53/);
  assert.equal(html.includes("<script>"), false);
  assert.ok(html.includes("&lt;script&gt;untrusted&lt;/script&gt;"));
});

test("Shadow report preserves every bounded attempt and event without settings or unknown extra fields", () => {
  const base = status();
  const input = { ...base, password: "never-export", config: { private_key: "secret" } };
  input.diagnostics!.attempts = [attempt(), attempt({ id: 2 })];
  const before = JSON.stringify(input);
  const report = JSON.parse(shadowDiagnosticsReport(input));
  assert.equal(report.format, "nfqws2-strategy-shadow-diagnostics");
  assert.equal(report.captured_at, base.diagnostics!.captured_at);
  assert.deepEqual(report.diagnostics, input.diagnostics);
  assert.deepEqual(report.shadow_dns, { enabled: true, automatic: true, servers: [], error: "context deadline exceeded" });
  assert.equal(JSON.stringify(report).includes("never-export"), false);
  assert.equal(JSON.stringify(report).includes("private_key"), false);
  assert.equal(JSON.stringify(input), before);
  assert.throws(() => shadowDiagnosticsReport(status({ diagnostics: undefined })), /недоступна/);
});

function replaceGlobal(t: TestContext, name: string, value: unknown) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
  Object.defineProperty(globalThis, name, { configurable: true, value });
  t.after(() => descriptor ? Object.defineProperty(globalThis, name, descriptor) : Reflect.deleteProperty(globalThis, name));
}

test("Shadow clipboard export copies the current snapshot without requesting the router", async (t) => {
  let copied = "";
  replaceGlobal(t, "navigator", { clipboard: { writeText: async (text: string) => { copied = text; } } });
  t.mock.method(globalThis, "fetch", () => { throw new Error("no requests allowed"); });
  assert.equal(await copyShadowDiagnostics(status()), "copied");
  assert.deepEqual(JSON.parse(copied), JSON.parse(shadowDiagnosticsReport(status())));
});

test("Shadow copy works on HTTP using a selected temporary textarea and restores focus", async (t) => {
  let selected = false;
  let removed = false;
  let copied = "";
  let focused = 0;
  const textarea = {
    value: "", readOnly: false, tabIndex: 0, style: { cssText: "" },
    focus() {}, select() { selected = true; },
    setSelectionRange(start: number, end: number) { assert.equal(start, 0); assert.equal(end, textarea.value.length); },
    remove() { removed = true; },
  };
  replaceGlobal(t, "navigator", {});
  replaceGlobal(t, "document", {
    activeElement: { focus() { focused++; } },
    createElement(tag: string) { assert.equal(tag, "textarea"); return textarea; },
    body: { appendChild() {} },
    execCommand(command: string) { assert.equal(command, "copy"); assert.equal(selected, true); copied = textarea.value; return true; },
  });
  t.mock.method(URL, "createObjectURL", () => { throw new Error("copy must not download"); });
  t.mock.method(globalThis, "fetch", () => { throw new Error("no requests allowed"); });
  assert.equal(await copyShadowDiagnostics(status()), "copied");
  assert.equal(copied, shadowDiagnosticsReport(status()));
  assert.equal(removed, true);
  assert.equal(focused, 1);
});

for (const mode of ["absent", "denied", "legacy-denied", "legacy-throws"] as const) {
  test(`Shadow export downloads the complete JSON when copying is ${mode}`, async (t) => {
    let blob: Blob | undefined;
    let clicks = 0;
    let removed = false;
    let textareaRemoved = false;
    let revoked = "";
    const link = { href: "", download: "", click() { clicks++; }, remove() { removed = true; } };
    replaceGlobal(t, "navigator", { clipboard: mode === "denied" ? { writeText: async () => { throw new Error("clipboard denied"); } } : undefined });
    replaceGlobal(t, "document", {
      createElement: (tag: string) => tag === "textarea" ? { value: "", style: {}, focus() {}, select() {}, setSelectionRange() {}, remove() { textareaRemoved = true; } } : link,
      body: { appendChild() {} },
      execCommand: mode === "legacy-denied" ? () => false : mode === "legacy-throws" ? () => { throw new Error("copy blocked"); } : undefined,
    });
    t.mock.method(globalThis, "fetch", () => { throw new Error("no requests allowed"); });
    t.mock.method(URL, "createObjectURL", (value: Blob) => { blob = value; return "blob:shadow"; });
    t.mock.method(URL, "revokeObjectURL", (value: string) => { revoked = value; });
    t.mock.timers.enable({ apis: ["setTimeout"] });
    assert.equal(await copyShadowDiagnostics(status()), "downloaded");
    assert.equal(link.download, "shadow-dns-diagnostics-20261004-000002.json");
    assert.equal(blob!.type, "application/json");
    assert.deepEqual(JSON.parse(await blob!.text()), JSON.parse(shadowDiagnosticsReport(status())));
    assert.equal(clicks, 1);
    assert.equal(removed, true);
    assert.equal(textareaRemoved, mode.startsWith("legacy-"));
    assert.equal(revoked, "");
    t.mock.timers.tick(2000);
    assert.equal(revoked, "blob:shadow");
  });
}

test("Shadow download fails before touching the browser when no diagnostic report exists", (t) => {
  t.mock.method(URL, "createObjectURL", () => { throw new Error("unexpected file"); });
  assert.throws(() => downloadShadowDiagnostics(status({ diagnostics: undefined })), /недоступна/);
});

test("Disabled diagnostics hide stale history and export controls even when Shadow DNS has an error", async (t) => {
  const off = status({ diagnostics: { ...status().diagnostics!, enabled: false, in_progress: true } });
  const request = t.mock.method(globalThis, "fetch", () => { throw new Error("render must not enable diagnostics"); });
  const html = renderToStaticMarkup(<ShadowDnsDiagnostics status={off} />);
  assert.match(html, /role="switch"/);
  assert.match(html, /aria-checked="false"/);
  assert.match(html, /Диагностика выключена/);
  assert.match(html, /после перезапуска NFQWS2 Strategy она также выключена/);
  for (const hidden of ["Скопировать диагностику", "Скачать JSON", "broadcast eth3", "Отправлено: 1", "Поиск DNS выполняется"]) assert.equal(html.includes(hidden), false);
  assert.equal(shadowDiagnosticState(off), "disabled");
  assert.throws(() => shadowDiagnosticsReport(off), /выключена/);
  assert.throws(() => downloadShadowDiagnostics(off), /выключена/);
  await assert.rejects(copyShadowDiagnostics(off), /выключена/);
  assert.equal(request.mock.callCount(), 0);
});

test("Older diagnostics remain read-compatible but cannot issue the new toggle mutation", async (t) => {
  const old = status({ diagnostics: { ...status().diagnostics!, enabled: undefined } });
  const request = t.mock.method(globalThis, "fetch", () => { throw new Error("older server must not receive toggle"); });
  const html = renderToStaticMarkup(<ShadowDnsDiagnostics status={old} />);
  assert.match(html, /disabled=""/);
  assert.match(html, /обновите NFQWS2 Strategy/);
  assert.equal(html.includes("Скопировать диагностику"), false);
  await assert.rejects(setShadowDiagnosticsEnabled(old, true), /обновите/);
  assert.equal(request.mock.callCount(), 0);
  assert.equal(JSON.parse(shadowDiagnosticsReport(old)).diagnostics.attempts.length, 1);
});

test("The diagnostics switch changes runtime collection without configuration writes or DHCP renewal", async (t) => {
  const calls: boolean[] = [];
  const request = t.mock.method(globalThis, "fetch", async (url: string | URL | Request, options?: RequestInit) => {
    assert.equal(url, "/api/dnsserver/shadow/diagnostics");
    assert.equal(options?.method, "POST");
    const body = JSON.parse(options?.body as string);
    assert.deepEqual(Object.keys(body), ["enabled"]);
    assert.equal(typeof body.enabled, "boolean");
    calls.push(body.enabled);
    return new Response(JSON.stringify({ shadow_dns: { ...status(), diagnostics: { ...status().diagnostics, enabled: body.enabled, attempts: [], in_progress: false } }, config: { preserved: true } }), { status: 200 });
  });
  const on = await setShadowDiagnosticsEnabled(status({ diagnostics: { ...status().diagnostics!, enabled: false } }), true);
  assert.equal(on.shadow_dns?.diagnostics?.enabled, true);
  const off = await setShadowDiagnosticsEnabled(on.shadow_dns, false);
  assert.equal(off.shadow_dns?.diagnostics?.enabled, false);
  assert.deepEqual(off.shadow_dns?.diagnostics?.attempts, []);
  assert.deepEqual(calls, [true, false]);
  assert.equal(request.mock.callCount(), 2);
});

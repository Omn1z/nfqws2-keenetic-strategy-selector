import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { DnsShadowRenewResult, DnsShadowStatus } from "@/types/api";
import { confirmAndRenewShadowDns, ShadowDnsRenew, ShadowDnsRenewOutcome } from "./ShadowDnsRenew";

const available: DnsShadowStatus = { enabled: true, automatic: true, servers: [], renewal_available: true };
const result = (status: DnsShadowRenewResult["status"]): DnsShadowRenewResult => ({ status, interface: "GigabitEthernet1", device: "eth3", message: "Ответ DHCP обработан", servers: status === "resolved" ? ["192.0.2.53:53"] : [] });
function windowConfirm(t: TestContext, confirm: (message: string) => boolean | Promise<boolean>) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", { configurable: true, value: { confirm } });
  t.after(() => descriptor ? Object.defineProperty(globalThis, "window", descriptor) : Reflect.deleteProperty(globalThis, "window"));
}

test("Shadow renewal is hidden for older backends, unsupported routers and disabled Shadow DNS", () => {
  for (const status of [undefined, { ...available, renewal_available: undefined }, { ...available, renewal_available: false }, { ...available, enabled: false }]) {
    assert.equal(renderToStaticMarkup(<ShadowDnsRenew status={status} />), "");
  }
  const html = renderToStaticMarkup(<ShadowDnsRenew status={available} />);
  assert.match(html, /Получить DNS сейчас/);
  assert.match(html, /интернет может ненадолго прерваться/);
  assert.match(html, /Действие потребует подтверждения/);
  assert.match(renderToStaticMarkup(<ShadowDnsRenew status={available} disabled />), /disabled=""/);
});

test("Shadow renewal sends nothing until explicit confirmation and cancellation sends no POST", async (t) => {
  let accept!: (accepted: boolean) => void;
  let confirmedText = "", beginCalls = 0;
  windowConfirm(t, (message) => { confirmedText = message; return new Promise<boolean>((resolve) => { accept = resolve; }); });
  const request = t.mock.method(globalThis, "fetch", async () => { throw new Error("must not request before confirmation"); });
  const pending = confirmAndRenewShadowDns(() => { beginCalls++; return true; });
  await Promise.resolve();
  assert.match(confirmedText, /Возможен перерыв интернета/);
  assert.equal(beginCalls, 0);
  assert.equal(request.mock.callCount(), 0);
  accept(false);
  assert.equal(await pending, null);
  assert.equal(beginCalls, 0);
  assert.equal(request.mock.callCount(), 0);
});

test("Confirmed renewal respects the mutation lock and uses the explicit API confirmation", async (t) => {
  windowConfirm(t, () => true);
  const request = t.mock.method(globalThis, "fetch", async (url: string | URL | Request, options?: RequestInit) => {
    assert.equal(url, "/api/dnsserver/shadow/renew");
    assert.equal(options?.method, "POST");
    assert.deepEqual(JSON.parse(options?.body as string), { confirm: true });
    assert.ok(options?.signal);
    return new Response(JSON.stringify({ ok: true, result: result("resolved") }), { status: 200 });
  });
  assert.equal(await confirmAndRenewShadowDns(() => false), null);
  assert.equal(request.mock.callCount(), 0);
  assert.deepEqual(await confirmAndRenewShadowDns(() => true), result("resolved"));
  assert.equal(request.mock.callCount(), 1);
});

test("A failed renewal remains visible and is not automatically repeated", async (t) => {
  windowConfirm(t, () => true);
  const request = t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ error: "WAN eth3 недоступен" }), { status: 409 }));
  let error = "";
  try { await confirmAndRenewShadowDns(() => true); }
  catch (e) { error = (e as Error).message; }
  assert.equal(request.mock.callCount(), 1);
  assert.equal(error, "WAN eth3 недоступен");
  const html = renderToStaticMarkup(<ShadowDnsRenewOutcome result={null} error={error} />);
  assert.match(html, /role="alert"/);
  assert.match(html, /WAN eth3 недоступен/);
});

test("Renewal outcomes distinguish provider silence, DNS omission and rejection from success", () => {
  for (const [status, title] of [
    ["resolved", "DNS провайдера получены"], ["waiting", "Ожидание ответа провайдера"],
    ["no_dns", "Провайдер не передал DNS"], ["nak", "DHCP-сервер отклонил обновление аренды"],
  ] as const) {
    const html = renderToStaticMarkup(<ShadowDnsRenewOutcome result={result(status)} error="" />);
    assert.ok(html.includes(title));
    assert.match(html, /GigabitEthernet1 \(eth3\)/);
    assert.equal(html.includes("192.0.2.53:53"), status === "resolved");
  }
  const escaped = renderToStaticMarkup(<ShadowDnsRenewOutcome result={{ ...result("waiting"), message: "<script>private</script>" }} error="" />);
  assert.equal(escaped.includes("<script>"), false);
  assert.match(escaped, /&lt;script&gt;private&lt;\/script&gt;/);
});

test("An invalid renewal response cannot be presented as successful", async (t) => {
  windowConfirm(t, () => true);
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));
  await assert.rejects(confirmAndRenewShadowDns(() => true), /Не удалось прочитать результат/);
});

import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { api, setUnauthorizedHandler } from "./api";

function pendingFetch(t: TestContext) {
  let options: RequestInit | undefined;
  let complete: (value: Response) => void = () => {};
  t.mock.method(globalThis, "fetch", (_input: RequestInfo | URL, init?: RequestInit) => {
    options = init;
    return new Promise<Response>((resolve, reject) => {
      complete = resolve;
      const signal = init?.signal;
      const abort = () => reject(signal?.reason);
      if (signal?.aborted) abort();
      else signal?.addEventListener("abort", abort, { once: true });
    });
  });
  return {
    options: () => options,
    complete: () => complete(new Response(JSON.stringify({ ok: true }), { status: 200 })),
  };
}

test("text asset reads preserve exact source and use the common authorization handler", async (t) => {
  const content = '# conf\nNFQWS_ARGS="--example"\n';
  t.mock.method(globalThis, "fetch", async () => new Response(content, { status: 200 }));
  assert.equal(await api<string>("GET", "/api/nfqws2/assets/file?path=nfqws2.conf", undefined, { responseType: "text" }), content);
  let unauthorized = 0;
  setUnauthorizedHandler(() => { unauthorized++; });
  t.after(() => setUnauthorizedHandler(() => {}));
  t.mock.method(globalThis, "fetch", async () => new Response('{"error":"login"}', { status: 401 }));
  await assert.rejects(api("GET", "/api/nfqws2/assets/file?path=nfqws2.conf", undefined, { responseType: "text" }), /Требуется вход/);
  assert.equal(unauthorized, 1);
});

test("a stalled read expires after 30 seconds so polling can recover", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fetch = pendingFetch(t);
  const result = api("GET", "/api/awg2");
  const rejection = assert.rejects(result, /Роутер не ответил вовремя/);
  t.mock.timers.tick(29_999);
  assert.equal(fetch.options()?.signal?.aborted, false);
  t.mock.timers.tick(1);
  await rejection;
  assert.equal(fetch.options()?.signal?.aborted, true);
});

test("routing writes keep their three-minute deadline and warn about an uncertain save", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fetch = pendingFetch(t);
  for (const path of ["/api/awg2/routing/rules", "/api/awg2/routing/rules/copy", "/api/awg2/routing/rules/insert-top", "/api/awg2/routing/rules/import"]) {
    const result = api("POST", path, { mode: "zones", zones: [] });
    const rejection = assert.rejects(result, /настройка могла сохраниться/);
    t.mock.timers.tick(179_999);
    assert.equal(fetch.options()?.signal?.aborted, false);
    assert.deepEqual(JSON.parse(String(fetch.options()?.body)), { mode: "zones", zones: [] });
    t.mock.timers.tick(1);
    await rejection;
  }
});

test("read-only POST previews expire as reads without implying a saved mutation", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fetch = pendingFetch(t);
  const result = api("POST", "/api/awg2/routing/rules/import/preview", { document: "{}" }, { readOnly: true });
  const rejection = assert.rejects(result, (error: unknown) => error instanceof Error &&
    error.message.includes("Повторите обновление") && !error.message.includes("настройка могла сохраниться"));
  t.mock.timers.tick(30_000);
  await rejection;
  assert.equal(fetch.options()?.signal?.aborted, true);
});

test("a long engine install is not cancelled by the read or routing deadline", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fetch = pendingFetch(t);
  const result = api<{ ok: boolean }>("POST", "/api/awg2/install", {});
  t.mock.timers.tick(600_000);
  assert.equal(fetch.options()?.signal?.aborted, false);
  fetch.complete();
  assert.deepEqual(await result, { ok: true });
});

test("pausing a poll forwards cancellation without reporting it as a timeout", async (t) => {
  const fetch = pendingFetch(t);
  const controller = new AbortController();
  const result = api("GET", "/api/devices", undefined, { signal: controller.signal });
  const rejection = assert.rejects(result, (error: unknown) => error instanceof Error && error.name === "AbortError");
  controller.abort();
  await rejection;
  assert.equal(fetch.options()?.signal?.aborted, true);
});

test("a signal already cancelled at entry remains cancelled", async (t) => {
  const fetch = pendingFetch(t);
  await assert.rejects(api("GET", "/api/awg2", undefined, { signal: AbortSignal.abort() }),
    (error: unknown) => error instanceof Error && error.name === "AbortError");
  assert.equal(fetch.options()?.signal?.aborted, true);
});

test("an explicit deadline can bound a small mutation without changing other POSTs", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fetch = pendingFetch(t);
  const result = api("POST", "/api/awg2/trace/clear", {}, { timeoutMs: 5_000 });
  const rejection = assert.rejects(result, /Роутер не ответил вовремя/);
  t.mock.timers.tick(4_999);
  assert.equal(fetch.options()?.signal?.aborted, false);
  t.mock.timers.tick(1);
  await rejection;
});

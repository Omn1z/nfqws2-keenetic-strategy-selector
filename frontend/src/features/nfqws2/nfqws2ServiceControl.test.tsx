import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { Nfqws2ServiceControls } from "./Nfqws2ServiceControl";
import { Nfqws2ServiceController } from "./nfqws2ServiceControlModel";

const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const running = { running: true, manual_off: false };
const stopped = { running: false, manual_off: true };
const result = { name: "nfqws2", ok: true, detail: "ok" };
function mockFetch(t: TestContext, fetcher: typeof fetch) {
  const original = globalThis.fetch;
  globalThis.fetch = fetcher;
  t.after(() => { globalThis.fetch = original; });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

test("NFQWS2 controls show actual running state and one restart action without Reload", () => {
  const html = renderToStaticMarkup(<Nfqws2ServiceControls status={running} error="" pending={null} onToggle={() => {}} onRestart={() => {}} />);
  assert.match(html, /role="switch"/);
  assert.match(html, /aria-checked="true"/);
  assert.match(html, /Перезапуск службы/);
  assert.doesNotMatch(html, /reload|SIGHUP/i);
  const off = renderToStaticMarkup(<Nfqws2ServiceControls status={stopped} error="" pending={null} onToggle={() => {}} onRestart={() => {}} />);
  assert.match(off, /aria-checked="false"/);
  assert.match(off, /Остановлена/);
  assert.match(off, /<button[^>]*disabled[^>]*>Перезапуск службы<\/button>/);
});

test("unknown, failed and pending service status disable actions without inventing a successful toggle", () => {
  for (const props of [
    { status: null, error: "", pending: null },
    { status: running, error: "Роутер недоступен", pending: null },
    { status: running, error: "", pending: "stop" as const },
  ]) {
    const html = renderToStaticMarkup(<Nfqws2ServiceControls {...props} onToggle={() => {}} onRestart={() => {}} />);
    assert.match(html, /role="switch"[^>]*(?:disabled|aria-disabled="true")/);
    assert.match(html, /<button[^>]*disabled[^>]*>Перезапуск службы<\/button>/);
    if (props.status) assert.match(html, /aria-checked="true"/);
  }
});

test("start and stop use existing service APIs and accept only observed process state", async t => {
  const calls: string[] = [];
  let observed = stopped;
  mockFetch(t, (async (input, init) => {
    calls.push(`${init?.method} ${input}`);
    if (init?.method === "GET") return response(observed);
    if (String(input).endsWith("/start")) observed = running;
    if (String(input).endsWith("/stop")) observed = stopped;
    return response(result);
  }) as typeof fetch);
  const control = new Nfqws2ServiceController();
  await control.refresh();
  assert.deepEqual(await control.perform("start"), result);
  assert.deepEqual(control.status, running);
  assert.deepEqual(await control.perform("stop"), result);
  assert.deepEqual(control.status, stopped);
  assert.deepEqual(calls, ["GET /api/nfqws2/status", "POST /api/nfqws2/start", "GET /api/nfqws2/status", "POST /api/nfqws2/stop", "GET /api/nfqws2/status"]);
});

test("restart cannot enable a stopped or manually disabled NFQWS2 service", async t => {
  let writes = 0;
  let observed = stopped;
  mockFetch(t, (async (_input, init) => {
    if (init?.method !== "GET") writes++;
    return response(observed);
  }) as typeof fetch);
  const control = new Nfqws2ServiceController();
  await control.refresh();
  await assert.rejects(control.perform("restart"), /остановлена/);
  observed = { running: true, manual_off: true };
  await control.refresh();
  await assert.rejects(control.perform("restart"), /остановлена/);
  assert.equal(writes, 0);
});

test("duplicate clicks remain locked until restart and its actual-state read both finish", async t => {
  const command = deferred<Response>();
  const confirmed = deferred<Response>();
  const readingAfterCommand = deferred<void>();
  let reads = 0;
  let writes = 0;
  mockFetch(t, (async (_input, init) => {
    if (init?.method === "POST") { writes++; assert.deepEqual(JSON.parse(String(init.body)), { services: ["nfqws2"] }); return command.promise; }
    if (++reads === 1) return response(running);
    readingAfterCommand.resolve();
    return confirmed.promise;
  }) as typeof fetch);
  const control = new Nfqws2ServiceController();
  await control.refresh();
  const pending = control.perform("restart");
  assert.equal(control.pending, "restart");
  assert.equal(await control.perform("restart"), null);
  command.resolve(response({ results: [result] }));
  await readingAfterCommand.promise;
  assert.equal(control.pending, "restart");
  assert.equal(await control.perform("stop"), null);
  confirmed.resolve(response(running));
  assert.deepEqual(await pending, result);
  assert.equal(control.pending, null);
  assert.equal(writes, 1);
});

test("a delayed pre-stop poll cannot replace the fresh stopped state", async t => {
  const old = deferred<Response>();
  const oldStarted = deferred<void>();
  let reads = 0;
  mockFetch(t, (async (_input, init) => {
    if (init?.method === "POST") return response(result);
    reads++;
    if (reads === 1) return response(running);
    if (reads === 2) { oldStarted.resolve(); return old.promise; }
    return response(stopped);
  }) as typeof fetch);
  const control = new Nfqws2ServiceController();
  await control.refresh();
  const oldPoll = control.refresh();
  await oldStarted.promise;
  await control.perform("stop");
  old.resolve(response(running));
  assert.equal(await oldPoll, null);
  assert.deepEqual(control.status, stopped);
});

test("uncertain command failure still refreshes actual status and never assumes stopped", async t => {
  let reads = 0;
  mockFetch(t, (async (_input, init) => {
    if (init?.method === "POST") throw new Error("connection lost");
    reads++;
    return response(running);
  }) as typeof fetch);
  const control = new Nfqws2ServiceController();
  await control.refresh();
  await assert.rejects(control.perform("stop"), /connection lost/);
  assert.deepEqual(control.status, running);
  assert.equal(control.pending, null);
  assert.equal(reads, 2);
});

test("failed status reads keep the last snapshot but block new service mutations", async t => {
  let available = true;
  let writes = 0;
  mockFetch(t, (async (_input, init) => {
    if (init?.method === "POST") writes++;
    return available ? response(running) : response({ error: "offline" }, 503);
  }) as typeof fetch);
  const control = new Nfqws2ServiceController();
  await control.refresh();
  available = false;
  await control.refresh();
  assert.deepEqual(control.status, running);
  assert.equal(control.error, "offline");
  await assert.rejects(control.perform("stop"), /подтверждения состояния/);
  assert.equal(writes, 0);
});

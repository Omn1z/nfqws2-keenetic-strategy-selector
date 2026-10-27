import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { AwgRecoverySettings } from "@/types/api";
import GeneralPane from "./GeneralPane";
import { collectRecoverySettings, defaultRecoverySettings, recoveryDirty, recoveryDraft, recoveryToForm, saveRecoverySettings, syncRecoveryDraft } from "./recoverySettings";

test("global recovery form converts its minute cutoff and rejects out-of-range or incomplete schedules", () => {
  assert.deepEqual(collectRecoverySettings(recoveryToForm(defaultRecoverySettings)), defaultRecoverySettings);
  assert.equal(collectRecoverySettings({ ...recoveryToForm(defaultRecoverySettings), slowAfterMinutes: "30" }).slow_retry_after_seconds, 1800);
  const secondsFromAPI = { ...defaultRecoverySettings, slow_retry_after_seconds: 1850 };
  assert.deepEqual(collectRecoverySettings(recoveryToForm(secondsFromAPI)), secondsFromAPI);
  for (const [key, values] of Object.entries({
    fastSeconds: ["", "0", "601", "1.5", "1e2"], retrySeconds: ["0", "31"],
    slowAfterMinutes: ["29", "61"], slowSeconds: ["89", "901"], handshakeSeconds: ["4", "61"],
  })) {
    for (const value of values) assert.throws(() => collectRecoverySettings({ ...recoveryToForm(defaultRecoverySettings), [key]: value }));
  }
});

test("global recovery drafts follow clean polls and preserve dirty edits when a different profile is selected", () => {
  const initial = recoveryDraft(defaultRecoverySettings);
  const updated = { ...defaultRecoverySettings, retry_delay_seconds: 7 };
  assert.equal(recoveryDirty(initial), false);
  const clean = syncRecoveryDraft(initial, updated);
  assert.equal(clean.form.retrySeconds, "7");
  const editing = { ...initial, form: { ...initial.form, slowAfterMinutes: "45" } };
  const afterProfilePoll = syncRecoveryDraft(editing, updated);
  assert.equal(afterProfilePoll.form.slowAfterMinutes, "45");
  assert.equal(afterProfilePoll.form.retrySeconds, "5");
  assert.equal(recoveryDirty(afterProfilePoll), true);
  assert.equal(afterProfilePoll.saved.retry_delay_seconds, 7);
  const acknowledged = recoveryDraft(collectRecoverySettings(afterProfilePoll.form));
  assert.equal(recoveryDirty(acknowledged), false);
  assert.equal(acknowledged.saved.slow_retry_after_seconds, 2700);
});

test("general settings explain the fast minute, bounded handshake and late slow retries without contacting a server", (t) => {
  const requests = t.mock.method(globalThis, "fetch", () => { throw new Error("render must not mutate global settings"); });
  const html = renderToStaticMarkup(<GeneralPane settings={defaultRecoverySettings} acceptStatus={() => {}} onBusyChange={() => {}} externalBusy={false} />);
  assert.match(html, /общие настройки для всех AWG и WARP/);
  assert.match(html, /Выбор профиля во вкладке «Сервер» на него не влияет/);
  assert.match(html, /Первые 60 с отказа/);
  assert.match(html, /пауза 5 с между попытками/);
  assert.match(html, /После 60 мин непрерывного отказа — пауза 90 с/);
  assert.match(html, /нет дополнительной паузы/);
  assert.match(html, /handshake до 20 с/);
  assert.equal(requests.mock.callCount(), 0);
});

test("global schedule save sends only recovery settings and retains the server acknowledgement", async (t) => {
  const requestSettings: AwgRecoverySettings = { ...defaultRecoverySettings, slow_retry_after_seconds: 2700 };
  const acknowledged = { ...requestSettings, retry_delay_seconds: 6 };
  const calls: { path: unknown; options?: RequestInit }[] = [];
  t.mock.method(globalThis, "fetch", async (path: unknown, options?: RequestInit) => {
    calls.push({ path, options });
    return new Response(JSON.stringify({ active_server_id: "another-profile", recovery_settings: acknowledged }), { status: 200 });
  });
  const next = await saveRecoverySettings(requestSettings);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, "/api/awg2/settings/recovery");
  assert.equal(calls[0].options?.method, "POST");
  assert.deepEqual(JSON.parse(calls[0].options?.body as string), requestSettings);
  assert.deepEqual(next.recovery_settings, acknowledged);
  assert.equal(next.active_server_id, "another-profile");
});

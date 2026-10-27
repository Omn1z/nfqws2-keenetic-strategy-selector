import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { AwgClientStatus } from "@/types/api";
import RecoveryStatus, { recoveryPhaseLabel } from "./RecoveryStatus";

const client: AwgClientStatus = {
  running: true, iface_present: true, last_handshake: 0, rx_bytes: 0, tx_bytes: 0,
  endpoint: "192.0.2.1:2408", address: "10.0.0.2/32", mtu: 1420, connected: false,
  recovering: true, retry_count: 2, verification_until: 1020, retry_at: 1025,
};

test("recovery cards distinguish the handshake window from its later retry pause", () => {
  assert.equal(recoveryPhaseLabel(client, 1000), "ожидаем handshake: ещё 20 с");
  assert.equal(recoveryPhaseLabel(client, 1019), "ожидаем handshake: ещё 1 с");
  assert.equal(recoveryPhaseLabel(client, 1020), "пауза перед повтором: 5 с");
  assert.equal(recoveryPhaseLabel(client, 1024), "пауза перед повтором: 1 с");
  assert.equal(recoveryPhaseLabel(client, 1025), "подключаемся / проверяем");
  assert.equal(recoveryPhaseLabel({ ...client, retry_at: 0 }, 1100), "подключаемся / проверяем");
});

test("older recovery snapshots and failed local starts keep a neutral readable deadline", () => {
  const legacy = { ...client, verification_until: undefined };
  assert.equal(recoveryPhaseLabel(legacy, 1000), "повтор через 25 с");
  assert.equal(recoveryPhaseLabel({ ...legacy, retry_at: undefined }, 1000), "подключаемся / проверяем");
});

test("recovery cards render handshake evidence and errors without advertising an extra wait", (t) => {
  t.mock.method(Date, "now", () => 1000_000);
  const html = renderToStaticMarkup(<RecoveryStatus client={{ ...client, recovery_error: "peer <offline>" }} />);
  assert.match(html, /role="status"/);
  assert.match(html, /попыток: 2/);
  assert.match(html, /ожидаем handshake: ещё 20 с/);
  assert.doesNotMatch(html, /25 с|пауза перед повтором|повтор через/);
  assert.match(html, /peer &lt;offline&gt;/);
  assert.equal(renderToStaticMarkup(<RecoveryStatus client={{ ...client, recovering: false }} />), "");
});

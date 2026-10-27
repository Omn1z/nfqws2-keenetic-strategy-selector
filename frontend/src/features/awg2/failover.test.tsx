import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { Awg2ServerSummary, Awg2Status, AwgConnectionTestResult } from "@/types/api";
import FailoverPane, { ConnectionFailoverBadge, ConnectionTestResult } from "./FailoverPane";
import { backupCreatesCycle, backupIDs, connectionTestPresentation, moveBackup } from "./failoverModel";

const summary = (id: string, patch: Partial<Awg2ServerSummary> = {}): Awg2ServerSummary => ({
  id, label: id, host: "", endpoint: "192.0.2.1:51820", client_iface: "awg0", enabled: true, imported: true,
  protocol: "awg", active: false, deployed: true, connected: false, reachable: false,
  has_password: false, has_key: false, has_server_key: true,
  failover: { standby: false, activated: false, active_tunnel_id: id, fallback_tunnel_ids: [] }, ...patch,
});
const failover = (ids: string[], patch: Partial<NonNullable<Awg2ServerSummary["failover"]>> = {}): NonNullable<Awg2ServerSummary["failover"]> => ({
  fallback_tunnel_ids: ids, standby: false, activated: false, active_tunnel_id: "primary", ...patch,
});
const fixture = (): Awg2Status => ({
  active_server_id: "primary",
  config: {
    enabled: true, protocol: "awg", conn: { host: "", port: 22, user: "root", auth_kind: "password", known_key: "" },
    install: "imported", public_key: "", listen_port: 51820, address: "10.0.0.1/24", subnet: "10.0.0.0/24", mtu: 1420,
    dns: "1.1.1.1", wan_iface: "", endpoint: "192.0.2.1:51820", obf: { jc: 0, jmin: 0, jmax: 0, s1: 0, s2: 0, s3: 0, s4: 0, h1: "1", h2: "2", h3: "3", h4: "4", i1: "", i2: "", i3: "", i4: "", i5: "" },
    peers: [], client: { enabled: true, peer_id: "", fallback_tunnel_ids: ["reserve-two", "reserve-one", "deleted"] }, routing: { mode: "zones", zones: [], mtu: 1420, killswitch: true, domain_source: "dnsproxy" }, interface: "awg0", deployed_at: 1,
  },
  servers: [summary("primary", { active: true, failover: failover(["reserve-two", "reserve-one", "deleted"]) }), summary("reserve-one", { enabled: false }), summary("reserve-two", { failover: failover([], { standby: true, active_tunnel_id: "reserve-two" }) }), summary("extra")],
  has_password: false, has_key: false, has_server_key: true, deployed: true, last_deploy: null, status: null, endpoint: "192.0.2.1:51820",
  engine: { installed: true, awg_version: "", arch: "arm64", supported: true, tun_ok: true }, client: null,
});

test("connection backups preserve priority, omit self and duplicates, and retain unavailable references", () => {
  assert.deepEqual(backupIDs("primary", [" reserve-two ", "primary", "reserve-one", "reserve-two", "", "deleted"]), ["reserve-two", "reserve-one", "deleted"]);
  const ids = ["reserve-two", "reserve-one", "deleted"];
  assert.deepEqual(moveBackup(ids, 1, -1), ["reserve-one", "reserve-two", "deleted"]);
  assert.deepEqual(moveBackup(ids, 1, 1), ["reserve-two", "deleted", "reserve-one"]);
  assert.deepEqual(moveBackup(ids, 0, -1), ids);
  assert.deepEqual(moveBackup(ids, 2, 1), ids);
  assert.deepEqual(ids, ["reserve-two", "reserve-one", "deleted"]);
});

test("backup candidates exclude direct and transitive cycles without looping on malformed saved graphs", () => {
  const servers = [summary("a", { failover: failover(["b"]) }), summary("b", { failover: failover(["primary"]) }), summary("x", { failover: failover(["y"]) }), summary("y", { failover: failover(["x"]) })];
  assert.equal(backupCreatesCycle("primary", "primary", servers), true);
  assert.equal(backupCreatesCycle("primary", "a", servers), true);
  assert.equal(backupCreatesCycle("primary", "b", servers), true);
  assert.equal(backupCreatesCycle("primary", "x", servers), false);
  assert.equal(backupCreatesCycle("primary", "missing", servers), false);
});

test("backup editor renders configured priority, unavailable entries and bulk real connection checks without starting probes", (t) => {
  const requests = t.mock.method(globalThis, "fetch", () => { throw new Error("render must not open a tunnel"); });
  const html = renderToStaticMarkup(<FailoverPane st={fixture()} acceptStatus={() => {}} reload={async () => {}} onBusyChange={() => {}} externalBusy={false} />);
  const list = html.slice(html.indexOf('<ol'), html.indexOf('</ol>'));
  assert.ok(list.indexOf('reserve-two') < list.indexOf('reserve-one'));
  assert.ok(list.indexOf('reserve-one') < list.indexOf('deleted'));
  assert.match(list, /подключение удалено/);
  assert.match(html, /можно выбрать сразу несколько/);
  assert.match(html, /Проверить основной и резервы/);
  assert.match(html, /Проверка временно запускает ожидающий туннель/);
  assert.match(html, /Включите его в списке VPN/);
  assert.equal(requests.mock.callCount(), 0);
});

test("test results distinguish a live data test from handshake-only or unsuccessful checks", () => {
  const result: AwgConnectionTestResult = { server_id: "primary", success: true, handshake: true, data_ok: true, latency_ms: 12.3, endpoint: "192.0.2.1:51820", egress_ip: "198.51.100.2", checked_at: 1793060400 };
  assert.equal(connectionTestPresentation(result).kind, "ok");
  assert.equal(connectionTestPresentation({ ...result, data_ok: false }).kind, "warn");
  assert.equal(connectionTestPresentation({ ...result, success: false }).kind, "warn");
  assert.equal(connectionTestPresentation({ ...result, handshake: false }).kind, "bad");
  const success = renderToStaticMarkup(<ConnectionTestResult result={result} />);
  assert.match(success, /Связь подтверждена/);
  assert.match(success, /198\.51\.100\.2/);
  const failed = renderToStaticMarkup(<ConnectionTestResult result={{ ...result, success: false, data_ok: false, error: "<script>timeout</script>" }} />);
  assert.match(failed, /Handshake есть, передача данных не подтверждена/);
  assert.match(failed, /&lt;script&gt;timeout&lt;\/script&gt;/);
  assert.equal(failed.includes("<script>"), false);
  const cleanupFailed = renderToStaticMarkup(<ConnectionTestResult result={{ ...result, success: false, error: "не удалось остановить временный туннель" }} />);
  assert.match(cleanupFailed, /Связь есть, проверка завершилась с ошибкой/);
  assert.match(cleanupFailed, /Данные: получены/);
  assert.match(cleanupFailed, /не удалось остановить временный туннель/);
  assert.equal(cleanupFailed.includes("передача данных не подтверждена"), false);
  const incomplete = renderToStaticMarkup(<ConnectionTestResult result={{ ...result, success: false, request_error: true, error: "request timeout" }} />);
  assert.match(incomplete, /Проверка не завершена/);
  assert.equal(incomplete.includes("Handshake:"), false);
});

test("connection cards distinguish dormant reserves, activated reserves and the active fallback path", () => {
  const servers = [summary("reserve", { label: "Резерв Москва" })];
  const render = (patch: Partial<NonNullable<Awg2ServerSummary["failover"]>>) => renderToStaticMarkup(<ConnectionFailoverBadge server={summary("primary", { failover: failover([], patch) })} servers={servers} />);
  assert.match(render({ standby: true, activated: false }), /резерв · ожидание/);
  assert.match(render({ standby: true, activated: true }), /резерв задействован/);
  assert.match(render({ active_tunnel_id: "reserve" }), /через резерв: Резерв Москва/);
  assert.equal(render({}).includes("через резерв"), false);
});

test("empty connection backup list explains the difference from reserves assigned to an individual rule", () => {
  const st = fixture();
  st.config.client.fallback_tunnel_ids = [];
  const html = renderToStaticMarkup(<FailoverPane st={st} acceptStatus={() => {}} reload={async () => {}} onBusyChange={() => {}} externalBusy={false} />);
  assert.match(html, /Общий резерв для primary ещё не выбран/);
  assert.match(html, /только для этого правила/);
  assert.match(html, /для всех его правил, включая новые списки/);
});

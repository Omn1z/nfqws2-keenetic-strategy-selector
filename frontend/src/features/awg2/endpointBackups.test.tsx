import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { Awg2Status, AwgClientStatus, AwgServerConfig } from "@/types/api";
import EndpointBackupsPane, { EndpointSelectionStatus } from "./EndpointBackupsPane";
import ServerPane from "./ServerPane";
import { endpointPort, moveEndpointBackup, normalizeEndpointBackup, primaryEndpointForBackups, saveEndpointBackups, validateEndpointBackups } from "./endpointBackups";

const primary = "vpn.example.com:51820";
const config = (patch: Partial<AwgServerConfig> = {}): AwgServerConfig => ({
  enabled: true, protocol: "awg", conn: { host: "192.0.2.1", port: 22, user: "root", auth_kind: "password", known_key: "" },
  install: "imported", public_key: "same-server-public-key", listen_port: 51820, address: "10.0.0.1/24", subnet: "10.0.0.0/24", mtu: 1420,
  dns: "1.1.1.1", wan_iface: "", endpoint: primary,
  obf: { jc: 0, jmin: 0, jmax: 0, s1: 0, s2: 0, s3: 0, s4: 0, h1: "1", h2: "2", h3: "3", h4: "4", i1: "", i2: "", i3: "", i4: "", i5: "" },
  peers: [], client: { enabled: true, peer_id: "router-peer", fallback_tunnel_ids: ["other-server"], endpoint_backups: ["198.51.100.2:51820", "198.51.100.1:51820"] },
  routing: { mode: "zones", zones: [], mtu: 1420, killswitch: true, domain_source: "dnsproxy" }, interface: "awg0", deployed_at: 1, ...patch,
});
const client = (patch: Partial<AwgClientStatus> = {}): AwgClientStatus => ({
  running: true, iface_present: true, last_handshake: 1, rx_bytes: 0, tx_bytes: 0, endpoint: "198.51.100.2:51820", address: "10.0.0.2/32", mtu: 1420, connected: true,
  endpoint_primary: primary, endpoint_candidate: "198.51.100.2:51820", endpoint_index: 1, endpoint_count: 3, ...patch,
});
const fixture = (patch: Partial<AwgServerConfig> = {}, warp = false): Awg2Status => ({
  active_server_id: "same-server", config: config(patch),
  servers: [{ id: "same-server", label: "Same server", host: "192.0.2.1", endpoint: primary, client_iface: "awg0", enabled: true, imported: patch.install !== "userspace", protocol: patch.protocol || "awg", active: true, deployed: true, connected: true, reachable: true, has_password: false, has_key: false, has_server_key: true, is_warp: warp }],
  has_password: false, has_key: false, has_server_key: true, deployed: true, last_deploy: null, status: null, endpoint: primary,
  engine: { installed: true, awg_version: "3.1", awg3_supported: true, arch: "arm64", supported: true, tun_ok: true }, client: client(),
});

test("same-server IP backups normalize literals and inherit only the primary UDP port", () => {
  assert.equal(endpointPort(primary), "51820");
  assert.equal(endpointPort("[2001:db8::1]:2408"), "2408");
  for (const [value, expected] of [
    [" 198.51.100.2 ", "198.51.100.2:51820"],
    ["198.51.100.2:2408", "198.51.100.2:2408"],
    ["2001:DB8:0:0::2", "[2001:db8::2]:51820"],
    ["[2001:db8::2]", "[2001:db8::2]:51820"],
    ["[2001:DB8::2]:2408", "[2001:db8::2]:2408"],
    ["::ffff:198.51.100.2", "198.51.100.2:51820"],
  ]) assert.equal(normalizeEndpointBackup(value, primary), expected);
  assert.equal(primaryEndpointForBackups(config(), "198.51.100.2:51820"), primary);
  assert.equal(primaryEndpointForBackups(config({ endpoint: "" }), "192.0.2.1:2408"), "192.0.2.1:2408");
  assert.equal(primaryEndpointForBackups(config({ endpoint: "", conn: { ...config().conn, host: "2001:db8::1" } }), ""), "[2001:db8::1]:51820");
});

test("IP backup validation rejects hostnames, malformed IPs, port errors and endpoint syntax that could be mistaken for a literal", () => {
  for (const invalid of ["", "example.com", "https://198.51.100.2", "198.51.100.2/32", "user@198.51.100.2", "192.0.2", "192.000.2.1", "256.0.0.1", "198.51.100.2:", "198.51.100.2:0", "198.51.100.2:65536", "198.51.100.2:1.5", "198.51.100.2:1e2", "198.51.100.2 51820", "[2001:db8::2", "2001::db8::2", "[2001:db8::2]:no", "fe80::1%eth0", "[2001:db8::2]:0", "0.0.0.0", "224.0.0.1", "::", "ff02::1", "::ffff:0.0.0.0"]) {
    assert.throws(() => normalizeEndpointBackup(invalid, primary), invalid);
  }
  assert.throws(() => endpointPort("vpn.example.com"), /UDP-порт/);
});

test("IP backup priority remains ordered and separate from the main endpoint, with duplicate and size protection", () => {
  const values = ["198.51.100.2", "[2001:db8::2]:2408", "198.51.100.3:51820"];
  assert.deepEqual(validateEndpointBackups(values, primary), ["198.51.100.2:51820", "[2001:db8::2]:2408", "198.51.100.3:51820"]);
  assert.deepEqual(moveEndpointBackup(values, 1, -1), [values[1], values[0], values[2]]);
  assert.deepEqual(moveEndpointBackup(values, 1, 1), [values[0], values[2], values[1]]);
  assert.deepEqual(moveEndpointBackup(values, 0, -1), values);
  assert.deepEqual(moveEndpointBackup(values, 2, 1), values);
  assert.deepEqual(values, ["198.51.100.2", "[2001:db8::2]:2408", "198.51.100.3:51820"]);
  assert.throws(() => validateEndpointBackups(["198.51.100.2", "198.51.100.2:51820"], primary), /уже есть/);
  assert.throws(() => validateEndpointBackups(["2001:db8::2", "[2001:DB8:0:0::2]:51820"], primary), /уже есть/);
  assert.throws(() => validateEndpointBackups(["192.0.2.1"], "192.0.2.1:51820"), /основные/);
  assert.throws(() => validateEndpointBackups(Array.from({ length: 9 }, (_, at) => `198.51.100.${at + 1}`), primary), /не более 8/);
  assert.equal(validateEndpointBackups(Array.from({ length: 8 }, (_, at) => `198.51.100.${at + 1}`), primary).length, 8);
  assert.deepEqual(validateEndpointBackups([], ""), []);
});

test("saving IP backups sends only the selected server's ordered pool and an explicit empty list clears it", async t => {
  const calls: { path: unknown; options?: RequestInit }[] = [];
  const next = fixture();
  t.mock.method(globalThis, "fetch", async (path: unknown, options?: RequestInit) => {
    calls.push({ path, options });
    return new Response(JSON.stringify(next), { status: 200 });
  });
  assert.deepEqual(await saveEndpointBackups("server/one", ["198.51.100.9", "198.51.100.8:2408"], primary), next);
  assert.equal(calls[0].path, "/api/awg2/servers/server%2Fone/endpoint-backups");
  assert.equal(calls[0].options?.method, "POST");
  assert.deepEqual(JSON.parse(calls[0].options?.body as string), { endpoint_backups: ["198.51.100.9:51820", "198.51.100.8:2408"] });
  await saveEndpointBackups("server/one", [], primary);
  assert.deepEqual(JSON.parse(calls[1].options?.body as string), { endpoint_backups: [] });
  assert.equal(calls.length, 2);
});

test("a backend IP pool error is surfaced and invalid local input sends no request", async t => {
  const request = t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ error: "Адрес не поддерживается" }), { status: 400 }));
  await assert.rejects(saveEndpointBackups("same-server", ["198.51.100.9"], primary), /Адрес не поддерживается/);
  assert.equal(request.mock.callCount(), 1);
  assert.throws(() => saveEndpointBackups("same-server", ["invalid.example"], primary));
  assert.equal(request.mock.callCount(), 1);
});

test("current endpoint status uses actual runtime IP and explicit backup selection without rewriting a hostname primary", () => {
  const backup = renderToStaticMarkup(<EndpointSelectionStatus client={client()} />);
  assert.match(backup, /Резервный IP №1/);
  assert.match(backup, /198\.51\.100\.2:51820/);
  const activePrimary = renderToStaticMarkup(<EndpointSelectionStatus client={client({ endpoint_index: 0, endpoint_candidate: primary, endpoint: "192.0.2.1:51820" })} />);
  assert.match(activePrimary, /Основной адрес/);
  assert.match(activePrimary, /192\.0\.2\.1:51820/);
  const legacy = renderToStaticMarkup(<EndpointSelectionStatus client={client({ endpoint_index: undefined })} />);
  assert.match(legacy, /Адрес подключения/);
  assert.doesNotMatch(legacy, /Основной адрес/);
  assert.match(renderToStaticMarkup(<EndpointSelectionStatus client={client({ endpoint_index: -1 })} />), /Адрес подключения/);
  const exhausted = renderToStaticMarkup(<EndpointSelectionStatus client={client({ endpoint: "", endpoint_candidate: "", endpoint_pool_exhausted: true })} />);
  assert.match(exhausted, /Все IP-адреса этого сервера проверены/);
});

test("IP editor shows priority, address ownership and sticky selection for imported AWG, WG and WARP without requests", t => {
  const request = t.mock.method(globalThis, "fetch", () => { throw new Error("render must not save or probe an endpoint"); });
  for (const [patch, warp] of [[{}, false], [{ protocol: "wireguard" }, false], [{}, true], [{ install: "userspace" }, false]] as const) {
    const st = fixture(patch, warp);
    const html = renderToStaticMarkup(<ServerPane st={st} reload={async () => {}} acceptStatus={() => {}} deployActive={async () => true} deploying={false} onFormatBusyChange={() => {}} onBusyChange={() => {}} externalBusy={false} onOpenEngineSettings={() => {}} />);
    assert.match(html, /Резервные IP-адреса/);
    assert.match(html, /до следующего сбоя или перезапуска подключения/);
    assert.match(html, /после всех IP этого сервера/);
    assert.match(html, /с теми же ключами/);
    assert.match(html, /без порта используется UDP 51820/);
    const list = html.slice(html.indexOf("<ol"), html.indexOf("</ol>"));
    assert.ok(list.indexOf("198.51.100.2") < list.indexOf("198.51.100.1"));
    assert.match(list, /Поднять резервный IP/);
    assert.match(list, /Опустить резервный IP/);
    assert.match(list, /Удалить резервный IP/);
  }
  const empty = fixture();
  empty.config.client.endpoint_backups = [];
  assert.match(renderToStaticMarkup(<EndpointBackupsPane st={empty} acceptStatus={() => {}} onBusyChange={() => {}} externalBusy={false} />), /пока не добавлены/);
  assert.equal(request.mock.callCount(), 0);
});

test("backup IPs inherit the deployed primary port while a different server endpoint awaits deployment", () => {
  const st = fixture({ endpoint: "pending.example:51820" });
  st.deployment_pending = true;
  st.client = client({ endpoint_primary: "deployed.example:2408", endpoint: "198.51.100.2:443" });
  const html = renderToStaticMarkup(<EndpointBackupsPane st={st} acceptStatus={() => {}} onBusyChange={() => {}} externalBusy={false} />);
  assert.match(html, /без порта используется UDP 2408/);
  assert.match(html, /deployed\.example:2408/);
  assert.doesNotMatch(html, /pending\.example:51820/);
});

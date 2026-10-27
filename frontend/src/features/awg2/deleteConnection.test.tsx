import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { Awg2ServerSummary, Awg2Status, AwgZone } from "@/types/api";
import { DeleteConnectionDetails } from "./DeleteConnectionModal";
import { deleteConnection, deleteConnectionCandidates, deleteConnectionProblem, deleteConnectionReferences, deletionWouldCreateCycle, initialDeleteConnectionSelection } from "./deleteConnection";

const server = (id: string, patch: Partial<Awg2ServerSummary> = {}): Awg2ServerSummary => ({
  id, label: id, host: "", endpoint: "192.0.2.1:51820", client_iface: "awg0", enabled: true, imported: true,
  protocol: "awg", active: false, deployed: true, connected: false, reachable: false,
  has_password: false, has_key: false, has_server_key: true,
  failover: { standby: false, activated: false, active_tunnel_id: "", fallback_tunnel_ids: [] }, ...patch,
});
const rule = (name: string, tunnelID: string, patch: Partial<AwgZone> = {}): AwgZone => ({
  name, tunnel_id: tunnelID, enabled: true, route: "tunnel", domains: ["list:user", "example.com"], ips: ["203.0.113.0/24"], source_ips: ["192.0.2.2"], order: 1, ...patch,
});
const state = (servers: Awg2ServerSummary[], rules: AwgZone[] = []): Awg2Status => ({
  servers, active_server_id: "source", routing_rules: rules,
  config: { routing: { zones: [] } },
}) as unknown as Awg2Status;

test("delete dialog defaults to transfer, prefers a connected target, and retains disabled/offline alternatives", () => {
  const servers = [server("source"), server("disabled", { enabled: false }), server("offline"), server("connected", { connected: true })];
  const snapshot = JSON.stringify(servers);
  assert.deepEqual(initialDeleteConnectionSelection(servers, "source"), { mode: "transfer", replacementID: "connected" });
  assert.deepEqual(deleteConnectionCandidates(servers, "source").map((entry) => entry.id), ["connected", "offline", "disabled"]);
  assert.equal(JSON.stringify(servers), snapshot);
  assert.deepEqual(initialDeleteConnectionSelection([server("source")], "source"), { mode: "waiting", replacementID: "" });
});

test("reference counters include waiting and disabled rules, direct/device criteria and fallback users without double counting owners", () => {
  const primary = [rule("disabled", "source", { enabled: false }), rule("waiting", "source", { waiting_for_connection: true }), rule("devices-direct", "source", { route: "direct", fallback_tunnel_ids: ["source"] })];
  const backups = [rule("backup", "other", { fallback_tunnel_ids: ["source", "source"] })];
  const st = state([server("source"), server("other", { failover: { standby: false, activated: false, active_tunnel_id: "", fallback_tunnel_ids: ["source"] } })], [...primary, ...backups, rule("unrelated", "other")]);
  assert.deepEqual(deleteConnectionReferences(st, "source"), { primaryRules: primary, fallbackRules: backups, connectionBackups: 1 });
  const legacy = { ...st, routing_rules: undefined, routing_config: { mode: "zones", zones: primary, mtu: 1420, killswitch: true, domain_source: "resolve" } };
  assert.equal(deleteConnectionReferences(legacy, "source").primaryRules.length, 3);
  assert.equal(deleteConnectionReferences({ ...st, routing_rules: [] }, "source").primaryRules.length, 0);
});

test("polling cannot silently replace a removed target or discard an explicit leave-waiting choice", () => {
  const selection = Object.freeze({ mode: "transfer" as const, replacementID: "chosen" });
  const before = [server("source"), server("chosen"), server("another")];
  assert.equal(deleteConnectionProblem(before, "source", selection), "");
  const after = [server("source"), server("another", { connected: true })];
  assert.match(deleteConnectionProblem(after, "source", selection), /больше недоступно/);
  assert.equal(selection.replacementID, "chosen");
  assert.equal(deleteConnectionProblem(after, "source", { mode: "waiting", replacementID: "chosen" }), "");
  assert.match(deleteConnectionProblem(after, "source", { mode: "transfer", replacementID: "source" }), /другое подключение/);
  assert.match(deleteConnectionProblem(after, "source", { mode: "transfer", replacementID: "" }), /Выберите подключение/);
  assert.match(deleteConnectionProblem([server("another")], "source", { mode: "waiting", replacementID: "" }), /уже отсутствует/);
});

test("remapping checks the resulting backup graph and ignores deduplicated self references", () => {
  const graph = [server("source"), server("a", { connected: true, failover: { standby: false, activated: false, active_tunnel_id: "", fallback_tunnel_ids: ["b"] } }), server("b", { failover: { standby: false, activated: false, active_tunnel_id: "", fallback_tunnel_ids: ["source", "source"] } }), server("safe")];
  assert.equal(deletionWouldCreateCycle(graph, "source", "a"), true);
  assert.match(deleteConnectionProblem(graph, "source", { mode: "transfer", replacementID: "a" }), /цикл/);
  assert.equal(deletionWouldCreateCycle(graph, "source", "b"), false);
  assert.equal(deleteConnectionProblem(graph, "source", { mode: "transfer", replacementID: "b" }), "");
  assert.equal(initialDeleteConnectionSelection(graph, "source").replacementID, "b");
});

test("inheriting the removed profile's backups cannot close a cycle or become the default replacement", () => {
  const withBackups = (id: string, backups: string[], connected = false) => server(id, {
    connected, failover: { standby: false, activated: false, active_tunnel_id: "", fallback_tunnel_ids: backups },
  });
  const graph = [withBackups("source", ["backup"]), withBackups("target", ["existing"], true), withBackups("backup", ["target"]), withBackups("existing", [])];
  const snapshot = JSON.stringify(graph);
  // source → backup → target → existing is valid until target inherits backup.
  assert.equal(deletionWouldCreateCycle(graph, "source", "target"), true);
  assert.match(deleteConnectionProblem(graph, "source", { mode: "transfer", replacementID: "target" }), /цикл/);
  assert.equal(deletionWouldCreateCycle(graph, "source", "backup"), false);
  assert.equal(initialDeleteConnectionSelection(graph, "source").replacementID, "backup");
  assert.equal(JSON.stringify(graph), snapshot);
});

test("delete details render exact scope, offline warnings, missing targets and backend errors without requesting anything", (t) => {
  const requests = t.mock.method(globalThis, "fetch", async () => { throw new Error("render cannot delete"); });
  const st = state([server("source"), server("target", { enabled: false, connected: false })], [rule("saved", "source")]);
  const html = renderToStaticMarkup(<DeleteConnectionDetails st={st} sourceID="source" sourceLabel="AWG1" selection={{ mode: "transfer", replacementID: "target" }} onChange={() => {}} disabled={false} error="<script>apply error</script>" />);
  assert.match(html, /Правил этого подключения: <strong>1<\/strong>/);
  assert.match(html, /Сохранятся домены, IP\/CIDR, ссылки на списки, фильтры устройств, порядок/);
  assert.match(html, /Резервы удаляемого профиля добавятся после существующих резервов выбранного подключения/);
  assert.match(html, /Выбранное подключение выключено/);
  assert.match(html, /не включит сервер/);
  assert.match(html, /Если этот VPN явно выбран в DNS-сервере или Telegram-прокси, выберите новое подключение также в их настройках/);
  assert.match(html, /&lt;script&gt;apply error&lt;\/script&gt;/);
  assert.equal(html.includes("<script>"), false);
  const missing = renderToStaticMarkup(<DeleteConnectionDetails st={st} sourceID="source" sourceLabel="AWG1" selection={{ mode: "transfer", replacementID: "vanished" }} onChange={() => {}} disabled={false} />);
  assert.match(missing, /Выбранное подключение больше недоступно/);
  const alone = renderToStaticMarkup(<DeleteConnectionDetails st={state([server("source")])} sourceID="source" sourceLabel="AWG1" selection={{ mode: "waiting", replacementID: "" }} onChange={() => {}} disabled={false} />);
  assert.match(alone, /Других подключений нет/);
  assert.match(alone, /сохранятся в ожидании/);
  assert.equal(requests.mock.callCount(), 0);
});

test("confirmed transfer sends a single DELETE with encoded replacement, without editing rules or selection first", async (t) => {
  const st = state([server("source/1"), server("target&2")], [rule("saved", "source/1")]);
  const snapshot = JSON.stringify(st);
  const next = state([server("target&2")], [rule("saved", "target&2")]);
  const requests = t.mock.method(globalThis, "fetch", async (url: string | URL | Request, options?: RequestInit) => {
    assert.equal(url, "/api/awg2/servers/source%2F1?replacement_id=target%262");
    assert.equal(options?.method, "DELETE");
    assert.equal(options?.body, undefined);
    return new Response(JSON.stringify(next));
  });
  assert.deepEqual(await deleteConnection(st, "source/1", { mode: "transfer", replacementID: "target&2" }), next);
  assert.equal(requests.mock.callCount(), 1);
  assert.equal(JSON.stringify(st), snapshot);
});

test("leave-waiting uses the legacy DELETE route; invalid or removed targets never request deletion", async (t) => {
  const st = state([server("source"), server("other")]);
  const requests = t.mock.method(globalThis, "fetch", async (url: string | URL | Request, options?: RequestInit) => {
    assert.equal(url, "/api/awg2/servers/source");
    assert.equal(options?.method, "DELETE");
    return new Response(JSON.stringify(state([server("other")])));
  });
  await deleteConnection(st, "source", { mode: "waiting", replacementID: "previously-chosen" });
  assert.equal(requests.mock.callCount(), 1);
  await assert.rejects(deleteConnection(st, "source", { mode: "transfer", replacementID: "missing" }), /больше недоступно/);
  await assert.rejects(deleteConnection(st, "source", { mode: "transfer", replacementID: "source" }), /другое подключение/);
  await assert.rejects(deleteConnection(state([server("other")]), "source", { mode: "waiting", replacementID: "" }), /уже отсутствует/);
  assert.equal(requests.mock.callCount(), 1);
});

test("committed deletion warning preserves the accepted status, while a validation failure rejects without retry", async (t) => {
  const st = state([server("source"), server("target")]);
  const next = { ...state([server("target")]), warning: "Правила сохранены; не удалось восстановить маршруты" };
  const requests = t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify(next)));
  const result = await deleteConnection(st, "source", { mode: "transfer", replacementID: "target" });
  assert.deepEqual(result, next);
  assert.equal(result.warning, next.warning);
  assert.equal(result.servers.some((entry) => entry.id === "source"), false);
  assert.equal(requests.mock.callCount(), 1);
  requests.mock.mockImplementation(async () => new Response(JSON.stringify({ error: "Перенос создаёт цикл резервов" }), { status: 400 }));
  await assert.rejects(deleteConnection(st, "source", { mode: "transfer", replacementID: "target" }), /цикл резервов/);
  assert.equal(requests.mock.callCount(), 2);
});

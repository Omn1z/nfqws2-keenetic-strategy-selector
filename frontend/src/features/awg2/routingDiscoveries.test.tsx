import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { AwgRoutingDiscoveries, AwgRoutingLearnedEntry, AwgZone } from "@/types/api";
import { readRoutingDiscoveries, RoutingDiscoveries } from "./RoutingDiscoveries";
import { matchingRoutingDiscovery, routingDiscoveryCatchAll, routingDiscoveryConfirmed, routingDiscoveryIdentity, routingDiscoveryTime, visibleRoutingDiscoveries } from "./routingDiscoveriesModel";

const rule = (patch: Partial<AwgZone> = {}): AwgZone => ({
  name: "Video", tunnel_id: "germany", route: "tunnel", domains: ["example.com"],
  include_subdomains: true, ips: [], source_ips: ["192.168.1.10"], enabled: true, ...patch,
});
const entry = (patch: Partial<AwgRoutingLearnedEntry> = {}): AwgRoutingLearnedEntry => ({
  domain: "cdn.example.com", ips: ["203.0.113.1", "2001:db8::1"], source_ips: ["192.168.1.10"], source: "dns",
  first_seen: 1_792_000_000, last_seen: 1_792_000_100, additional: true, confirmed: true, ...patch,
});
const snapshot = (patch: Partial<AwgRoutingDiscoveries> = {}): AwgRoutingDiscoveries => ({
  revision: 10, active: true, ready: true, domain_source: "dnsproxy", limit: 512,
  rules: [{ rule_index: 0, rule_key: "saved-rule", rule: rule(), entries: [entry(), entry({ domain: "example.com", additional: false })] }], ...patch,
});

test("discovery identity ignores name, order and enabled state but preserves legacy subdomain semantics", () => {
  const value = snapshot();
  const renamed = rule({ name: "Renamed", order: 100, enabled: false });
  assert.equal(matchingRoutingDiscovery(value, renamed, 0), value.rules[0]);
  assert.equal(routingDiscoveryIdentity(rule({ route: undefined, mode: "include" })), routingDiscoveryIdentity(rule()));
  assert.notEqual(routingDiscoveryIdentity(rule({ include_subdomains: undefined })), routingDiscoveryIdentity(rule()));
  assert.equal(matchingRoutingDiscovery(value, rule({ include_subdomains: undefined }), 0), null);
});

test("edited matches, route, sources and tunnel identity cannot acquire another rule's observations", () => {
  const value = snapshot();
  const changes: Partial<AwgZone>[] = [
    { domains: ["other.example"] }, { include_subdomains: false }, { ips: ["192.0.2.0/24"] },
    { source_ips: [] }, { tunnel_id: "another" }, { route: "direct" },
    { fallback_tunnel_ids: ["backup"] }, { waiting_for_connection: true },
  ];
  for (const patch of changes) assert.equal(matchingRoutingDiscovery(value, rule(patch), 0), null, JSON.stringify(patch));
  assert.equal(matchingRoutingDiscovery(value, rule(), 1), null, "a rule moved to another index must wait for the next saved snapshot");
  assert.equal(matchingRoutingDiscovery(null, rule(), 0), null);
});

test("additional subdomains are the default view and filtering never mutates the snapshot", () => {
  const entries = [entry({ domain: "example.com", additional: false, last_seen: 30 }), entry({ domain: "old.example.com", last_seen: 10 }), entry({ domain: "new.example.com", last_seen: 20 })];
  const before = structuredClone(entries);
  assert.deepEqual(visibleRoutingDiscoveries(entries, false).map(item => item.domain), ["new.example.com", "old.example.com"]);
  assert.deepEqual(visibleRoutingDiscoveries(entries, true).map(item => item.domain), ["example.com", "new.example.com", "old.example.com"]);
  assert.deepEqual(entries, before);
});

test("history cannot be presented as an active confirmed route when routing is stopped or applying", () => {
  assert.equal(routingDiscoveryConfirmed(snapshot(), entry()), true);
  assert.equal(routingDiscoveryConfirmed(snapshot({ active: false }), entry()), false);
  assert.equal(routingDiscoveryConfirmed(snapshot({ ready: false }), entry()), false);
  assert.equal(routingDiscoveryConfirmed(snapshot(), entry({ confirmed: false })), false);
  assert.deepEqual(routingDiscoveryTime(0), { label: "—" });
  assert.deepEqual(routingDiscoveryTime(Number.NaN), { label: "—" });
  assert.equal(routingDiscoveryTime(1_792_000_100).dateTime, new Date(1_792_000_100_000).toISOString());
});

test("observed routes render as read-only additional records and never fill rule fields", () => {
  const html = renderToStaticMarkup(<RoutingDiscoveries rule={rule()} index={0} snapshot={snapshot()} loading={false} />);
  assert.match(html, /Обнаруженные маршруты \(1\)/);
  assert.match(html, /только чтение/);
  assert.match(html, /cdn\.example\.com/);
  assert.match(html, /203\.0\.113\.1/);
  assert.match(html, /2001:db8::1/);
  assert.match(html, /DNS · A\/AAAA/);
  assert.match(html, /Подтверждён/);
  assert.match(html, /Показать также исходные домены \(1\)/);
  assert.doesNotMatch(html, /<(?:input|textarea|select)\b/);
  assert.doesNotMatch(html, /Удалить|Скопировать|Добавить в/);
  const history = renderToStaticMarkup(<RoutingDiscoveries rule={rule()} index={0} snapshot={snapshot({ active: false })} loading={false} />);
  assert.match(history, />История</);
  assert.doesNotMatch(history, />Подтверждён</);
  const disabledDraft = renderToStaticMarkup(<RoutingDiscoveries rule={rule({ enabled: false })} index={0} snapshot={snapshot()} loading={false} />);
  assert.match(disabledDraft, />Подтверждён</);
  assert.match(disabledDraft, /Статусы относятся к последнему снимку роутера/);
});

test("mismatched snapshots remain hidden and untrusted observation text is escaped", () => {
  const changed = renderToStaticMarkup(<RoutingDiscoveries rule={rule({ domains: ["new.example"] })} index={0} snapshot={snapshot()} loading={false} />);
  assert.match(changed, /отличаются от снимка роутера/);
  assert.doesNotMatch(changed, /cdn\.example\.com|203\.0\.113\.1/);
  const value = snapshot();
  value.rules[0].entries = [entry({ domain: "<script>alert(1)</script>" })];
  const html = renderToStaticMarkup(<RoutingDiscoveries rule={rule()} index={0} snapshot={value} loading={false} />);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
});

test("catch-all rules explain why they do not need learned address routes", () => {
  for (const catchAll of [rule({ domains: ["*"] }), rule({ ips: ["0.0.0.0/0"] }), rule({ ips: ["::/0"] })]) {
    assert.equal(routingDiscoveryCatchAll(catchAll), true);
    const html = renderToStaticMarkup(<RoutingDiscoveries rule={catchAll} index={0} snapshot={snapshot({ rules: [] })} loading={false} />);
    assert.match(html, /Правило охватывает весь трафик/);
    assert.doesNotMatch(html, /Наблюдения появятся после сохранения|ещё не загружены|поддомены пока не обнаружены/);
  }
  assert.equal(routingDiscoveryCatchAll(rule({ domains: ["*.example.com", "*video*"] })), false);
});

test("reading observations only requests the snapshot endpoint and forwards cancellation", async t => {
  const original = globalThis.fetch;
  t.after(() => { globalThis.fetch = original; });
  const controller = new AbortController();
  const calls: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = (async (input, init) => {
    calls.push({ url: String(input), init });
    return new Response(JSON.stringify(snapshot()), { status: 200 });
  }) as typeof fetch;
  const result = await readRoutingDiscoveries(controller.signal);
  assert.equal(result.rules[0].entries[0].domain, "cdn.example.com");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/awg2/routing/discovered");
  assert.equal(calls[0].init?.method, "GET");
  assert.equal(calls[0].init?.body, undefined);
  assert.ok(calls[0].init?.signal, "the shared client must make the poll cancellable");
});

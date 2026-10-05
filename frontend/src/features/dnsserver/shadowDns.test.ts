import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { appendShadowDomains, collectShadow, collectShadowDomains, defaultShadowDomains, dnsRouteLabel, shadowForm, SHADOW_ROUTE_LABEL } from "./shadowDnsForm";
import { ShadowDns } from "./ShadowDns";
import { DnsStatistics } from "./DnsStatistics";
import { DnsTestAnswer } from "./DnsAnswerPresentation";
import { DnsLogRows } from "./DnsLogRows";
import { dnsSchedulerState } from "./dnsSchedulerState";
import type { DnsServerSchedulerSnapshot } from "@/types/api";

test("legacy Shadow config is disabled and defaults include Russia suffixes and the requested domains", () => {
  const legacy = shadowForm();
  assert.equal(legacy.enabled, false);
  assert.equal(legacy.patterns, "*.ru\n*.рф\n*.vk.*\n*.avito.*");
  assert.equal(defaultShadowDomains()[0].domain, "ru");
  assert.equal(shadowForm({ enabled: true, servers: [], domains: [] }).patterns, "");
});

test("bulk Shadow domains normalize IDNA, suffixes, separators and duplicate coverage without mutating input", () => {
  const existing = [{ domain: "VK.COM", include_subdomains: false }];
  const result = appendShadowDomains(existing, ".ru\n.РФ ; *.Vk.com, озон.рф. example.com", false);
  assert.deepEqual(result, [
    { domain: "vk.com", include_subdomains: true }, { domain: "ru", include_subdomains: true },
    { domain: "xn--p1ai", include_subdomains: true }, { domain: "xn--g1ambb.xn--p1ai", include_subdomains: false },
    { domain: "example.com", include_subdomains: false },
  ]);
  assert.deepEqual(existing, [{ domain: "VK.COM", include_subdomains: false }]);
  assert.deepEqual(appendShadowDomains([], "a.example a.example", true), [{ domain: "a.example", include_subdomains: true }]);
});

test("Shadow domains reject URLs, paths and invalid masks and bound the resulting unique rules", () => {
  for (const domain of ["", ".", "*.", "foo..com", "https://vk.com", "vk.com/path", "foo*bar.com", "**.foo.com", "foo@bar.com", "a%2eb.com", "x\\y.com", "a".repeat(64) + ".ru"]) {
    assert.throws(() => collectShadowDomains([{ domain, include_subdomains: false }]), /некорректный домен/);
  }
  assert.equal(collectShadowDomains(Array.from({ length: 4096 }, (_, i) => ({ domain: `d${i}.example`, include_subdomains: true }))).length, 4096);
  assert.throws(() => collectShadowDomains(Array.from({ length: 4097 }, (_, i) => ({ domain: `d${i}.example`, include_subdomains: true }))), /4096/);
});

test("Shadow settings migrate manual addresses to automatic discovery and preserve masks", () => {
  const manual = { enabled: true, servers: ["192.0.2.53:5353", "[2001:db8::53]:53"], domains: [{ domain: "vk.com", include_subdomains: false }] };
  const draft = shadowForm(manual);
  assert.deepEqual(collectShadow(draft), { ...manual, servers: [] });
  draft.patterns = "*.avito.*\n*.рф\n*.vk.*";
  assert.equal(manual.domains[0].domain, "vk.com");
  assert.deepEqual(collectShadow(draft), { enabled: true, servers: [], domains: [{ domain: "avito.*", include_subdomains: true }, { domain: "xn--p1ai", include_subdomains: true }, { domain: "vk.*", include_subdomains: true }] });
  assert.throws(() => collectShadow({ enabled: true, patterns: "" }), /хотя бы один/);
});

test("Shadow editor bounds rendered rule controls and distinguishes pending discovery from failure", () => {
  const value = { ...shadowForm(), patterns: Array.from({ length: 4096 }, (_, i) => `*.d${i}.example`).join("\n") };
  const pending = renderToStaticMarkup(createElement(ShadowDns, { value, status: { enabled: true, automatic: true, servers: [] }, onChange: () => {} }));
  assert.equal((pending.match(/<textarea/g) ?? []).length, 1);
  assert.equal((pending.match(/role="switch"/g) ?? []).length, 1);
  assert.equal(pending.includes("адреса вручную"), false);
  assert.ok(pending.includes("при первом запросе"));
  assert.ok(pending.includes("DNS провайдера имеет приоритет"));
  assert.ok(pending.includes("Если он недоступен, используются обычные DNS-маршруты сервера"));
  const failed = renderToStaticMarkup(createElement(ShadowDns, { value: shadowForm(), status: { enabled: true, automatic: true, servers: [], error: "DNS провайдера не найден" }, onChange: () => {} }));
  assert.ok(failed.includes("DNS провайдера не найден"));
  assert.equal(failed.includes("при первом запросе"), false);
});

test("Shadow labels are consistent in tests, logs, statistics and scheduler explanations", () => {
  assert.equal(dnsRouteLabel("shadow"), SHADOW_ROUTE_LABEL);
  assert.equal(dnsRouteLabel("awg:test", [{ id: "awg:test", name: "Мой VPN", interface: "awg0", available: true }]), "Мой VPN");
  const answer = renderToStaticMarkup(createElement(DnsTestAnswer, { result: { ok: true, domain: "vk.com", type: "A", route: "shadow", upstream: "192.0.2.53:53", answers: [], duration_ms: 2 }, routeName: dnsRouteLabel }));
  assert.ok(answer.includes(SHADOW_ROUTE_LABEL));
  const logs = renderToStaticMarkup(createElement(DnsLogRows, { entries: [{ id: 1, time: "2026-10-03T00:00:00Z", level: "info", event: "answer", domain: "vk.com", route: "shadow" }], routeName: dnsRouteLabel }));
  assert.ok(logs.includes(SHADOW_ROUTE_LABEL));
  const metrics = renderToStaticMarkup(createElement(DnsStatistics, { stats: { queries: 15, cache_hits: 10, nfqws_success: 0, awg_success: 1, shadow_success: 4, failures: 0 }, cache: { entries: 10, capacity: 512, ttl_seconds: 3600 } }));
  assert.match(metrics, /Shadow DNS<\/p><p[^>]*>4<\/p>/);
  const state = dnsSchedulerState({ enabled: false, effective: false, reason: "shadow", pool_source: "shadow", candidates: [] } as unknown as DnsServerSchedulerSnapshot);
  assert.equal(state.active, false);
  assert.match(state.message, /Shadow DNS/);
});

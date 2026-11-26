import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { DnsServerLogEntry, DnsServerStats, DnsServerTestResult } from "@/types/api";
import { DnsRequestOrigin, DnsRequestOriginDetails } from "./DnsRequestOrigin";
import { DNS_FORWARDER_NOTE } from "./dnsRequestSource";
import { DnsLastRequest, DnsTestAnswer } from "./DnsAnswerPresentation";
import { DnsLogRows } from "./DnsLogRows";
import { matchesLogFilter } from "./dnsLogPresentation";

const log = (patch: Partial<DnsServerLogEntry>): DnsServerLogEntry => ({
  id: 1, time: "2026-10-02T00:00:00Z", level: "info", event: "query", domain: "example.com", qtype: "A", ...patch,
});

test("a direct request identifies the observed device IP and incoming DNS transport", () => {
  const html = renderToStaticMarkup(createElement(DnsRequestOrigin, { source: "client", clientIP: "192.168.3.21", transport: "udp" }));
  assert.ok(html.includes("Устройство · Отправитель: 192.168.3.21 · UDP"));
  assert.equal(html.includes(DNS_FORWARDER_NOTE), false);
});

test("a local forwarder is labelled separately and never claims the original LAN device", () => {
  const html = renderToStaticMarkup(createElement(DnsRequestOriginDetails, { source: "local", clientIP: "192.168.3.1", transport: "tcp" }));
  assert.ok(html.includes("Источник DNS-запроса: Роутер / DNS-посредник"));
  assert.ok(html.includes("Наблюдаемый IP отправителя: 192.168.3.1"));
  assert.ok(html.includes("Входящий транспорт: TCP"));
  assert.ok(html.includes(DNS_FORWARDER_NOTE));
  assert.equal(html.includes("Источник DNS-запроса: Устройство"), false);
});

test("diagnostics and scheduler probes have distinct visible sources", () => {
  const result: DnsServerTestResult = { ok: true, domain: "example.com", type: "A", route: "nfqws", upstream: "https://1.1.1.1/dns-query", answers: [], duration_ms: 10, source: "diagnostic", transport: "api" };
  const html = renderToStaticMarkup(createElement(DnsTestAnswer, { result, routeName: (id: string) => id }));
  assert.ok(html.includes("Проверка в панели · API"));
  assert.equal(html.includes("Отправитель:"), false);
  const probe = renderToStaticMarkup(createElement(DnsLogRows, { entries: [log({ source: "probe", event: "attempt" })], routeName: (id: string) => id }));
  assert.ok(probe.includes("Фоновая проверка"));
  assert.equal(probe.includes("Источник DNS-запроса: Устройство"), false);
});

test("cache and shared deliveries preserve the current request's source without confusing it with the historical resolver", () => {
  for (const event of ["cache", "shared"]) {
    const html = renderToStaticMarkup(createElement(DnsLogRows, { entries: [log({ event, source: "client", client_ip: "192.168.3.42", transport: "udp", upstream: "https://cloudflare-dns.com/dns-query", route: "awg:warp" })], routeName: (id: string) => id }));
    const main = html.split("</summary>")[0];
    assert.ok(main.includes("Устройство · Отправитель: 192.168.3.42 · UDP"));
    assert.equal(main.includes("cloudflare-dns.com"), false);
    assert.ok(html.includes("Первичный источник"));
  }
});

test("last-request source uses delivery attribution and legacy missing fields do not invent a sender", () => {
  const stats: DnsServerStats = { queries: 1, cache_hits: 1, nfqws_success: 0, awg_success: 0, failures: 0, last_domain: "example.com", last_cached: true, last_source: "local", last_client_ip: "127.0.0.1", last_transport: "tcp" };
  const html = renderToStaticMarkup(createElement(DnsLastRequest, { stats, routeName: (id: string) => id }));
  assert.ok(html.includes("Из кэша"));
  assert.ok(html.includes("Роутер / DNS-посредник · Отправитель: 127.0.0.1 · TCP"));
  assert.equal(renderToStaticMarkup(createElement(DnsRequestOrigin, {})), "");
  assert.equal(renderToStaticMarkup(createElement(DnsRequestOriginDetails, {})), "");
});

test("log filters search both observed IPs and human-readable or raw source names", () => {
  const entry = log({ source: "local", client_ip: "192.168.3.1", transport: "tcp" });
  for (const query of ["192.168.3.1", "Роутер", "DNS-посредник", "local", "TCP"]) assert.equal(matchesLogFilter(entry, query), true);
  assert.equal(matchesLogFilter(entry, "192.168.3.99"), false);
  assert.equal(matchesLogFilter(entry, "diagnostic"), false);
});

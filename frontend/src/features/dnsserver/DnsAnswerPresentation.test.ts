import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { DnsServerLogEntry, DnsServerStats, DnsServerTestResult } from "@/types/api";
import { DNS_CACHE_NOTE, DNS_SHARED_NOTE, DnsLastRequest, DnsTestAnswer } from "./DnsAnswerPresentation";
import { DnsLogRows } from "./DnsLogRows";
import { DnsStatistics } from "./DnsStatistics";
import { matchesLogFilter } from "./dnsLogPresentation";

const provider = "https://cloudflare-dns.com/dns-query";
const routeName = (id: string) => id === "awg:warp" ? "Cloudflare WARP" : id || "—";
const answer = (patch: Partial<DnsServerTestResult> = {}): DnsServerTestResult => ({
  ok: true, domain: "example.com", type: "A", route: "awg:warp", upstream: provider,
  answers: ["A 203.0.113.10"], duration_ms: 1, ...patch,
});
const stats = (patch: Partial<DnsServerStats> = {}): DnsServerStats => ({
  queries: 10, cache_hits: 5, nfqws_success: 1, awg_success: 4, failures: 0,
  last_domain: "example.com", last_route: "awg:warp", last_upstream: provider, ...patch,
});
const log = (patch: Partial<DnsServerLogEntry> = {}): DnsServerLogEntry => ({
  id: 1, time: "2026-10-02T00:00:00Z", event: "cache", level: "info", domain: "example.com",
  qtype: "A", route: "awg:warp", upstream: provider, message: "Ответ из DNS-кэша", ...patch,
});
const logHTML = (entry: DnsServerLogEntry) => renderToStaticMarkup(createElement(DnsLogRows, { entries: [entry], routeName }));
const summary = (html: string) => html.match(/<summary[^>]*>([\s\S]*?)<\/summary>/)?.[1] || "";

test("a cached test answer labels cache explicitly and shows its original provider only inside details", () => {
  const html = renderToStaticMarkup(createElement(DnsTestAnswer, { result: answer({ cached: true }), routeName }));
  const main = html.split("<details")[0];
  assert.ok(main.includes("Из кэша"));
  assert.ok(main.includes(DNS_CACHE_NOTE));
  assert.equal(main.includes(provider), false);
  assert.equal(main.includes("Cloudflare WARP"), false);
  assert.ok(html.includes("Первичный источник"));
  assert.ok(html.includes("DNS-провайдер первичного запроса"));
  assert.ok(html.includes("Маршрут первичного запроса"));
  assert.ok(html.includes(provider));
  assert.ok(html.includes("A 203.0.113.10"));
});

test("a fresh test answer keeps the actual resolver and route visible without claiming a cache hit", () => {
  for (const cached of [false, undefined]) {
    const html = renderToStaticMarkup(createElement(DnsTestAnswer, { result: answer({ cached }), routeName }));
    assert.ok(html.includes("Ответ получен"));
    assert.ok(html.includes(provider));
    assert.ok(html.includes("Маршрут:"));
    assert.ok(html.includes("Cloudflare WARP"));
    assert.equal(html.includes(DNS_CACHE_NOTE), false);
    assert.equal(html.includes("Первичный источник"), false);
  }
});

test("blocked and failed test responses take precedence over an inconsistent cached flag", () => {
  const blocked = renderToStaticMarkup(createElement(DnsTestAnswer, { result: answer({ cached: true, shared: true, blocked: true }), routeName }));
  assert.ok(blocked.includes("Заблокировано локально"));
  assert.ok(blocked.includes("NXDOMAIN"));
  assert.equal(blocked.includes("Из кэша"), false);
  assert.equal(blocked.includes("Общий ответ"), false);
  assert.equal(blocked.includes(provider), false);
  const failed = renderToStaticMarkup(createElement(DnsTestAnswer, { result: answer({ ok: false, cached: true, shared: true, error: "AWG route apply failed" }), routeName }));
  assert.ok(failed.includes("Ошибка"));
  assert.ok(failed.includes("AWG route apply failed"));
  assert.equal(failed.includes("Из кэша"), false);
  assert.equal(failed.includes("Общий ответ"), false);
  assert.equal(failed.includes(DNS_CACHE_NOTE), false);
});

test("a shared test response identifies an in-flight answer rather than cache or a new provider request", () => {
  const html = renderToStaticMarkup(createElement(DnsTestAnswer, { result: answer({ cached: false, shared: true }), routeName }));
  const main = html.split("<details")[0];
  assert.ok(main.includes("Общий ответ"));
  assert.ok(main.includes(DNS_SHARED_NOTE));
  assert.equal(main.includes("Из кэша"), false);
  assert.equal(main.includes(provider), false);
  assert.equal(main.includes("Cloudflare WARP"), false);
  assert.equal(html.includes(DNS_CACHE_NOTE), false);
  assert.ok(html.includes("Первичный источник"));
  assert.ok(html.includes(provider));
});

test("last shared result preserves original source in details without displaying cache or a fresh route", () => {
  const html = renderToStaticMarkup(createElement(DnsLastRequest, { stats: stats({ last_cached: false, last_shared: true }), routeName }));
  const main = html.split("<details")[0];
  assert.ok(main.includes("Общий ответ"));
  assert.ok(main.includes(DNS_SHARED_NOTE));
  assert.equal(main.includes("Из кэша"), false);
  assert.equal(main.includes(provider), false);
  assert.equal(main.includes("Cloudflare WARP"), false);
  assert.ok(html.includes(provider));
});

test("shared log rows expose a searchable common-answer label and retain source metadata only in details", () => {
  const value = log({ event: "shared", message: "" });
  const html = logHTML(value);
  const main = summary(html);
  assert.ok(main.includes("Общий ответ"));
  assert.equal(main.includes("Из кэша"), false);
  assert.equal(main.includes("cloudflare-dns.com"), false);
  assert.equal(main.includes("Cloudflare WARP"), false);
  assert.ok(html.includes("Первичный источник:"));
  assert.ok(html.includes(DNS_SHARED_NOTE));
  assert.equal(matchesLogFilter(value, "Общий ответ"), true);
  assert.equal(matchesLogFilter(value, "⇄"), true);
  assert.equal(matchesLogFilter(value, "из кэша"), false);
});

test("statistics count shared responses separately from true cache hits and support older snapshots without the field", () => {
  const cache = { entries: 2, capacity: 128, ttl_seconds: 3600 };
  const html = renderToStaticMarkup(createElement(DnsStatistics, { stats: stats({ shared_responses: 7 }), cache }));
  assert.match(html, /Общий ответ<\/p><p[^>]*>7<\/p>/);
  assert.match(html, /Из кэша<\/p><p[^>]*>5<\/p>/);
  assert.ok(html.includes("50.0% запросов"));
  const legacy = renderToStaticMarkup(createElement(DnsStatistics, { stats: stats(), cache }));
  assert.match(legacy, /Общий ответ<\/p><p[^>]*>0<\/p>/);
});

test("last-request statistics distinguish a cache result from its historical route and provider", () => {
  const html = renderToStaticMarkup(createElement(DnsLastRequest, { stats: stats({ last_cached: true }), routeName }));
  const main = html.split("<details")[0];
  assert.ok(main.includes("Последний запрос:"));
  assert.ok(main.includes("Из кэша"));
  assert.ok(main.includes(DNS_CACHE_NOTE));
  assert.equal(main.includes(provider), false);
  assert.equal(main.includes("Cloudflare WARP"), false);
  assert.ok(html.includes(provider));
  const fresh = renderToStaticMarkup(createElement(DnsLastRequest, { stats: stats({ last_cached: false }), routeName }));
  assert.ok(fresh.includes(provider));
  assert.ok(fresh.includes("Cloudflare WARP"));
  assert.equal(fresh.includes(DNS_CACHE_NOTE), false);
});

test("cache log rows hide provider and VPN chips in their main line while retaining labeled origin details", () => {
  for (const event of ["cache", "cache_hit"]) {
    const html = logHTML(log({ event }));
    const main = summary(html);
    assert.ok(main.includes("Из кэша"));
    assert.ok(main.includes("example.com"));
    assert.equal(main.includes("cloudflare-dns.com"), false);
    assert.equal(main.includes("Cloudflare WARP"), false);
    assert.equal(main.includes("awg:warp"), false);
    assert.ok(html.includes("Первичный источник:"));
    assert.ok(html.includes("Маршрут первичного запроса:"));
    assert.ok(html.includes(provider));
    assert.ok(html.includes(DNS_CACHE_NOTE));
  }
});

test("real answer log rows still identify the fresh resolver and route in the main line", () => {
  const html = logHTML(log({ event: "answer", message: "Первый успешный ответ возвращён клиенту" }));
  const main = summary(html);
  assert.ok(main.includes("cloudflare-dns.com"));
  assert.ok(main.includes("Cloudflare WARP"));
  assert.equal(main.includes("Из кэша"), false);
  assert.equal(html.includes(DNS_CACHE_NOTE), false);
  assert.ok(html.includes("DNS-провайдер:"));
});

test("a legacy cache row without origin metadata never invents a provider or labels cache as its original route", () => {
  const html = logHTML(log({ route: "cache", upstream: "" }));
  assert.ok(summary(html).includes("Из кэша"));
  assert.ok(html.includes(DNS_CACHE_NOTE));
  assert.equal(html.includes("Первичный источник:"), false);
  assert.equal(html.includes("Маршрут первичного запроса:"), false);
  assert.equal(html.includes(provider), false);
});

test("cached answers without origin metadata still show cache, and empty last stats produce no synthetic request", () => {
  const html = renderToStaticMarkup(createElement(DnsTestAnswer, { result: answer({ cached: true, route: "", upstream: "" }), routeName }));
  assert.ok(html.includes("Из кэша"));
  assert.ok(html.includes(DNS_CACHE_NOTE));
  assert.equal(html.includes("Первичный источник"), false);
  assert.equal(renderToStaticMarkup(createElement(DnsLastRequest, { stats: stats({ last_domain: "" }), routeName })), "");
});

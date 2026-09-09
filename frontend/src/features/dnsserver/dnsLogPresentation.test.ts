import assert from "node:assert/strict";
import test from "node:test";
import type { DnsServerLogEntry } from "@/types/api";
import {
  cancellationChips, compactLogMessage, groupLogRows, isCancellation, isLogProblem, logCount,
  logEventPresentation, matchesLogFilter, shortProvider,
} from "./dnsLogPresentation";

const entry = (id: number, patch: Partial<DnsServerLogEntry> = {}): DnsServerLogEntry => ({
  id, time: `2026-09-09T12:00:${String(id).padStart(2, "0")}Z`,
  level: "debug", event: "canceled", domain: "claude.ai", qtype: "A", ...patch,
});
const flattenRows = (entries: DnsServerLogEntry[]) => groupLogRows(entries)
  .flatMap((row) => row.kind === "entry" ? [row.entry] : row.entries);

test("adjacent cancellation domains share a compact row without dropping duplicates or their order", () => {
  const values = [entry(1), entry(2, { domain: "grok.com" }), entry(3)];
  const original = structuredClone(values);
  const rows = groupLogRows(values);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, "cancellations");
  assert.deepEqual(flattenRows(values), values);
  assert.deepEqual(values, original, "preparing compact rows must not change the API snapshot");
});

test("repeated domain chips sum cancellations while keeping query counts, first appearance and A/AAAA separate", () => {
  const values = [
    entry(1, { domain: "claude.ai", qtype: "A", count: 8 }),
    entry(2, { domain: "grok.com", qtype: "A", count: 3 }),
    entry(3, { domain: "claude.ai", qtype: "AAAA", count: 4 }),
    entry(4, { domain: "claude.ai", qtype: "A", count: 5 }),
    entry(5, { domain: "grok.com", qtype: "A" }),
    entry(6, { domain: "claude.ai", qtype: "AAAA", count: 2 }),
  ];
  const original = structuredClone(values);
  assert.deepEqual(cancellationChips(values), [
    { domain: "claude.ai", qtype: "A", count: 13, queries: 2, firstTime: values[0].time, lastTime: values[3].time },
    { domain: "grok.com", qtype: "A", count: 4, queries: 2, firstTime: values[1].time, lastTime: values[4].time },
    { domain: "claude.ai", qtype: "AAAA", count: 6, queries: 2, firstTime: values[2].time, lastTime: values[5].time },
  ]);
  assert.deepEqual(values, original, "chips must leave original entries available for expanded details");
});

test("answers, cache hits and errors remain in place and split neighboring cancellation rows", () => {
  const values = [
    entry(1), entry(2),
    entry(3, { event: "answer", level: "info", route: "awg:warp" }),
    entry(4),
    entry(5, { event: "attempt_error", level: "warn", message: "TLS handshake timeout" }),
    entry(6),
    entry(7, { event: "cache", level: "info", route: "cache" }),
    entry(8),
  ];
  assert.deepEqual(groupLogRows(values).map((row) => row.kind), [
    "cancellations", "entry", "cancellations", "entry", "cancellations", "entry", "cancellations",
  ]);
  assert.deepEqual(flattenRows(values), values);
});

test("cancellations with real diagnostics or problem severity stay individually visible", () => {
  const values = [
    entry(1),
    entry(2, { message: "router route disappeared while request was active" }),
    entry(3),
    entry(4, { level: "warn", message: "request canceled after deadline" }),
    entry(5),
    entry(6, { level: "error" }),
    entry(7),
  ];
  const rows = groupLogRows(values);
  assert.equal(rows.length, values.length);
  assert.deepEqual(rows.filter((row) => row.kind === "entry").map((row) => row.entry.id), [2, 4, 6]);
  assert.deepEqual(flattenRows(values), values);
});

test("summarized cancellation counts and old one-at-a-time events retain their multiplicity", () => {
  const values = [entry(1, { count: 8 }), entry(2), entry(3, { count: 3 }), entry(4, { count: 0 })];
  const rows = groupLogRows(values);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, "cancellations");
  if (rows[0].kind !== "cancellations") throw new Error("expected cancellation summary");
  assert.equal(rows[0].entries.reduce((total, value) => total + logCount(value), 0), 13);
  assert.equal(logCount(entry(5, { count: 1 })), 1);
  for (const count of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.equal(logCount(entry(5, { count })), 1, "invalid summaries must not corrupt displayed totals");
  }
});

test("legacy cancellation event spellings are recognized without matching arbitrary event names", () => {
  for (const event of ["cancel", "canceled", "cancelled", "attempt_cancelled"]) {
    assert.equal(isCancellation(entry(1, { event })), true, event);
  }
  for (const event of ["attempt_error", "error", "cache", "answer", "cancel_configuration"]) {
    assert.equal(isCancellation(entry(1, { event })), false, event);
  }
});

test("only exact redundant cache and cancellation boilerplate is omitted", () => {
  const canceled = "Попытка отменена; штраф планировщика не начисляется";
  const cache = "Ответ из DNS-кэша";
  assert.equal(compactLogMessage(entry(1, { message: canceled })), "");
  assert.equal(compactLogMessage(entry(2, { event: "cache", level: "info", message: cache })), "");
  for (const message of [
    `${canceled}: соединение закрыто`,
    `${cache}: повреждённая запись`,
    "context canceled while contacting resolver",
    "lookup failed\nupstream refused connection",
  ]) {
    assert.equal(compactLogMessage(entry(3, { message })), message);
  }
  assert.equal(compactLogMessage(entry(4, { event: "config", level: "info", message: cache })), cache);
});

test("error and warning text is retained even when it resembles routine boilerplate", () => {
  for (const level of ["warn", "error"]) {
    const value = entry(1, { level, message: "Попытка отменена; штраф планировщика не начисляется" });
    assert.equal(isLogProblem(value), true);
    assert.equal(compactLogMessage(value), value.message);
  }
  for (const level of ["debug", "info"]) assert.equal(isLogProblem(entry(1, { level })), false);
  for (const event of ["error", "failure", "attempt_error"]) {
    const value = entry(1, { level: "info", event, message: "Попытка отменена; штраф планировщика не начисляется" });
    assert.equal(isLogProblem(value), true, "explicit error events must remain in the problems filter");
    assert.equal(compactLogMessage(value), value.message);
  }
});

test("compact event symbols carry readable labels and unknown events remain identifiable", () => {
  for (const event of ["answer", "cache", "canceled", "attempt_error", "error", "start", "stop", "logging", "cache_clear"]) {
    const presentation = logEventPresentation(entry(1, { event }));
    assert.ok(presentation.symbol.trim(), `${event} requires a symbol`);
    assert.ok([...presentation.symbol].length <= 3, `${event} symbol must stay compact`);
    assert.ok(presentation.label.trim(), `${event} requires a readable label`);
    assert.ok(presentation.tone, `${event} requires a visible style`);
  }
  assert.equal(logEventPresentation(entry(1, { event: "upstream_reconnected" })).label, "upstream_reconnected");
});

test("provider labels omit long URL paths and preserve an identifiable malformed address", () => {
  assert.equal(shortProvider("https://xbox-dns.ru/dns-query"), "xbox-dns.ru");
  assert.equal(shortProvider("https://dns.example/private-profile/dns-query?padding=123"), "dns.example");
  assert.equal(shortProvider("https://dns.example:8443/dns-query"), "dns.example:8443");
  assert.equal(shortProvider("https://[2001:db8::1]:8443/dns-query"), "[2001:db8::1]:8443");
  assert.equal(shortProvider("not a URL"), "not a URL");
  assert.equal(shortProvider(""), "");
});

test("search still reaches full URLs, messages, raw route IDs and visible route names", () => {
  const value = entry(1, {
    level: "warn", event: "attempt_error", domain: "claude.ai", qtype: "AAAA", route: "awg:adae5f163c11",
    upstream: "https://dns.example/custom-path/dns-query?profile=sample",
    message: "TLS handshake timeout\nupstream certificate rejected",
  });
  const routeName = (id: string) => id === "awg:adae5f163c11" ? "Cloudflare WARP" : id;
  for (const query of ["claude.AI", "AAAA", "adae5f163c11", "WARP", "cloudflare warp", "custom-path", "profile=sample", "HANDSHAKE timeout", "certificate rejected", "attempt_error", "Ошибка маршрута"]) {
    assert.equal(matchesLogFilter(value, query, routeName), true, query);
  }
  assert.equal(matchesLogFilter(value, "unrelated.example", routeName), false);
  assert.equal(matchesLogFilter(value, "", routeName), true);
  assert.equal(matchesLogFilter(value, "awg:adae5f163c11"), true, "route resolver is optional");
});

test("cache and cancellation searches accept clear labels and symbols as well as old raw messages", () => {
  const cancellation = entry(1, { message: "Попытка отменена; штраф планировщика не начисляется" });
  const cache = entry(2, { level: "info", event: "cache", message: "Ответ из DNS-кэша" });
  assert.equal(matchesLogFilter(cancellation, "⊘"), true);
  assert.equal(matchesLogFilter(cancellation, "отмена без штрафа"), true);
  assert.equal(matchesLogFilter(cancellation, "штраф планировщика"), true);
  assert.equal(matchesLogFilter(cache, "⚡"), true);
  assert.equal(matchesLogFilter(cache, "из кэша"), true);
  assert.equal(matchesLogFilter(cache, "DNS-кэша"), true);
});

test("filtering summarized cancellation rows retains matching domains and only their counts", () => {
  const values = [
    entry(1, { domain: "claude.ai", count: 8 }),
    entry(2, { domain: "grok.com", count: 5 }),
    entry(3, { domain: "claude.ai", qtype: "AAAA", count: 3 }),
  ];
  const selected = values.filter((value) => matchesLogFilter(value, "CLAUDE.AI"));
  const rows = groupLogRows(selected);
  assert.equal(rows.length, 1);
  assert.deepEqual(flattenRows(selected).map((value) => value.id), [1, 3]);
  assert.equal(flattenRows(selected).reduce((sum, value) => sum + logCount(value), 0), 11);
});

test("empty logs produce no synthetic console rows", () => {
  assert.deepEqual(groupLogRows([]), []);
});

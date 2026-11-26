import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { DnsCatalog, DnsSummary, visibleDnsServers } from "./presentation";
import type { DnsServer } from "@/types/api";

const servers: DnsServer[] = [
  { id: "custom-doh", name: "Personal HTTPS resolver", type: "doh", addr: `https://dns.example:8443/${"long-path/".repeat(25)}dns-query` },
  { id: "custom-dot", name: "Personal TLS resolver", type: "dot", addr: "[2001:db8::53]:8853" },
];

test("DNS protocol filters combine with case-insensitive identity and endpoint search without altering URLs or ports", () => {
  const original = structuredClone(servers);
  assert.deepEqual(visibleDnsServers(servers, " PERSONAL ", "doh"), [servers[0]]);
  assert.deepEqual(visibleDnsServers(servers, "2001:DB8", "dot"), [servers[1]]);
  assert.deepEqual(visibleDnsServers(servers, "8443", "dot"), []);
  assert.deepEqual(visibleDnsServers(servers, "CUSTOM-DOT", ""), [servers[1]]);
  assert.deepEqual(servers, original);
});

test("DNS rows retain complete names, IDs, protocols and addresses and lock delete during pending operations", () => {
  const html = renderToStaticMarkup(<DnsCatalog servers={servers} busy={null} filtered={false} onDelete={() => {}} />);
  for (const value of ["Personal HTTPS resolver", "Personal TLS resolver", "custom-doh", "custom-dot", "DOH", "DOT", servers[0].addr, servers[1].addr, "Удалить DNS"]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /14 ms|RTT OK|Синхронно|Тест резолвера/);
  const busy = renderToStaticMarkup(<DnsCatalog servers={servers} busy="delete:custom-dot" filtered={false} onDelete={() => {}} />);
  assert.equal((busy.match(/<button[^>]* disabled=/g) ?? []).length, 2);
  assert.match(busy, /Удаление…/);
});

test("DNS summaries use configured counts and empty filters stay distinct from an empty catalog", () => {
  const html = renderToStaticMarkup(<DnsSummary servers={servers} />);
  for (const value of ["DNS-серверов", ">2<", "DNS over HTTPS", "DNS over TLS", ">1<", "настроено для прогонов"]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /Готовы|По умолчанию|Синхронно/);
  const props = { servers: [], busy: null, onDelete: () => {} };
  assert.match(renderToStaticMarkup(<DnsCatalog {...props} filtered />), /под выбранный фильтр не найдены/);
  assert.match(renderToStaticMarkup(<DnsCatalog {...props} filtered={false} />), /Список пуст/);
});

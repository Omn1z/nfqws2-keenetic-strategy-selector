import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { Strategy } from "@/types/api";
import { filterStrategies, StrategyCatalog, strategyL7Options } from "./StrategyCatalog";

const strategies: Strategy[] = [
  { id: "builtin-tls", name: "Fake TLS", l7: "tls", args: "--filter-tcp=443 --lua-desync=fake:sni=www.example.com", source: "builtin" },
  { id: "custom-http", name: "Мой HTTP", l7: "http", args: "--filter-tcp=80 --payload=http_req", source: "custom" },
  { id: "custom-quic", name: "QUIC profile", l7: "QUIC", args: "--filter-udp=443 --payload=quic_initial", source: "custom" },
];
const all = { search: "", l7: "", source: "" };

test("strategy search matches real IDs, names, args and L7 without changing the catalog", () => {
  for (const [query, id] of [["  BUILTIN-TLS  ", "builtin-tls"], ["мой http", "custom-http"], ["SNI=WWW.EXAMPLE.COM", "builtin-tls"], ["QUIC", "custom-quic"]]) {
    assert.deepEqual(filterStrategies(strategies, { ...all, search: query }).map(strategy => strategy.id), [id]);
  }
  assert.deepEqual(filterStrategies(strategies, all), strategies);
  assert.equal(strategies.length, 3);
});

test("source, protocol and search filters combine and retain arbitrary real L7 values", () => {
  assert.deepEqual(filterStrategies(strategies, { search: "443", l7: "quic", source: "custom" }).map(strategy => strategy.id), ["custom-quic"]);
  assert.deepEqual(filterStrategies(strategies, { search: "", l7: "tls", source: "custom" }), []);
  assert.deepEqual(strategyL7Options([...strategies, { ...strategies[0], l7: " TLS " }, { ...strategies[0], l7: "" }]), ["http", "quic", "tls"]);
});

test("catalog keeps complete selectable arguments, all identity fields and custom-only actions", () => {
  const args = `--lua-desync=${"long-argument:".repeat(30)}END-OF-COMPLETE-ARGS`;
  const data = [{ ...strategies[0], args }, strategies[1]];
  const html = renderToStaticMarkup(<StrategyCatalog strategies={data} busy={null} filtered={false} onExport={() => {}} onEdit={() => {}} onDelete={() => {}} />);
  for (const value of ["builtin-tls", "Fake TLS", "tls", "builtin", "custom-http", "Мой HTTP", "http", "custom", "Показать аргументы", "Свернуть аргументы"]) assert.ok(html.includes(value), value);
  assert.ok(html.includes(`>${args}</pre>`), "expanded args retain the complete text beyond the preview");
  assert.equal((html.match(/<details/g) ?? []).length, 2);
  assert.equal((html.match(/Экспортировать /g) ?? []).length, 2);
  assert.equal((html.match(/>Изменить</g) ?? []).length, 1);
  assert.equal((html.match(/aria-label="Удалить стратегию /g) ?? []).length, 1);
});

test("catalog shows distinct empty states and prevents competing row actions while busy", () => {
  const props = { onExport: () => {}, onEdit: () => {}, onDelete: () => {} };
  const empty = renderToStaticMarkup(<StrategyCatalog {...props} strategies={[]} busy={null} filtered={false} />);
  const filtered = renderToStaticMarkup(<StrategyCatalog {...props} strategies={[]} busy={null} filtered />);
  assert.match(empty, /В каталоге пока нет стратегий/);
  assert.match(filtered, /По выбранным фильтрам стратегии не найдены/);
  const busy = renderToStaticMarkup(<StrategyCatalog {...props} strategies={strategies.slice(0, 2)} busy="delete:custom-http" filtered={false} />);
  assert.equal((busy.match(/<button[^>]* disabled=/g) ?? []).length, 4);
  assert.match(busy, /Удаление…/);
});

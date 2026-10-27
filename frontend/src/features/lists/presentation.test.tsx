import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { SavedListStrategyRow } from "./Lists";
import { entryCount, listSavePayload, ListsCatalog, ListsSummary, visibleLists } from "./presentation";
import type { List, SavedStrategy } from "@/types/api";

const saved: SavedStrategy = { strategy_id: "saved-strategy-id", name: "Working combination", args: `--lua-desync=${"full-argument:".repeat(35)}THE-END`, dns: "Resolver name", dns_id: "resolver-id", avg_ttfb_ms: 21, avg_speed_bps: 4096, coefficient: 37.4, found_at: 10, run_id: "run-id" };
const lists: List[] = [
  { id: "domain-list", name: "Example targets", domains: ["example.org", "", "   "], ips: [], base_strategy_ids: ["base-id"], successful_strategies: [saved], created_at: 1, updated_at: 2 },
  { id: "ip-list", name: "IPv6 targets", domains: [], ips: ["2001:db8::/32", "192.0.2.1"], created_at: 3, updated_at: 4 },
];

test("list catalog filters compose with search over names, IDs, domains and IPv6 without mutating saved data", () => {
  const original = structuredClone(lists);
  assert.deepEqual(visibleLists(lists, "  EXAMPLE.ORG  ", "domains").map(list => list.id), ["domain-list"]);
  assert.deepEqual(visibleLists(lists, "2001:DB8", "ips").map(list => list.id), ["ip-list"]);
  assert.deepEqual(visibleLists(lists, "ip-list", "strategies"), []);
  assert.deepEqual(visibleLists(lists, "", "strategies").map(list => list.id), ["domain-list"]);
  assert.deepEqual(lists, original);
  assert.equal(entryCount(null), 0);
  assert.equal(entryCount(lists[0].domains), 1);
});

test("editing a list preserves base strategy bindings and complete working results in the existing save payload", () => {
  const draft = { ...lists[0], name: "  Renamed list  ", domains: ["new.example", "", "  exact text  "] };
  assert.deepEqual(listSavePayload(draft), { id: "domain-list", name: "Renamed list", domains: draft.domains, ips: [], base_strategy_ids: ["base-id"], successful_strategies: [saved] });
  assert.equal(listSavePayload(draft).successful_strategies[0].args, saved.args);
  assert.deepEqual(listSavePayload(lists[1]).base_strategy_ids, []);
});

test("list catalog and summary expose actual identities, draft counts and explicit missing selection", () => {
  const html = renderToStaticMarkup(<ListsCatalog lists={lists} selectedId="domain-list" busy={null} filtered={false} onSelect={() => {}} onDelete={() => {}} />);
  for (const value of ["domain-list", "Example targets", "ip-list", "IPv6 targets", "1 дом. · 0 IP · 1 стратегий", "0 дом. · 2 IP · 0 стратегий", "Удалить список"]) assert.ok(html.includes(value), value);
  const summary = renderToStaticMarkup(<ListsSummary lists={lists} selected={lists[0]} />);
  for (const value of ["Доменов в редакторе", "IP / CIDR в редакторе", "Сохранённых стратегий", "из результатов прогонов", "Example targets"]) assert.ok(summary.includes(value), value);
  assert.match(renderToStaticMarkup(<ListsSummary lists={lists} selected={null} />), /Список не выбран/);
  assert.match(renderToStaticMarkup(<ListsCatalog lists={[]} busy={null} filtered onSelect={() => {}} onDelete={() => {}} />), /Списки под выбранный фильтр не найдены/);
});

test("saved list results retain measured values, full selectable args and explicit configuration and ZIP actions without requests on render", t => {
  const request = t.mock.method(globalThis, "fetch", () => { throw new Error("render must not mutate router state"); });
  const html = renderToStaticMarkup(<table><tbody><SavedListStrategyRow strategy={saved} disabled={false} onExport={() => {}} /></tbody></table>);
  for (const value of ["saved-strategy-id", "Working combination", "Resolver name", "21 мс", "4 КБ/с", ">37<", "Аргументы целиком", saved.args, "Применить", "ZIP ↓"]) assert.ok(html.includes(value), value);
  assert.equal(request.mock.callCount(), 0);
});

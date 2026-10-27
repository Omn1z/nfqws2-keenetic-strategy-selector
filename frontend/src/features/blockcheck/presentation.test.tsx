import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import BlockCheck, { BlockCheckResults, BlockCheckSummary } from "./BlockCheck";
import { blockCheckCounts, visibleBlockCheckTargets } from "./presentation";
import { StoreProvider } from "@/providers/StoreProvider";
import type { BlockCheck as Check, TargetCheck } from "@/types/api";

const target = (host: string, verdict: TargetCheck["verdict"], blocked = false): TargetCheck => ({ host, verdict, blocked, code: 200, size: 1024, ttfb_ms: 12, speed_bps: 2048 });
const targets: TargetCheck[] = [target("good.example", "ok"), target("reset.example", "reset", true), { ...target("local.example", "local_error", true), err: "socket resources <exhausted>" }, target("unknown.example", "error"), { ...target("dns.example", "dns", true), code: 451 }];
const check: Check = { id: "check-1", list_id: "list-1", list_name: "Own list", threads: 4, status: "done", total: 5, done: 5, targets };

test("BlockCheck totals never turn local or inconclusive errors into availability or a blocked provider", () => {
  assert.deepEqual(blockCheckCounts(targets), { blocked: 2, available: 1, localErrors: 1, undetermined: 2 });
  const html = renderToStaticMarkup(<BlockCheckSummary check={check} />);
  for (const value of ["Завершена", "5 / 5", "100% завершено", "Заблокировано", "Доступно напрямую", "Не определено", "Локальные ошибки: 1"]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /RST: 3|ISP DPI|всё доступно/);
  assert.match(renderToStaticMarkup(<BlockCheckSummary check={null} />), /Ожидание запуска/);
});

test("BlockCheck filters and search use existing results without mutating their order or misclassifying legacy local errors", () => {
  const original = targets.map(item => ({ ...item }));
  assert.deepEqual(visibleBlockCheckTargets(targets, "", "blocked").map(item => item.host), ["reset.example", "dns.example"]);
  assert.deepEqual(visibleBlockCheckTargets(targets, "", "ok").map(item => item.host), ["good.example"]);
  assert.deepEqual(visibleBlockCheckTargets(targets, " EXHAUSTED ", "local_error").map(item => item.host), ["local.example"]);
  assert.deepEqual(visibleBlockCheckTargets(targets, "451", "all").map(item => item.host), ["dns.example"]);
  assert.deepEqual(visibleBlockCheckTargets(targets, "missing", "all"), []);
  assert.deepEqual(targets, original);
});

test("BlockCheck results retain all measured fields, verdicts, error details and distinct empty states", () => {
  const props = { targets, query: "", filter: "all" as const, onQuery: () => {}, onFilter: () => {}, running: false, hasCheck: true };
  const html = renderToStaticMarkup(<BlockCheckResults {...props} />);
  for (const value of ["good.example", "reset.example", "local.example", "unknown.example", "dns.example", "12 мс", "2 КБ/с", "451", "socket resources &lt;exhausted&gt;", "локальная ошибка", "Поиск результатов BlockCheck", "Фильтр результатов BlockCheck"]) assert.ok(html.includes(value), value);
  assert.match(renderToStaticMarkup(<BlockCheckResults {...props} query="missing" />), /Нет целей под выбранный фильтр/);
  assert.match(renderToStaticMarkup(<BlockCheckResults {...props} targets={[]} running />), /Ожидаем первые результаты/);
  assert.match(renderToStaticMarkup(<BlockCheckResults {...props} targets={[]} hasCheck={false} />), /Запустите проверку/);
});

test("the initial BlockCheck screen remains a real source/configuration workflow and performs no requests on render", (t) => {
  const request = t.mock.method(globalThis, "fetch", () => { throw new Error("render must not start checks"); });
  const html = renderToStaticMarkup(<StoreProvider><BlockCheck /></StoreProvider>);
  for (const value of ["Проверить", "Параметры проверки", "Список", "GeoSite/GeoIP", "Текст", "Потоков", "Результаты проверки", "Запустите проверку."]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /В прогон|Симуляция|RAW TCP bypass/);
  assert.equal(request.mock.callCount(), 0);
});

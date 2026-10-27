import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import Runs, { RunLog, RunResultRow, RunSummary } from "./Runs";
import { StoreProvider } from "@/providers/StoreProvider";
import type { Run, StrategyResult } from "@/types/api";

const result: StrategyResult = { strategy_id: "strategy-1", name: "Working strategy", args: "--filter-tcp=443 --test=<value>", l7: "tls", dns: "Resolver test", dns_id: "resolver-1", targets_total: 2, targets_ok: 2, avg_ttfb_ms: 31, avg_speed_bps: 4096, coefficient: 40.8, success: true };
const run: Run = { id: "run-1", list_id: "list-1", list_name: "Own targets", threads: 2, auto: false, status: "done", total: 3, done: 3, started_at: 1, targets: ["one.example", "two.example"], results: [result, { ...result, strategy_id: "failed", success: false, coefficient: 999, targets_ok: 0, error: "Local setup failure" }, { ...result, strategy_id: "partial", success: false, targets_ok: 1 }] };

test("run KPIs use the actual run and successful coefficients rather than selections or reference values", () => {
  const html = renderToStaticMarkup(<RunSummary run={run} threads="8" />);
  for (const value of ["Завершён", "Own targets", ">2<", "3 / 3", "100% проверено", "Рабочих решений", ">1<", "С ошибкой: 1", "Лучший коэффициент", ">41<"]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, />999<|>94<|>8</);
  const empty = renderToStaticMarkup(<RunSummary run={null} threads="6" />);
  assert.match(empty, /Готов/); assert.match(empty, /Ожидание запуска/); assert.match(empty, />6</);
  for (const [status, label] of [["cancelled", "Отменён"], ["error", "Ошибка"], ["running", "В работе"]] as const) assert.ok(renderToStaticMarkup(<RunSummary run={{ ...run, status }} threads="4" />).includes(label));
});

test("run result rows preserve measured data, configuration/export actions and failed-result errors", (t) => {
  const request = t.mock.method(globalThis, "fetch", () => { throw new Error("render must not apply or export strategies"); });
  const html = renderToStaticMarkup(<table><tbody><RunResultRow result={result} /></tbody></table>);
  for (const value of ["Working strategy", "Resolver test", "2/2", "31 мс", "4 КБ/с", ">41<", "Применить", "Экспорт (ZIP)", "⤓ ZIP", "--test=&lt;value&gt;"]) assert.ok(html.includes(value), value);
  const failed = renderToStaticMarkup(<table><tbody><RunResultRow result={run.results[1]} /></tbody></table>);
  assert.match(failed, /Local setup failure/); assert.match(failed, /Экспорт \(ZIP\)/); assert.doesNotMatch(failed, /Применить/);
  assert.equal(request.mock.callCount(), 0);
});

test("the run log keeps chronological completions, errors and complete engine diagnostics", () => {
  const results = [result, { ...run.results[1], name: "Second check", engine_log: "engine <failure>\nsecond line" }];
  const html = renderToStaticMarkup(<RunLog results={results} status="error" done={2} total={3} />);
  assert.ok(html.indexOf("Working strategy") < html.indexOf("Second check"));
  for (const value of ["error", "2/3", "Local setup failure", "лог движка", "engine &lt;failure&gt;", "second line"]) assert.ok(html.includes(value), value);
  assert.match(renderToStaticMarkup(<RunLog results={[]} status="не запущен" done={0} total={0} />), /Лог появится по мере прогона/);
});

test("the initial runs screen exposes source modes, all selectors, search and a log without starting work", (t) => {
  const request = t.mock.method(globalThis, "fetch", () => { throw new Error("initial render must not start work"); });
  const html = renderToStaticMarkup(<StoreProvider><Runs /></StoreProvider>);
  for (const value of ["Запустить прогон", "Список", "GeoSite/GeoIP", "Текст", "Потоков", "Автоподбор", "Стратегии", "Фейк-пейлоад", "DNS", "Лог прогона", "Результаты прогона", "Поиск результатов прогона", "Фильтр результатов по успешным целям", "Запустите прогон."]) assert.ok(html.includes(value), value);
  assert.equal(request.mock.callCount(), 0);
});

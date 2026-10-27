import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { collect, toForm } from "./MtProto";
import { MtProtoContent, MtProtoStatistics, MtProtoSummary } from "./MtProtoPresentation";
import type { TgwsConfig, TgwsStatus } from "@/types/api";

function fixture(): TgwsStatus {
  const config: TgwsConfig = { enabled: true, port: 1433, secret: "f".repeat(32), dc_redirects: { "2": "192.0.2.2", "4": "192.0.2.4" }, buffer_size: 262144, pool_size: 0, proxy_protocol: true, force_test_dc: false, sni_fronting: true, disable_secure: false, cfproxy: true, cfproxy_h2_media: false, cfproxy_user_domain: "", cfproxy_worker_domain: "", cfproxy_user_domains: ["one.example", "two.example"], cfproxy_worker_domains: ["worker.example"], fake_tls_domain: "tls.example", link_host: "router.example" };
  return { upstream_version: "test-version", running: true, config, link: "tg://test-placeholder", stats: { connections: { total: 31, active: 2, ws: 13, tcp_fallback: 7, cfproxy: 11, h2: 4, fronting: 9, bad: 6, masked: 5 }, traffic: { bytes_up: 1024, bytes_down: 2048, human_up: "1.0 КБ", human_down: "2.0 КБ" }, ws: { errors: 8, pool_hits: 2, pool_misses: 3, cf_pool_hits: 4, cf_pool_misses: 6 }, h2: { tcp_connections: 12, requests: 17, replays: 18, errors: 19 }, started_at: 1 } };
}

test("MTProto presentation masks both sensitive fields by default and preserves the real connection/configuration workflow", (t) => {
  const request = t.mock.method(globalThis, "fetch", () => { throw new Error("presentation must not save, generate secrets or start a proxy"); });
  const live = fixture(); const form = { ...toForm(live.config), port: "5555" };
  let actions = 0;
  const html = renderToStaticMarkup(<MtProtoContent live={live} form={form} set={() => {}} onToggle={() => { actions++; }} onCopy={() => { actions++; }} onNewSecret={() => { actions++; }} onSave={() => { actions++; }} fallback={<aside>Shared Telegram DC route</aside>} />);
  const fields = html.match(/<input\b[^>]*>/g) ?? [];
  for (const label of ["tg:// ссылка", "Секрет MTProto"]) {
    const field = fields.find(item => item.includes(`aria-label="${label}"`));
    assert.ok(field, label); assert.match(field, /type="password"/); assert.match(field, /readOnly=""/);
  }
  for (const value of ["Показать ссылку", "Показать секрет", "Копировать", "Сгенерировать", "Сохранить настройки", "Прокси включён", "Shared Telegram DC route", "Порт прокси", "Fake-TLS домен", "Хост для ссылки", "Размер пула WS", "Буфер сокета", "DC-редиректы", "CF fallback", "HTTP/2 для медиа через CF", "PROXY protocol", "Резервный SNI", "CF без TLS (порт 80)", "Тестовые DC Telegram", "Свои CF-домены", "Домены CF Worker"]) assert.ok(html.includes(value), value);
  assert.ok(html.includes("Слушает порт 1433"));
  assert.doesNotMatch(html, /Слушает порт 5555/);
  assert.equal(actions, 0); assert.equal(request.mock.callCount(), 0);
});

test("MTProto metrics keep every connection, H2, pool, traffic and SNI counter", () => {
  const html = renderToStaticMarkup(<MtProtoStatistics live={fixture()} />);
  for (const value of ["Соединения", ">31<", "Активные", ">2<", "WS / TCP-fallback / CF", "13 / 7 / 11", "Медиа через HTTP/2 · TCP-соединения", "4 · 12", "HTTP/2 запросы / повторы / ошибки", "17 / 18 / 19", "Отклонено (плохой секрет) / маскировка", "6 / 5", "1.0 КБ / 2.0 КБ", "2/5 · 8", "Пул CF Worker (попаданий/всего)", "4/10", "Соединения через резервный SNI", ">9<"]) assert.ok(html.includes(value), value);
  const live = fixture(); live.stats.h2 = undefined; live.stats.connections.h2 = undefined;
  const legacy = renderToStaticMarkup(<MtProtoStatistics live={live} />);
  assert.match(legacy, /0 · 0/); assert.match(legacy, /0 \/ 0 \/ 0/); assert.doesNotMatch(legacy, /undefined|NaN/);
});

test("MTProto summary distinguishes the observed running process, failed listener and an explicitly stopped proxy", () => {
  const live = fixture();
  assert.match(renderToStaticMarkup(<MtProtoSummary live={live} />), /Работает/);
  const failed = renderToStaticMarkup(<MtProtoSummary live={{ ...live, running: false }} />);
  assert.match(failed, /Ошибка запуска/);
  const stopped = renderToStaticMarkup(<MtProtoSummary live={{ ...live, running: false, config: { ...live.config, enabled: false } }} />);
  assert.match(stopped, /Остановлена/); assert.doesNotMatch(stopped, /Ошибка запуска/);
});

test("grouped MTProto fields keep all existing form payload choices and domain-list representations", () => {
  const live = fixture(); const form = toForm(live.config); const body = collect(form);
  for (const field of ["port", "secret", "dc_redirects", "fake_tls_domain", "link_host", "pool_size", "buffer_size", "cfproxy", "cfproxy_h2_media", "proxy_protocol", "force_test_dc", "sni_fronting", "disable_secure", "cfproxy_user_domains", "cfproxy_worker_domains"] as const) assert.deepEqual(body[field], live.config[field], field);
  assert.equal(form.cfproxy_user_domain, "one.example\ntwo.example");
  assert.equal(form.cfproxy_worker_domain, "worker.example");
  assert.equal(body.pool_size, 0); assert.equal(body.cfproxy_h2_media, false);
});

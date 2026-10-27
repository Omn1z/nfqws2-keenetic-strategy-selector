import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { Dashboard as DashboardData } from "@/types/api";
import { ChannelsTable, DashboardOverview } from "./DashboardOverview";
import { Nfqws2Card } from "./Dashboard";
import { DnsStatistics } from "@/features/dnsserver/DnsStatistics";
import { fmtNum } from "@/lib/format";

function dashboard(): DashboardData {
  return {
    tgws: { running: true, stats: { connections: { active: 2, total: 40, ws: 20, tcp_fallback: 7, cfproxy: 13 }, traffic: { bytes_up: 100, bytes_down: 200, human_up: "100 Б", human_down: "200 Б" } } } as DashboardData["tgws"],
    socks5: { running: false, stats: { connections: { active: 0, total: 9, telegram: 8, direct: 1, bad: 0 }, traffic: { bytes_up: 30, bytes_down: 70, human_up: "30 Б", human_down: "70 Б" } } } as DashboardData["socks5"],
    dnsserver: { enabled: true, running: true, endpoint: "192.168.3.1:5355", stats: { queries: 1234, cache_hits: 25, shared_responses: 17, nfqws_success: 201, awg_success: 202, shadow_success: 203, failures: 204, blocked_total: 205, blocked_ads: 206, blocked_trackers: 207, blocked_mixed: 208 }, cache: { entries: 19, capacity: 256, ttl_seconds: 7200 } },
    awg: ["connected", "stale", "down", "off"].map((state, index) => ({ id: `vpn${index}`, label: `server-${state}`, endpoint: `192.0.2.${index + 1}:2408`, state, connected: index === 0, running: index < 2, last_handshake: index === 0 ? 1000 : 0, rx_bytes: 1024, tx_bytes: 2048, mtu: 1420 + index, address: `10.0.${index}.2/32` })),
    wan: [{ iface: "eth3", rx_bytes: 4096, tx_bytes: 8192, rx_packets: 101, tx_packets: 102 }, { iface: "ppp0", rx_bytes: 1024, tx_bytes: 2048, rx_packets: 103, tx_packets: 104 }],
    nfqws2_running: true, main_queue: 300, queues: [{ queue: 300, id_seq: 4500, queued: 3, queue_drop: 4, user_drop: 5, portid: 10, copy_mode: 0, copy_range: 0 }],
    conntrack: { count: 60, max: 10000 }, conns: { total: 60, failing: 6, by_proto: { tcp: 31, udp: 28, icmp: 1 } },
    trace_counters: { dns: 987, sni: 3, flow: 9, tunnel: 40, direct: 50, blocked: 6, cdn_skip: 7 },
    system: { cpu_percent: 35.2, load_avg: [0.12, 0.34, 0.56], mem_total_kb: 524288, mem_free_kb: 1024, mem_avail_kb: 32768, mem_used_kb: 491520, mem_apps_kb: 65536, mem_kernel_kb: 131072, mem_cache_kb: 196608, swap_total_kb: 65536, swap_free_kb: 32768, uptime_sec: 90060, temps: [{ label: "sensor-long-label-one", c: 62 }, { label: "sensor-two", c: 87 }], services: [{ name: "service-with-a-very-long-visible-process-name", pid: 5432, cpu_percent: 3.4, rss_kb: 8192, uptime_sec: 3660 }] },
    top_devices: [{ ip: "192.168.3.10", hostname: "computer-with-full-hostname", mac: "AA:BB:CC:DD:EE:FF", ipv6: ["2001:db8::10", "fe80::10"], iface: "br0", total: 14, established: 9, failing: 1, bytes_up: 1024, bytes_down: 2048, working: [], failing_dsts: [] }],
  };
}

function overview(data = dashboard()) {
  return <DashboardOverview d={data} rates={{ eth3: { rx: 1024, tx: 2048 }, ppp0: { rx: 2048, tx: 4096 } }} awgRates={{ vpn0: { rx: 512, tx: 256 } }} hist={[{ conns: 50, pps: 10, rx: 1024, tx: 2048 }, { conns: 60, pps: 20, rx: 2048, tx: 4096 }]} traceRates={{ dns: 12, sni: 13, tunnel: 14, direct: 15, blocked: 16, cdnSkip: 17 }} restart={<button>Перезапуск сервисов</button>} nfqws2={<Nfqws2Card running={data.nfqws2_running} queue={data.main_queue} queueStat={data.queues[0]} pps={20} history={[]} />} />;
}

test("the channel table retains every WAN and VPN row, rates, addresses and all four VPN states", (t) => {
  t.mock.method(Date, "now", () => 1030_000);
  const html = renderToStaticMarkup(<ChannelsTable d={dashboard()} rates={{ eth3: { rx: 0, tx: 512 } }} awgRates={{ vpn0: { rx: 1024, tx: 2048 } }} />);
  assert.equal((html.match(/scope="row"/g) ?? []).length, 6);
  for (const value of ["eth3", "ppp0", "server-connected", "server-stale", "server-down", "server-off", "подключён", "хендшейк устарел", "не в сети", "выключен", "192.0.2.4:2408", "10.0.3.2/32", "MTU 1423", "30 с назад", "101", "104"]) assert.ok(html.includes(value), value);
  assert.match(html, /↓ 1\.0 КБ\/с/);
  assert.doesNotMatch(html, /truncate|opacity-70|line-clamp/);
});

test("zero WAN throughput does not invent offline state or reference-only network properties", () => {
  const data = dashboard(); data.awg = []; data.wan = [data.wan[0]];
  const html = renderToStaticMarkup(<ChannelsTable d={data} rates={{ eth3: { rx: 0, tx: 0 } }} awgRates={{}} />);
  assert.match(html, /↓ 0 Б\/с/);
  assert.doesNotMatch(html, />Online<|>Offline<|>не в сети<|1 Gbit|1500|192\.168\.1\.1/);
  assert.match(html, /Нулевая скорость не означает обрыв/);
});

test("dashboard keeps real DNS totals separate from routing counters and preserves routing, proxies and DPI details", (t) => {
  const request = t.mock.method(globalThis, "fetch", () => { throw new Error("presentation must not change or fetch router state"); });
  const html = renderToStaticMarkup(overview());
  const kpis = html.match(/<section aria-label="Ключевые показатели"[^>]*>([\s\S]*?)<\/section>/)?.[1] ?? "";
  assert.match(kpis, new RegExp(`Запросы DNS<\\/p><(?:p|div)[^>]*>${fmtNum(1234)}<\\/(?:p|div)>`));
  assert.ok(!kpis.includes(`>${fmtNum(987)}<`), "DNS KPI must use DNS Server queries, not routing counters");
  for (const value of ["Перезапуск сервисов", "Настройки DNS", "TCP / UDP / ICMP", "31 / 28 / 1", "Не отвечают", "DNS / SNI", "12 / 13", "tunnel / direct", "14 / 15", "blocked / cdn-skip", "16 / 17", "Всего DNS / SNI", "987 / 3", "Всего обработано", "990", "TG WS Proxy", "SOCKS5", "20 / 7 / 13", "8 / 1", "30 Б / 70 Б", "В очереди сейчас", "Отброшено", "4 / 5", "Перезапуск службы", "Служба NFQWS2"]) assert.ok(html.includes(value), value);
  assert.equal(request.mock.callCount(), 0);
});

test("system and device rows expose all sensor, process, memory and address data without clipped identities", () => {
  const html = renderToStaticMarkup(overview());
  for (const value of ["Приложения · RSS", "64.0 MB", "Ядро · slab", "128.0 MB", "Кэш / буферы", "192.0 MB", "Доступно / всего RAM", "32.0 MB / 512.0 MB", "0.12 / 0.34 / 0.56", "Swap", "32.0 MB / 64.0 MB", "1д 1ч", "sensor-long-label-one", "sensor-two", "62°C", "87°C", "service-with-a-very-long-visible-process-name", "PID 5432", "3.4%", "8.0 MB", "1ч 1м", "computer-with-full-hostname", "2001:db8::10", "fe80::10", "AA:BB:CC:DD:EE:FF", "1.0 КБ", "2.0 КБ", "3.0 КБ"]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /truncate|line-clamp/);
});

test("missing channels, inactive DNS and queue, unavailable system data and empty devices remain explicit", () => {
  const data = dashboard(); data.awg = []; data.wan = []; data.queues = []; data.top_devices = []; data.system = undefined as unknown as DashboardData["system"];
  data.dnsserver.running = false; data.dnsserver.last_error = "DNS listener failed";
  const html = renderToStaticMarkup(overview(data));
  for (const value of ["Нет данных по WAN-интерфейсам", "ошибка запуска", "DNS listener failed", "Очередь 300 не активна", "Данные о ресурсах роутера недоступны", "Нет данных по LAN-устройствам", "Служба NFQWS2"]) assert.ok(html.includes(value), value);
});

test("DPI rates and connection charts remain visible when no WAN interface is reported", () => {
  const data = dashboard(); data.wan = [];
  const html = renderToStaticMarkup(overview(data));
  for (const value of ["Нет данных по WAN-интерфейсам.", "Соединения · история", "Очередь 300 · пакетов/с", ">20<", "Пакеты DPI · история"]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /↓ Приём|↑ Отправка/);
});

test("three DNS groups retain all counters, distinguish shared and cache hits and leave the DNS page layout intact", () => {
  const data = dashboard().dnsserver;
  const html = renderToStaticMarkup(<DnsStatistics stats={data.stats} cache={data.cache} variant="dashboard" />);
  for (const value of ["Запросы и кэш", "Маршрутизация DNS", "Реклама и трекеры", "Общий ответ", ">17<", "Из кэша", ">25<", "Через NFQWS", ">201<", "Через AWG", ">202<", "Shadow DNS", ">203<", "Ошибок", ">204<", ">205 ", ">206<", ">207<", ">208<", "19 / 256", `Хранение до ${fmtNum(7200)} сек.`, "mixed"]) assert.ok(html.includes(value), value);
  assert.match(html, /ожидание уже выполняющегося запроса, отдельно от попаданий в кэш/);
  const normal = renderToStaticMarkup(<DnsStatistics stats={data.stats} cache={data.cache} />);
  assert.ok(normal.includes("Общий ответ</p><p"));
  assert.ok(normal.includes("2.0% запросов"));
  assert.doesNotMatch(normal, /Запросы и кэш|Маршрутизация DNS/);
});

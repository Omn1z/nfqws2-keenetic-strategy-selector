import type { ReactNode } from "react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Sparkline } from "@/components/ui/Chart";
import { DnsStatistics } from "@/features/dnsserver/DnsStatistics";
import { fmtNum, human } from "@/lib/format";
import { navigate } from "@/lib/router";
import type { Dashboard as DashboardData } from "@/types/api";

export type Rate = { rx: number; tx: number };
export interface Sample { conns: number; pps: number; rx: number; tx: number; }
export type TraceRates = { dns: number; sni: number; tunnel: number; direct: number; blocked: number; cdnSkip: number };

export const DASH_CARD = "mb-0 min-w-0 p-4 sm:p-4 [&_[data-slot=card-header]]:mb-3 [&_[data-slot=card-title]]:text-sm [&_[data-slot=card-description]]:text-xs";

export function DashboardRow({ label, children }: { label: string; children: ReactNode }) {
  return <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 border-t border-line-soft py-1.5 text-xs first:border-t-0">
    <span className="text-ink-soft">{label}</span><span className="ml-auto text-right font-medium tabular-nums [overflow-wrap:anywhere]">{children}</span>
  </div>;
}

function Metric({ label, value, hint, className = "" }: { label: string; value: ReactNode; hint: ReactNode; className?: string }) {
  return <div className={`min-w-0 rounded-lg border border-line bg-panel px-3 py-2.5 ${className}`}>
    <p className="text-xs text-ink-soft">{label}</p>
    <p className="mt-1 text-lg font-semibold leading-tight tabular-nums sm:text-xl">{value}</p>
    <div className="mt-1 text-[11px] text-muted [overflow-wrap:anywhere]">{hint}</div>
  </div>;
}

const AWG_STATE: Record<string, { kind: "ok" | "warn" | "bad" | "neutral"; label: string }> = {
  connected: { kind: "ok", label: "подключён" },
  stale: { kind: "warn", label: "хендшейк устарел" },
  down: { kind: "bad", label: "не в сети" },
  off: { kind: "neutral", label: "выключен" },
};
const agoRu = (timestamp: number) => {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - timestamp);
  return seconds < 60 ? `${seconds} с назад` : seconds < 3600 ? `${Math.floor(seconds / 60)} мин назад` : `${Math.floor(seconds / 3600)} ч назад`;
};
const tableHead = "px-3 py-2 text-left text-[11px] font-medium text-muted first:pl-0 last:pr-0";
const tableCell = "px-3 py-2.5 align-top text-xs first:pl-0 last:pr-0";

export function ChannelsTable({ d, rates, awgRates }: { d: DashboardData; rates: Record<string, Rate>; awgRates: Record<string, Rate> }) {
  const wan = d.wan ?? [], awg = d.awg ?? [];
  return <Card title="Каналы и подключения" sub={`${wan.length} WAN · ${awg.length} VPN`} className={DASH_CARD}>
    {wan.length + awg.length === 0 ? <p className="text-xs text-muted">Нет данных по WAN-интерфейсам и VPN-подключениям.</p> : <div className="overflow-x-auto" role="region" aria-label="Все WAN и VPN подключения" tabIndex={0}>
      <table className="w-full min-w-[780px] border-collapse">
        <thead className="border-b border-line"><tr>{["Канал / интерфейс", "Состояние", "Endpoint / адрес", "Сейчас ↓ / ↑", "Хендшейк", "Всего ↓ / ↑"].map(label => <th key={label} scope="col" className={tableHead}>{label}</th>)}</tr></thead>
        <tbody className="divide-y divide-line-soft">
          {wan.map(iface => <tr key={`wan:${iface.iface}`}>
            <th scope="row" className={`${tableCell} min-w-[150px] text-left font-normal`}><b className="font-medium">WAN · {iface.iface}</b><p className="mt-1 text-[11px] text-muted">Сетевой интерфейс</p></th>
            <td className={tableCell}><Badge kind="neutral">счётчики доступны</Badge></td>
            <td className={`${tableCell} text-muted`}>—</td>
            <td className={`${tableCell} whitespace-nowrap tabular-nums`}><p>↓ {rates[iface.iface] ? `${human(rates[iface.iface].rx)}/с` : "…"}</p><p className="mt-1">↑ {rates[iface.iface] ? `${human(rates[iface.iface].tx)}/с` : "…"}</p></td>
            <td className={`${tableCell} text-muted`}>—</td>
            <td className={`${tableCell} whitespace-nowrap tabular-nums`}><p>↓ {human(iface.rx_bytes)}</p><p className="mt-1">↑ {human(iface.tx_bytes)}</p><p className="mt-1 text-[11px] text-muted">Пакеты ↓ {fmtNum(iface.rx_packets)} / ↑ {fmtNum(iface.tx_packets)}</p></td>
          </tr>)}
          {awg.map(connection => {
            const rate = awgRates[connection.id];
            const state = AWG_STATE[connection.state] ?? { kind: "neutral" as const, label: connection.state || "нет данных" };
            const speed = (direction: keyof Rate) => rate ? `${human(rate[direction])}/с` : connection.running ? "…" : `${human(0)}/с`;
            return <tr key={`vpn:${connection.id}`}>
              <th scope="row" className={`${tableCell} min-w-[150px] max-w-[240px] text-left font-normal [overflow-wrap:anywhere]`}><b className="font-medium">{connection.label || connection.id}</b><p className="mt-1 text-[11px] text-muted">VPN-туннель</p></th>
              <td className={tableCell}><Badge kind={state.kind}>{state.label}</Badge></td>
              <td className={`${tableCell} min-w-[180px] max-w-[260px] [overflow-wrap:anywhere]`}><p className="font-mono text-[11px]">{connection.endpoint || "—"}</p><p className="mt-1 text-[11px] text-ink-soft">{connection.address || "—"} · MTU {connection.mtu || "—"}</p></td>
              <td className={`${tableCell} whitespace-nowrap tabular-nums`}><p>↓ {speed("rx")}</p><p className="mt-1">↑ {speed("tx")}</p></td>
              <td className={`${tableCell} whitespace-nowrap tabular-nums`}>{connection.last_handshake ? agoRu(connection.last_handshake) : "—"}</td>
              <td className={`${tableCell} whitespace-nowrap tabular-nums`}><p>↓ {human(connection.rx_bytes)}</p><p className="mt-1">↑ {human(connection.tx_bytes)}</p></td>
            </tr>;
          })}
        </tbody>
      </table>
    </div>}
    <p className="mt-2 text-[11px] text-muted">Для WAN показаны счётчики трафика. Нулевая скорость не означает обрыв связи.</p>
  </Card>;
}

interface Props {
  d: DashboardData;
  rates: Record<string, Rate>;
  awgRates: Record<string, Rate>;
  hist: Sample[];
  traceRates: TraceRates | null;
  restart: ReactNode;
  nfqws2: ReactNode;
}

export function DashboardOverview({ d, rates, awgRates, hist, traceRates, restart, nfqws2 }: Props) {
  const awg = d.awg ?? [], wan = d.wan ?? [];
  const awgConnected = awg.filter(connection => connection.state === "connected").length;
  const wanRates = wan.flatMap(iface => rates[iface.iface] ? [rates[iface.iface]] : []);
  const wanRate = wanRates.length ? wanRates.reduce((sum, value) => ({ rx: sum.rx + value.rx, tx: sum.tx + value.tx }), { rx: 0, tx: 0 }) : null;
  const { connections: tgConnections, traffic: tgTraffic } = d.tgws.stats;
  const { connections: socksConnections, traffic: socksTraffic } = d.socks5.stats;
  const showTgws = d.tgws.running || tgConnections.total > 0 || tgTraffic.bytes_up > 0 || tgTraffic.bytes_down > 0;
  const showSocks5 = d.socks5.running || socksConnections.total > 0 || socksTraffic.bytes_up > 0 || socksTraffic.bytes_down > 0;
  const protocol = d.conns.by_proto ?? {};
  const trace = traceRates;
  const m = (value: number) => fmtNum(Math.round(value));
  const hitRatio = d.dnsserver.stats.queries > 0 ? Math.min(100, d.dnsserver.stats.cache_hits / d.dnsserver.stats.queries * 100) : 0;
  return <div className="dashboard-overview flex min-w-0 flex-col gap-4">
    <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="text-sm font-medium">Сводка</h2>{restart}</div>
    <section aria-label="Ключевые показатели" className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5">
      <Metric label="VPN-туннели" value={<>{awgConnected}<span className="text-sm font-normal text-muted"> / {awg.length}</span></>} hint="подключено / настроено" />
      <Metric label="WAN · суммарно" value={wanRate ? `${human(wanRate.rx)}/с ↓` : wan.length ? "…" : "—"} hint={wanRate ? `${human(wanRate.tx)}/с ↑ · ${wan.map(iface => iface.iface).join(", ")}` : wan.length ? "сбор скорости" : "нет данных"} />
      <Metric label="Обход DPI" value={d.nfqws2_running ? "Работает" : "Остановлен"} hint={`NFQWS2 · очередь ${d.main_queue}`} />
      <Metric label="Запросы DNS" value={fmtNum(d.dnsserver.stats.queries)} hint={`${hitRatio.toFixed(1)}% из кэша · с запуска`} />
      <Metric label="Соединения" value={fmtNum(d.conns.total)} hint={`из ${fmtNum(d.conntrack.max)} · не отвечают: ${fmtNum(d.conns.failing)}`} className="col-span-2 xl:col-span-1" />
    </section>

    <ChannelsTable d={d} rates={rates} awgRates={awgRates} />

    <section aria-label="Статистика DNS Server" className="min-w-0">
      <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-2">
        <h2 className="text-sm font-medium">Статистика DNS и фильтрация</h2><span className="text-xs text-muted [overflow-wrap:anywhere]">{d.dnsserver.endpoint || "локальный DNS"}</span>
        <div className="ml-auto flex flex-wrap items-center gap-2"><Badge kind={d.dnsserver.running ? "ok" : d.dnsserver.enabled ? "bad" : "neutral"}>{d.dnsserver.running ? "работает" : d.dnsserver.enabled ? "ошибка запуска" : "выключен"}</Badge><Button mini onClick={() => navigate("dnsserver")}>Настройки DNS</Button></div>
      </div>
      <DnsStatistics variant="dashboard" stats={d.dnsserver.stats} cache={d.dnsserver.cache} />
      {d.dnsserver.last_error && <p className="mt-2 text-xs text-bad [overflow-wrap:anywhere]">{d.dnsserver.last_error}</p>}
      {!d.dnsserver.last_error && d.dnsserver.stats.last_error && <p className="mt-2 text-xs text-bad [overflow-wrap:anywhere]">Последняя ошибка: {d.dnsserver.stats.last_error}</p>}
    </section>

    <div className="grid gap-3 lg:grid-cols-3">
      <Card title="Активные соединения" sub="conntrack" className={DASH_CARD}>
        <DashboardRow label="Сейчас / максимум">{fmtNum(d.conns.total)} / {fmtNum(d.conntrack.max)}</DashboardRow>
        <DashboardRow label="TCP / UDP / ICMP">{protocol.tcp ?? 0} / {protocol.udp ?? 0} / {protocol.icmp ?? 0}</DashboardRow>
        <DashboardRow label="Не отвечают"><span className={d.conns.failing ? "text-bad" : ""}>{fmtNum(d.conns.failing)}</span></DashboardRow>
        <div className="mt-3"><Sparkline data={hist.map(sample => sample.conns)} label="Соединения · история" value="" /></div>
      </Card>
      <Card title="Маршрутизация VPN" sub="DNS + SNI" className={DASH_CARD}>
        <p className="mb-2 text-xl font-semibold tabular-nums">{trace ? `${m(Math.round(trace.dns) + Math.round(trace.sni))}/мин` : "…"}</p>
        <DashboardRow label="DNS / SNI">{trace ? `${m(trace.dns)} / ${m(trace.sni)}` : "…"}</DashboardRow>
        <DashboardRow label="tunnel / direct">{trace ? `${m(trace.tunnel)} / ${m(trace.direct)}` : "…"}</DashboardRow>
        <DashboardRow label="blocked / cdn-skip"><span className={trace && trace.blocked > 0 ? "text-warn" : ""}>{trace ? `${m(trace.blocked)} / ${m(trace.cdnSkip)}` : "…"}</span></DashboardRow>
        <DashboardRow label="Всего DNS / SNI">{fmtNum(d.trace_counters.dns)} / {fmtNum(d.trace_counters.sni)}</DashboardRow>
        <DashboardRow label="Всего обработано">{fmtNum(d.trace_counters.dns + d.trace_counters.sni)}</DashboardRow>
      </Card>
      <Card title="Трафик WAN" sub="сумма интерфейсов" className={DASH_CARD}>
        {wan.length ? <><Sparkline data={hist.map(sample => sample.rx / 1024)} label="↓ Приём" value={wanRate ? `${human(wanRate.rx)}/с` : "…"} />
          <div className="mt-3"><Sparkline data={hist.map(sample => sample.tx / 1024)} label="↑ Отправка" value={wanRate ? `${human(wanRate.tx)}/с` : "…"} /></div>
          <p className="mt-2 text-[11px] text-muted">До 120 измерений с открытия страницы.</p></> : <p className="text-xs text-muted">Нет данных по WAN-интерфейсам.</p>}
      </Card>
    </div>

    <div className="grid items-start gap-4 xl:grid-cols-2">
      <section aria-label="Сервисы" className="flex min-w-0 flex-col gap-3">
        {nfqws2}
        {showTgws && <Card title="TG WS Proxy" sub="MTProto" head={<Badge kind={d.tgws.running ? "ok" : "neutral"}>{d.tgws.running ? "работает" : "стоп"}</Badge>} className={DASH_CARD}>
          <DashboardRow label="Активные / всего">{tgConnections.active} / {tgConnections.total}</DashboardRow>
          <DashboardRow label="WS / TCP / CF">{tgConnections.ws} / {tgConnections.tcp_fallback} / {tgConnections.cfproxy}</DashboardRow>
          <DashboardRow label="Трафик ↑ / ↓">{tgTraffic.human_up || "0 Б"} / {tgTraffic.human_down || "0 Б"}</DashboardRow>
        </Card>}
        {showSocks5 && <Card title="SOCKS5" sub="Telegram" head={<Badge kind={d.socks5.running ? "ok" : "neutral"}>{d.socks5.running ? "работает" : "стоп"}</Badge>} className={DASH_CARD}>
          <DashboardRow label="Активные / всего">{socksConnections.active} / {socksConnections.total}</DashboardRow>
          <DashboardRow label="Telegram / прямые">{socksConnections.telegram} / {socksConnections.direct}</DashboardRow>
          <DashboardRow label="Трафик ↑ / ↓">{socksTraffic.human_up || "0 Б"} / {socksTraffic.human_down || "0 Б"}</DashboardRow>
        </Card>}
      </section>
      <SystemPanel d={d} />
    </div>
    <DevicesPanel d={d} />
  </div>;
}

export function fmtUptime(seconds: number): string {
  if (!seconds || seconds < 0) return "—";
  const days = Math.floor(seconds / 86400), hours = Math.floor((seconds % 86400) / 3600), minutes = Math.floor((seconds % 3600) / 60);
  return days > 0 ? `${days}д ${hours}ч` : hours > 0 ? `${hours}ч ${minutes}м` : `${minutes}м`;
}
export function fmtKB(kb: number): string {
  return !kb ? "—" : kb < 1024 ? `${kb} KB` : kb < 1024 * 1024 ? `${(kb / 1024).toFixed(1)} MB` : `${(kb / 1024 / 1024).toFixed(2)} GB`;
}

function SystemPanel({ d }: { d: DashboardData }) {
  const system = d.system;
  if (!system) return <Card title="Система" className={DASH_CARD}><p className="text-xs text-muted">Данные о ресурсах роутера недоступны.</p></Card>;
  const total = system.mem_total_kb || 1;
  const apps = system.mem_apps_kb || 0, kernel = system.mem_kernel_kb || 0, cache = system.mem_cache_kb || 0;
  const appsPct = Math.round(apps / total * 100), kernelPct = Math.round(kernel / total * 100), cachePct = Math.round(cache / total * 100);
  const appsWidth = Math.max(0, Math.min(100, appsPct));
  const kernelWidth = Math.max(0, Math.min(100 - appsWidth, kernelPct));
  const cacheWidth = Math.max(0, Math.min(100 - appsWidth - kernelWidth, cachePct));
  const cpu = system.cpu_percent >= 0 ? Math.round(system.cpu_percent) : null;
  return <section aria-label="Система и процессы" className="flex min-w-0 flex-col gap-3">
    <Card title="Ресурсы роутера" sub={`Аптайм ${fmtUptime(system.uptime_sec)}`} className={DASH_CARD}>
      <DashboardRow label="CPU сейчас">{cpu === null ? "…" : `${cpu}%`}</DashboardRow>
      <div className="mb-3 h-1.5 overflow-hidden rounded-full bg-line-soft"><div className="h-full rounded-full bg-accent" style={{ width: `${cpu === null ? 0 : Math.max(0, Math.min(100, cpu))}%` }} /></div>
      <div className="mb-2 flex h-1.5 overflow-hidden rounded-full bg-line-soft" aria-label="Память: приложения, ядро и кэш">
        <span style={{ width: `${appsWidth}%`, background: "var(--c-accent)" }} /><span style={{ width: `${kernelWidth}%`, background: "var(--c-warn)" }} /><span style={{ width: `${cacheWidth}%`, background: "var(--c-muted)" }} />
      </div>
      <DashboardRow label="Приложения · RSS">{fmtKB(apps)} ({appsPct}%)</DashboardRow>
      <DashboardRow label="Ядро · slab">{fmtKB(kernel)} ({kernelPct}%)</DashboardRow>
      <DashboardRow label="Кэш / буферы">{fmtKB(cache)} ({cachePct}%)</DashboardRow>
      <DashboardRow label="Доступно / всего RAM">{fmtKB(system.mem_avail_kb)} / {fmtKB(system.mem_total_kb)}</DashboardRow>
      <DashboardRow label="Load · 1 / 5 / 15 мин">{system.load_avg.map(value => value.toFixed(2)).join(" / ")}</DashboardRow>
      {system.swap_total_kb > 0 && <DashboardRow label="Swap">{fmtKB(system.swap_total_kb - system.swap_free_kb)} / {fmtKB(system.swap_total_kb)}</DashboardRow>}
      <div className="mt-3 border-t border-line pt-3"><h3 className="mb-2 text-xs font-medium">Температура · все доступные сенсоры</h3>
        {system.temps?.length ? <div className="grid gap-x-5 gap-y-1.5 sm:grid-cols-2">{system.temps.map(temp => <div key={temp.label} className="flex items-baseline justify-between gap-2 text-xs"><span className="text-ink-soft [overflow-wrap:anywhere]">{temp.label}</span><span className={`shrink-0 tabular-nums ${temp.c >= 85 ? "text-bad" : temp.c >= 70 ? "text-warn" : ""}`}>{temp.c}°C</span></div>)}</div> : <p className="text-xs text-muted">Сенсоры температуры недоступны.</p>}
      </div>
    </Card>
    <Card title="Топ процессов" sub="RAM · CPU · аптайм" className={DASH_CARD}>
      <p className="mb-2 text-[11px] text-muted">100% CPU процесса = одно ядро; общий CPU усреднён по ядрам.</p>
      {system.services?.length ? <div className="overflow-x-auto" role="region" aria-label="Ресурсы процессов" tabIndex={0}><table className="w-full min-w-[390px] border-collapse">
        <thead className="border-b border-line"><tr>{["Процесс / PID", "CPU", "RAM", "Аптайм"].map(label => <th key={label} scope="col" className={tableHead}>{label}</th>)}</tr></thead>
        <tbody className="divide-y divide-line-soft">{system.services.map(service => <tr key={service.name + service.pid}>
          <th scope="row" className={`${tableCell} min-w-[125px] max-w-[220px] text-left font-normal [overflow-wrap:anywhere]`}><b className="font-medium">{service.name}</b><span className="ml-2 text-[11px] text-muted">PID {service.pid}</span></th>
          <td className={`${tableCell} whitespace-nowrap tabular-nums`}>{service.cpu_percent < 0 ? "…" : `${service.cpu_percent.toFixed(1)}%`}</td>
          <td className={`${tableCell} whitespace-nowrap tabular-nums`}>{fmtKB(service.rss_kb)}</td><td className={`${tableCell} whitespace-nowrap tabular-nums`}>{fmtUptime(service.uptime_sec)}</td>
        </tr>)}</tbody>
      </table></div> : <p className="text-xs text-muted">Нет данных по /proc.</p>}
    </Card>
  </section>;
}

function DevicesPanel({ d }: { d: DashboardData }) {
  const devices = d.top_devices ?? [];
  return <Card title="Устройства по трафику" sub="суммарно по conntrack" className={DASH_CARD}>
    {!devices.length ? <p className="text-xs text-muted">Нет данных по LAN-устройствам.</p> : <div className="overflow-x-auto" role="region" aria-label="Трафик LAN-устройств" tabIndex={0}><table className="w-full min-w-[650px] border-collapse">
      <thead className="border-b border-line"><tr>{["Устройство / адреса", "Соединения", "↑ Отправлено", "↓ Получено", "Всего"].map(label => <th key={label} scope="col" className={tableHead}>{label}</th>)}</tr></thead>
      <tbody className="divide-y divide-line-soft">{devices.map(device => <tr key={device.ip + device.mac}>
        <th scope="row" className={`${tableCell} min-w-[210px] max-w-[340px] text-left font-normal [overflow-wrap:anywhere]`}>
          {device.hostname && <b className="font-medium">{device.hostname}</b>}<p className="mt-0.5 font-mono text-[11px]">{device.ip}</p>
          {device.ipv6?.map(address => <p key={address} className="mt-0.5 font-mono text-[11px] text-ink-soft">{address}</p>)}
          {device.mac && <p className="mt-0.5 font-mono text-[11px] text-muted">{device.mac}{device.iface ? ` · ${device.iface}` : ""}</p>}
        </th>
        <td className={`${tableCell} tabular-nums`}>{device.total}</td><td className={`${tableCell} whitespace-nowrap tabular-nums`}>{human(device.bytes_up || 0)}</td><td className={`${tableCell} whitespace-nowrap tabular-nums`}>{human(device.bytes_down || 0)}</td><td className={`${tableCell} whitespace-nowrap font-medium tabular-nums`}>{human((device.bytes_up || 0) + (device.bytes_down || 0))}</td>
      </tr>)}</tbody>
    </table></div>}
    <p className="mt-2 text-[11px] text-muted">При аппаратном ускорении (HW-offload) счётчики conntrack могут отставать.</p>
  </Card>;
}

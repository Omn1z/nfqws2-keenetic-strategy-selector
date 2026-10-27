import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { connFailing, human } from "@/lib/format";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { PageHeader, StatsStrip, compactCard } from "@/components/ui/FeaturePage";
import { Skeleton } from "@/components/ui/Skeleton";
import { Switch } from "@/components/ui/Switch";
import { fieldCls } from "@/components/ui/form";
import { Pager, pageSlice } from "@/components/ui/Pager";
import { EmptyRow, SortTh, TableWrap, nextSort, tableCls, tdCls } from "@/components/ui/Table";
import type { Sort } from "@/components/ui/Table";
import type { Conn, Device } from "@/types/api";
import { connectionRows, connectionSummary, type ProtocolFilter } from "./connectionsView";

export default function Connections() {
  const [conns, setConns] = useState<Conn[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [err, setErr] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const refreshInFlight = useRef(false);
  const [filter, setFilter] = useState("");
  const [failOnly, setFailOnly] = useState(false);
  const [protocol, setProtocol] = useState<ProtocolFilter>("all");
  const [sort, setSort] = useState<Sort>({ key: "bytes", dir: -1 });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState("50");
  // ip → hostname map, built from /api/devices (covers v4 + every v6 from NDP).
  const [ipToHost, setIpToHost] = useState<Record<string, string>>({});
  useEffect(() => {
    const refresh = async () => {
      try {
        const v = await api<{ devices: Device[] }>("GET", "/api/devices");
        const map: Record<string, string> = {};
        for (const d of v.devices ?? []) {
          if (!d.hostname) continue;
          if (d.ip) map[d.ip] = d.hostname;
          for (const v6 of d.ipv6 ?? []) map[v6] = d.hostname;
        }
        setIpToHost(map);
      } catch { /* keep last */ }
    };
    void refresh();
    const t = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(t);
  }, []);

  const refresh = async (signal?: AbortSignal) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    setRefreshing(true);
    try {
      const value = await api<{ items: Conn[] }>("GET", "/api/connections", undefined, { signal });
      if (signal?.aborted) return;
      setConns(value.items ?? []); setLoaded(true); setErr("");
    } catch (error) {
      if (!signal?.aborted) setErr((error as Error).message);
    } finally {
      refreshInFlight.current = false;
      if (!signal?.aborted) setRefreshing(false);
    }
  };
  usePoll(refresh, 3000);

  const rows = connectionRows(conns, { query: filter, failOnly, protocol, sort, hosts: ipToHost });
  const summary = connectionSummary(conns);
  const onSort = (k: string) => setSort((s) => nextSort(s, k));

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader title="Соединения" description="Текущие сессии conntrack: состояние, назначения и объём трафика."
        actions={<Button mini onClick={() => { void refresh(); }} disabled={refreshing} aria-busy={refreshing}>↻ Обновить сейчас</Button>} />
      <StatsStrip label="Сводка соединений" items={[
        { label: "Всего соединений", value: loaded ? summary.total : "—", hint: "Текущая таблица conntrack" },
        { label: "Не отвечают", value: loaded ? summary.failing : "—", hint: "UNREPLIED / SYN_SENT", tone: summary.failing ? "bad" : "neutral" },
        { label: "Установлено", value: loaded ? summary.established : "—", hint: "ESTABLISHED", tone: "ok" },
        { label: "Протоколы", value: loaded ? `${summary.protocols.tcp} TCP` : "—", hint: loaded ? `UDP: ${summary.protocols.udp} · ICMP/v6: ${summary.protocols.icmp}${summary.protocols.other ? ` · другие: ${summary.protocols.other}` : ""}` : "TCP / UDP / ICMP" },
        { label: "Обновление", value: err ? "Ошибка" : "3 с", hint: err ? "Повторим автоматически" : "Пока открыта вкладка", tone: err ? "bad" : "neutral" },
      ]} />
    <Card className={compactCard} title="Таблица активных соединений"
      head={<span className="font-mono text-xs text-muted">{rows.length} из {conns.length}</span>}>
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <input
          type="search"
          aria-label="Поиск соединений"
          placeholder="Фильтр: IP, порт, протокол, состояние…"
          value={filter}
          onChange={(e) => { setFilter(e.target.value); setPage(1); }}
          className={cn(fieldCls, "min-w-0 flex-1 basis-full lg:basis-64")}
        />
        <div role="group" aria-label="Протокол соединения" className="inline-flex max-w-full flex-wrap items-center gap-0.5 rounded-md border border-line bg-line-soft p-0.5">
          {(["all", "tcp", "udp", "icmp"] as const).map(value => <Button key={value} mini variant="ghost" aria-pressed={protocol === value}
            className={protocol === value ? "bg-panel shadow-sm" : "text-muted"}
            onClick={() => { setProtocol(value); setPage(1); }}>{value === "all" ? "Все" : value.toUpperCase()}</Button>)}
        </div>
        <Switch checked={failOnly} onChange={(v) => { setFailOnly(v); setPage(1); }} label="только проблемные" />
      </div>
      {err && <p role="alert" className="mb-3 text-xs text-bad [overflow-wrap:anywhere]">Не удалось обновить соединения: {err}{loaded && " Показаны последние полученные данные."}</p>}
      <TableWrap scrollable>
        <table className={cn(tableCls, "min-w-[760px]")}>
          <thead>
            <tr>
              <SortTh label="Proto" k="proto" sort={sort} onSort={onSort} />
              <SortTh label="Состояние" k="state" sort={sort} onSort={onSort} />
              <SortTh label="Источник (LAN)" k="src" sort={sort} onSort={onSort} />
              <SortTh label="Назначение" k="dst" sort={sort} onSort={onSort} />
              <SortTh label="Порт" k="dport" sort={sort} onSort={onSort} />
              <SortTh label="Трафик" k="bytes" sort={sort} onSort={onSort} />
              <SortTh label="Зона" k="zone" sort={sort} onSort={onSort} />
            </tr>
          </thead>
          <tbody>
            {!loaded && !err && Array.from({ length: 6 }).map((_, i) => (
              <tr key={`sk${i}`}>{Array.from({ length: 7 }).map((_, j) => <td key={j} className={tdCls}><Skeleton className="h-3.5 w-16" /></td>)}</tr>
            ))}
            {!loaded && err && <EmptyRow colSpan={7}>Данные временно недоступны.</EmptyRow>}
            {loaded && rows.length === 0 && <EmptyRow colSpan={7}>{conns.length ? "Нет соединений, соответствующих фильтрам." : "Нет соединений."}</EmptyRow>}
            {loaded && pageSlice(rows, page, pageSize).map((c, i) => {
              const fail = connFailing(c);
              const label = c.state || (c.unreplied ? "нет ответа" : c.proto === "udp" ? "udp" : "—");
              const chip = fail ? "bg-bad-bg text-bad" : c.state === "ESTABLISHED" ? "bg-ok-bg text-ok" : "bg-line-soft text-ink-soft";
              return (
                <tr key={`${c.proto}|${c.src}|${c.sport}|${c.dst}|${c.dport}|${i}`} className="hover:bg-line-soft">
                  <td className={tdCls}>{c.proto}</td>
                  <td className={tdCls}><span className={cn("inline-block whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-semibold", chip)}>{label}</span></td>
                  <td className={cn(tdCls, "min-w-44 max-w-64 [overflow-wrap:anywhere]")}>
                    {ipToHost[c.src] && <b className="block text-ink">{ipToHost[c.src]}</b>}
                    <span className={cn("font-mono", ipToHost[c.src] && "text-[11px] text-muted")}>{c.src}</span>
                    {c.src.includes(":") && <span className="ml-1 text-[10px] text-muted">v6</span>}
                  </td>
                  <td className={cn(tdCls, "min-w-40 max-w-64 font-mono [overflow-wrap:anywhere]")}>{c.dst}</td>
                  <td className={cn(tdCls, "tabular-nums")}>{c.dport || "—"}</td>
                  <td className={cn(tdCls, "whitespace-nowrap tabular-nums")}>{human(c.bytes + c.reply_bytes)}</td>
                  <td className={tdCls}><span className="rounded border border-line bg-line-soft px-1.5 py-0.5 font-mono text-xs">{c.zone || "—"}</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableWrap>
      <div className="mt-3 border-t border-line pt-0.5"><Pager total={rows.length} page={page} setPage={setPage} pageSize={pageSize} setPageSize={setPageSize} /></div>
    </Card>
    </div>
  );
}

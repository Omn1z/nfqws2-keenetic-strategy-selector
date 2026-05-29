import { useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { connFailing, human } from "@/lib/format";
import { Card } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { Switch } from "@/components/ui/Switch";
import { fieldCls } from "@/components/ui/form";
import { Pager, pageSlice } from "@/components/ui/Pager";
import { EmptyRow, SortTh, TableWrap, nextSort, tableCls, tdCls } from "@/components/ui/Table";
import type { Sort } from "@/components/ui/Table";
import type { Conn } from "@/types/api";

const sortVal = (c: Conn, k: string): string | number => {
  switch (k) {
    case "proto": return c.proto;
    case "state": return c.state || (c.unreplied ? "UNREPLIED" : "");
    case "src": return c.src;
    case "dst": return c.dst;
    case "dport": return c.dport;
    case "bytes": return c.bytes + c.reply_bytes;
    case "zone": return c.zone;
    default: return 0;
  }
};

export default function Connections() {
  const [conns, setConns] = useState<Conn[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [filter, setFilter] = useState("");
  const [failOnly, setFailOnly] = useState(false);
  const [sort, setSort] = useState<Sort>({ key: "bytes", dir: -1 });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState("50");

  usePoll(async () => {
    try { const v = await api<{ items: Conn[] }>("GET", "/api/connections"); setConns(v.items ?? []); setLoaded(true); } catch { /* keep last */ }
  }, 3000);

  const f = filter.toLowerCase().trim();
  const rows = conns
    .filter((c) => {
      if (failOnly && !connFailing(c)) return false;
      if (!f) return true;
      return [c.proto, c.state, c.src, c.dst, String(c.dport || ""), c.zone].some((x) => x.toLowerCase().includes(f));
    })
    .sort((a, b) => {
      const va = sortVal(a, sort.key), vb = sortVal(b, sort.key);
      return va < vb ? -sort.dir : va > vb ? sort.dir : 0;
    });
  const failTotal = conns.filter(connFailing).length;
  const onSort = (k: string) => setSort((s) => nextSort(s, k));

  return (
    <Card
      title="Активные соединения"
      sub="обновляется, пока открыта вкладка"
      head={<span className="text-xs text-muted">{rows.length} из {conns.length} · не отвечают {failTotal}</span>}
    >
      <div className="mb-3 flex flex-wrap items-center gap-3.5">
        <input
          type="search"
          placeholder="Фильтр: IP, порт, протокол, состояние…"
          value={filter}
          onChange={(e) => { setFilter(e.target.value); setPage(1); }}
          className={cn(fieldCls, "min-w-[220px] flex-1")}
        />
        <Switch checked={failOnly} onChange={(v) => { setFailOnly(v); setPage(1); }} label="только проблемные" />
      </div>
      <TableWrap scrollable>
        <table className={tableCls}>
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
            {!loaded && Array.from({ length: 6 }).map((_, i) => (
              <tr key={`sk${i}`}>{Array.from({ length: 7 }).map((_, j) => <td key={j} className={tdCls}><Skeleton className="h-3.5 w-16" /></td>)}</tr>
            ))}
            {loaded && rows.length === 0 && <EmptyRow colSpan={7}>Нет соединений.</EmptyRow>}
            {loaded && pageSlice(rows, page, pageSize).map((c, i) => {
              const fail = connFailing(c);
              const label = c.state || (c.unreplied ? "нет ответа" : c.proto === "udp" ? "udp" : "—");
              const chip = fail ? "bg-bad-bg text-bad" : c.state === "ESTABLISHED" ? "bg-ok-bg text-ok" : "bg-line-soft text-ink-soft";
              return (
                <tr key={`${c.proto}|${c.src}|${c.sport}|${c.dst}|${c.dport}|${i}`} className="hover:bg-line-soft">
                  <td className={tdCls}>{c.proto}</td>
                  <td className={tdCls}><span className={cn("inline-block whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-semibold", chip)}>{label}</span></td>
                  <td className={cn(tdCls, "font-mono")}>{c.src}</td>
                  <td className={cn(tdCls, "font-mono")}>{c.dst}</td>
                  <td className={cn(tdCls, "tabular-nums")}>{c.dport || "—"}</td>
                  <td className={cn(tdCls, "whitespace-nowrap tabular-nums")}>{human(c.bytes + c.reply_bytes)}</td>
                  <td className={tdCls}>{c.zone}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableWrap>
      <Pager total={rows.length} page={page} setPage={setPage} pageSize={pageSize} setPageSize={setPageSize} />
    </Card>
  );
}

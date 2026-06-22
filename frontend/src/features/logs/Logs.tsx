import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/form";
import { confirmDialog } from "@/components/ui/Confirm";
import type { LogEntry } from "@/types/api";

/** Pi-hole-styled selector log viewer. Same vocabulary as the AWG2 trace panel:
 *  Live update toggle, Refresh, sortable columns, paginated, column-footer filters,
 *  level-coloured badge per row. The data source is /api/logs (existing ring buffer). */

type SortKey = "t" | "module" | "level" | "msg";
type SortDir = "asc" | "desc";
const PAGE_SIZES = [10, 25, 50, 100, 250];

const pad = (n: number, w = 2) => String(n).padStart(w, "0");
const fmtTime = (ms: number) => {
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
};

const LEVEL: Record<string, { k: "ok" | "warn" | "bad" | "neutral"; icon: string }> = {
  error: { k: "bad",     icon: "✕" },
  warn:  { k: "warn",    icon: "⚠" },
  info:  { k: "neutral", icon: "ℹ" },
  debug: { k: "neutral", icon: "·" },
};

const sortGlyph = (key: SortKey, k: SortKey, d: SortDir) => (k === key ? (d === "asc" ? " ▲" : " ▼") : " ⇅");

export default function Logs() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [modules, setModules] = useState<string[]>([]);
  const [moduleFilter, setModuleFilter] = useState("all");
  const [levelFilter, setLevelFilter] = useState<"all" | "error" | "warn" | "info" | "debug">("all");
  const [msgFilter, setMsgFilter] = useState("");
  const [live, setLive] = useState(true);
  const [pageSize, setPageSize] = useState(50);
  const [page, setPage] = useState(1);
  const [sortKey, setSortKey] = useState<SortKey>("t");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const lastFetchRef = useRef<number>(0);

  const fetchOnce = async () => {
    try {
      const r = await api<{ entries: LogEntry[]; modules: string[] }>("GET", "/api/logs?limit=1000");
      setEntries(r.entries ?? []);
      setModules(r.modules ?? []);
      lastFetchRef.current = Date.now();
    } catch { /* keep last */ }
  };

  useEffect(() => { void fetchOnce(); }, []);
  useEffect(() => {
    if (!live) return;
    const id = window.setInterval(() => { void fetchOnce(); }, 2000);
    return () => window.clearInterval(id);
  }, [live]);

  const onClear = async () => {
    if (!(await confirmDialog({ title: "Очистить все логи?" }))) return;
    try {
      await api("POST", "/api/logs/clear", {});
      setEntries([]);
      setPage(1);
      toast("Логи очищены", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  const onSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir(key === "t" ? "desc" : "asc"); }
  };

  const filtered = useMemo(() => {
    const m = msgFilter.trim().toLowerCase();
    return entries.filter((e) => {
      if (moduleFilter !== "all" && e.module !== moduleFilter) return false;
      if (levelFilter !== "all" && e.level !== levelFilter) return false;
      if (m && !e.msg.toLowerCase().includes(m) && !e.module.toLowerCase().includes(m)) return false;
      return true;
    });
  }, [entries, moduleFilter, levelFilter, msgFilter]);

  const sorted = useMemo(() => {
    const cmp = (a: LogEntry, b: LogEntry): number => {
      switch (sortKey) {
        case "t":      return a.t - b.t;
        case "module": return a.module.localeCompare(b.module);
        case "level":  return a.level.localeCompare(b.level);
        case "msg":    return a.msg.localeCompare(b.msg);
      }
    };
    const arr = filtered.slice().sort(cmp);
    return sortDir === "asc" ? arr : arr.reverse();
  }, [filtered, sortKey, sortDir]);

  const total = sorted.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  useEffect(() => { if (page > pages) setPage(pages); }, [page, pages]);
  const pageStart = (page - 1) * pageSize;
  const pageEnd = Math.min(pageStart + pageSize, total);
  const slice = sorted.slice(pageStart, pageEnd);

  return (
    <Card>
      {/* Header: title + Live + Refresh */}
      <div className="flex flex-wrap items-center gap-3 border-b border-line pb-3">
        <h2 className="text-[15px] font-semibold">Логи селектора</h2>
        <div className="text-xs text-muted">{entries.length} записей в кольце</div>
        <div className="ml-auto flex items-center gap-3">
          <label className="flex cursor-pointer select-none items-center gap-1.5 text-[12px]">
            <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} className="h-3.5 w-3.5 cursor-pointer accent-accent" />
            Live update
          </label>
          <Button mini variant="primary" onClick={() => void fetchOnce()}>Refresh</Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3 py-3">
        <Button mini variant="ghost" onClick={onClear}>Очистить</Button>
        <span className="ml-2 text-[12px] text-muted">Модуль:</span>
        <select value={moduleFilter} onChange={(e) => { setModuleFilter(e.target.value); setPage(1); }} className="h-7 rounded border border-line bg-panel px-2 text-[12px]">
          <option value="all">все</option>
          {modules.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <span className="ml-2 text-[12px] text-muted">Уровень:</span>
        <select value={levelFilter} onChange={(e) => { setLevelFilter(e.target.value as typeof levelFilter); setPage(1); }} className="h-7 rounded border border-line bg-panel px-2 text-[12px]">
          <option value="all">все</option>
          <option value="error">error</option>
          <option value="warn">warn</option>
          <option value="info">info</option>
          <option value="debug">debug</option>
        </select>
        <span className="ml-auto text-[12px] text-muted">
          Show
          <select value={pageSize} onChange={(e) => { setPageSize(parseInt(e.target.value, 10)); setPage(1); }} className="mx-1 h-7 rounded border border-line bg-panel px-1 text-[12px]">
            {PAGE_SIZES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          entries
        </span>
      </div>

      <div className="overflow-x-auto rounded border border-line">
        <table className="w-full text-[11px] md:text-[12px]">
          <thead className="bg-panel-soft text-[10px] uppercase text-muted md:text-[11px]">
            <tr>
              <Th onClick={() => onSort("t")}>Время{sortGlyph("t", sortKey, sortDir)}</Th>
              <Th onClick={() => onSort("level")} className="w-[44px] text-center">●</Th>
              <Th onClick={() => onSort("module")} className="hidden md:table-cell">Модуль{sortGlyph("module", sortKey, sortDir)}</Th>
              <Th onClick={() => onSort("level")} className="hidden lg:table-cell">Уровень{sortGlyph("level", sortKey, sortDir)}</Th>
              <Th onClick={() => onSort("msg")}>Сообщение{sortGlyph("msg", sortKey, sortDir)}</Th>
            </tr>
          </thead>
          <tbody>
            {slice.length === 0 && (
              <tr>
                <td colSpan={5} className="px-2 py-6 text-center text-muted">
                  {entries.length === 0 ? "Пусто." : "Ничего не подходит под фильтр."}
                </td>
              </tr>
            )}
            {slice.map((e, i) => {
              const lv = LEVEL[e.level] ?? LEVEL.info;
              return (
                <tr key={`${e.t}-${i}`} className={cn("border-t border-line", i % 2 ? "bg-panel-soft/40" : "")}>
                  <td className="whitespace-nowrap px-2 py-1 font-mono">{fmtTime(e.t)}</td>
                  <td className="px-2 py-1 text-center">
                    <span className={cn(
                      "inline-flex h-5 w-5 items-center justify-center rounded-full text-[11px]",
                      lv.k === "ok"      && "bg-good-bg text-good",
                      lv.k === "neutral" && "bg-panel-soft text-ink-soft",
                      lv.k === "bad"     && "bg-bad-bg text-bad",
                      lv.k === "warn"    && "bg-warn-bg text-warn",
                    )} title={e.level}>{lv.icon}</span>
                  </td>
                  <td className="hidden whitespace-nowrap px-2 py-1 font-mono md:table-cell">{e.module}</td>
                  <td className="hidden whitespace-nowrap px-2 py-1 lg:table-cell"><Badge kind={lv.k}>{e.level}</Badge></td>
                  <td className="px-2 py-1 font-mono [overflow-wrap:anywhere]">{e.msg}</td>
                </tr>
              );
            })}
          </tbody>
          <tfoot className="bg-panel-soft">
            <tr>
              <td className="px-2 py-1 text-[11px] uppercase text-muted">Время</td>
              <td className="px-2 py-1" />
              <td className="px-2 py-1 text-[11px] uppercase text-muted">{moduleFilter === "all" ? "все" : moduleFilter}</td>
              <td className="px-2 py-1 text-[11px] uppercase text-muted">{levelFilter === "all" ? "все" : levelFilter}</td>
              <td className="px-2 py-1">
                <Input value={msgFilter} onChange={(e) => { setMsgFilter(e.target.value); setPage(1); }} placeholder="поиск по сообщению / модулю" className="h-7 text-[12px]" />
              </td>
            </tr>
          </tfoot>
        </table>
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[12px] text-muted">
        <div>{total === 0 ? "Showing 0" : `Showing ${pageStart + 1} to ${pageEnd} of ${total}`}</div>
        <div className="flex items-center gap-1">
          <Button mini variant="ghost" onClick={() => setPage(1)} disabled={page <= 1}>«</Button>
          <Button mini variant="ghost" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>‹</Button>
          <span className="px-2 tabular-nums">{page} / {pages}</span>
          <Button mini variant="ghost" onClick={() => setPage((p) => Math.min(pages, p + 1))} disabled={page >= pages}>›</Button>
          <Button mini variant="ghost" onClick={() => setPage(pages)} disabled={page >= pages}>»</Button>
        </div>
      </div>

      <p className="mt-3 text-[11px] text-muted">
        Логи TG WS Proxy — модуль <code>tgws</code>. Per-device трассировки — модуль <code>trace</code>.
        Запись логов глобально регулируется в Система → «Логирование».
      </p>
    </Card>
  );
}

function Th({ children, onClick, className }: { children: React.ReactNode; onClick?: () => void; className?: string }) {
  return (
    <th
      onClick={onClick}
      className={cn("select-none px-2 py-1.5 text-left font-semibold", onClick && "cursor-pointer hover:text-ink", className)}
    >
      {children}
    </th>
  );
}

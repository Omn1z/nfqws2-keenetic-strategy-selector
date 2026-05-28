import { useEffect, useRef, useState } from "react";
import { api, exportStrategy } from "@/lib/api";
import { cn } from "@/lib/cn";
import { kb } from "@/lib/format";
import { applyStrategyToConfig } from "@/lib/actions";
import { usePoll } from "@/lib/hooks";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { Badge, DnsBadge, VerdictBadge } from "@/components/ui/Badge";
import { Checklist } from "@/components/ui/Checklist";
import { Field, Input, Select } from "@/components/ui/form";
import { Pager, pageSlice } from "@/components/ui/Pager";
import { Args, EmptyRow, SortTh, TableWrap, nextSort, tableCls, tdCls, thBase } from "@/components/ui/Table";
import type { Sort } from "@/components/ui/Table";
import { SourceSelector } from "@/components/SourceSelector";
import type { SourceSelectorHandle } from "@/components/SourceSelector";
import type { Run, RunRequest, StrategyResult, TargetSource } from "@/types/api";

const sortVal = (r: StrategyResult, k: string): string | number => {
  switch (k) {
    case "status": return r.error ? 0 : r.success ? 2 : 1;
    case "name": return (r.name || "").toLowerCase();
    case "dns": return (r.dns ?? "").toLowerCase();
    case "targets": return r.targets_ok;
    case "latency": return r.avg_ttfb_ms || 1e12;
    case "speed": return r.avg_speed_bps;
    case "coef": return r.coefficient;
    default: return 0;
  }
};
const ratio = (r: StrategyResult) => (r.targets_total ? r.targets_ok / r.targets_total : 0);
const FILTERS: Record<string, (r: StrategyResult) => boolean> = {
  all: () => true,
  one: (r) => r.targets_ok > 0,
  "50": (r) => ratio(r) >= 0.5,
  "75": (r) => ratio(r) >= 0.75,
  "100": (r) => r.targets_total > 0 && r.targets_ok === r.targets_total,
};

export default function Runs() {
  const { lists, geo, strategies, blobs, dns, reloadLists, pendingTargets, setPendingTargets } = useStore();
  const srcRef = useRef<SourceSelectorHandle>(null);
  const [initialText] = useState(() => pendingTargets?.join("\n") ?? "");
  useEffect(() => { if (pendingTargets) setPendingTargets(null); /* consume hand-off once */ }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const [threads, setThreads] = useState("4");
  const [auto, setAuto] = useState(false);
  const [stratSel, setStratSel] = useState<string[]>([]);
  const [blobSel, setBlobSel] = useState<string[]>([]);
  const [dnsSel, setDnsSel] = useState<string[]>([]);
  const [run, setRun] = useState<Run | null>(null);
  const [running, setRunning] = useState(false);
  const [sort, setSort] = useState<Sort>({ key: "coef", dir: -1 });
  const [filterMode, setFilterMode] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState("20");

  const stratItems = strategies.map((s) => ({ value: s.id, label: s.name || s.id, sub: s.l7 || "?" }));
  const blobItems = [...blobs.custom.map((n) => ({ value: n, label: n, sub: "свой" })), ...blobs.system.map((n) => ({ value: n, label: n }))];
  const dnsItems = [{ value: "system", label: "Системный", sub: "без DoH/DoT" }, ...dns.map((d) => ({ value: d.id, label: d.name || d.id, sub: d.type.toUpperCase() }))];

  usePoll(async () => {
    if (!run) return;
    try {
      const r = await api<Run>("GET", `/api/runs/${run.id}`);
      setRun(r);
      if (r.status !== "running") {
        setRunning(false);
        void reloadLists();
        const ok = r.results.filter((x) => x.success).length;
        if (r.status === "cancelled") toast("Прогон отменён", "ok");
        else if (r.auto && r.total === 0) toast("Цели доступны без обхода — обходить нечего", "ok");
        else toast(`Прогон завершён: найдено рабочих ${ok}`, "ok");
      }
    } catch (e) { setRunning(false); toast((e as Error).message, "err"); }
  }, 1000, running);

  const start = async () => {
    if (!srcRef.current) return;
    let target: TargetSource;
    try { target = await srcRef.current.resolve(); } catch (e) { toast((e as Error).message, "err"); return; }
    const req: RunRequest = { ...target, strategy_ids: auto ? [] : stratSel, blobs: blobSel, dns: dnsSel, auto, threads: parseInt(threads, 10) || 4 };
    try { const r = await api<Run>("POST", "/api/runs", req); setRun(r); setPage(1); setRunning(true); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const cancel = async () => { setRunning(false); if (run) { try { await api("POST", `/api/runs/${run.id}/cancel`); } catch { /* already stopping */ } } };
  const addThread = async () => {
    if (!run) return;
    const next = (run.threads || 1) + 1;
    if (next > 8) { toast("Максимум 8 потоков", "err"); return; }
    try { const d = await api<{ threads: number }>("POST", `/api/runs/${run.id}/threads`, { threads: next }); toast(`Потоков: ${d.threads}`, "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
  };

  const results = run?.results ?? [];
  const sorted = results.filter(FILTERS[filterMode]).sort((a, b) => { const va = sortVal(a, sort.key), vb = sortVal(b, sort.key); return va < vb ? -sort.dir : va > vb ? sort.dir : 0; });
  const onSort = (k: string) => setSort((s) => nextSort(s, k, k === "latency" ? 1 : -1));
  const found = results.filter((x) => x.success).length;
  const errored = results.filter((x) => x.error).length;
  const pct = run?.total ? Math.round((run.done * 100) / run.total) : 0;
  const base = (run?.auto && run.baseline) || [];

  return (
    <>
      <Card title="Прогон стратегий" sub="подбор рабочих стратегий обхода">
        <SourceSelector ref={srcRef} lists={lists} geo={geo} initialText={initialText} />
        <div className="mb-1.5 flex flex-wrap items-end gap-4">
          <Field label="Потоков" className="w-28 shrink-0"><Input type="number" min={1} max={8} value={threads} onChange={(e) => setThreads(e.target.value)} /></Field>
          <div className="mb-3"><div className="mb-1.5 text-[13px] font-medium text-ink-soft">Автоподбор</div><Switch checked={auto} onChange={setAuto} /></div>
        </div>
        <div className="flex flex-wrap items-start gap-4">
          <Checklist title="Стратегии" hint="пусто = все" items={stratItems} value={stratSel} onChange={setStratSel} disabled={auto} />
          <Checklist title="Фейк-пейлоад (blob)" hint="по умолч. tls_clienthello" items={blobItems} value={blobSel} onChange={setBlobSel} />
          <Checklist title="DNS" hint="каждый DNS — отдельный прогон" items={dnsItems} value={dnsSel} onChange={setDnsSel} />
        </div>
        <p className="mt-2 text-xs text-muted">Выбранный блоб подставляется в стратегии как фейковый пейлоад (<code>blob=</code>), каждый — отдельным прогоном; без выбора используется <code>tls_clienthello</code>. <code>--payload=tls_client_hello</code> в аргументах — это L7-фильтр (на какие пакеты влиять), а не сам пейлоад.</p>
        {auto && <p className="mt-2 text-xs text-muted">Автоподбор сам перебирает встроенный каталог кандидатов — выбор стратегий не используется.</p>}
        <div className="mt-3 flex flex-wrap items-center gap-2.5">
          <Button variant="primary" onClick={start} disabled={running}>▶ Запустить прогон</Button>
          {running && <Button variant="danger" onClick={cancel}>■ Отменить</Button>}
          {running && <Button mini onClick={addThread} disabled={(run?.threads ?? 0) >= 8}>+ поток</Button>}
          {run && <span className="text-xs text-muted">{run.status}</span>}
        </div>
        {running && run && (
          <div className="mt-2">
            <div className="h-2 overflow-hidden rounded-full bg-line"><div className="h-full rounded-full bg-gradient-to-r from-accent to-[#5cb3ff] transition-[width]" style={{ width: `${pct}%` }} /></div>
            <span className="text-xs text-muted">{run.done}/{run.total} стратегий · {run.threads} потоков · найдено {found} · с ошибкой {errored} · {run.status}</span>
          </div>
        )}
      </Card>

      <Card
        title="Результаты прогона"
        sub="клик по заголовку — сортировка"
        head={
          <Select value={filterMode} onChange={(e) => { setFilterMode(e.target.value); setPage(1); }} className="w-auto">
            <option value="all">Все</option>
            <option value="one">≥1 цель пройдена</option>
            <option value="50">≥50% целей</option>
            <option value="75">≥75% целей</option>
            <option value="100">100% целей</option>
          </Select>
        }
      >
        {base.length > 0 && (
          <div className="mb-3 rounded-[10px] border border-line bg-line-soft p-3 text-[12.5px] text-ink-soft">
            <b className="text-ink">Базовый замер без обхода:</b> заблокировано {base.filter((b) => b.blocked).length} из {base.length}.{" "}
            {base.filter((b) => b.blocked).length === 0 ? "Обходить нечего — всё доступно." : "Автоподбор тестируется только на заблокированных целях."}
            <div className="mt-1.5 flex flex-wrap gap-2">{base.map((b, i) => <span key={i}>{b.host} <VerdictBadge v={b.verdict} /></span>)}</div>
          </div>
        )}
        <TableWrap scrollable>
          <table className={tableCls}>
            <thead><tr>
              <SortTh label="Статус" k="status" sort={sort} onSort={onSort} />
              <SortTh label="Стратегия" k="name" sort={sort} onSort={onSort} />
              <SortTh label="DNS" k="dns" sort={sort} onSort={onSort} />
              <SortTh label="Цели" k="targets" sort={sort} onSort={onSort} />
              <SortTh label="Задержка" k="latency" sort={sort} onSort={onSort} />
              <SortTh label="Скорость" k="speed" sort={sort} onSort={onSort} />
              <SortTh label="Коэф." k="coef" sort={sort} onSort={onSort} />
              <th className={thBase} />
            </tr></thead>
            <tbody>
              {sorted.length === 0 && <EmptyRow colSpan={8}>{results.length ? "Нет результатов под фильтр." : "Запустите прогон."}</EmptyRow>}
              {pageSlice(sorted, page, pageSize).map((r, i) => (
                <tr key={(r.strategy_id || "") + (r.dns_id || "") + i} className="hover:bg-line-soft">
                  <td className={tdCls}>{r.error ? <Badge kind="bad">ошибка</Badge> : r.success ? <Badge kind="ok">OK</Badge> : <Badge kind="bad">нет</Badge>}</td>
                  <td className={tdCls}>{r.name || r.strategy_id}<Args>{r.args}</Args></td>
                  <td className={tdCls}><DnsBadge name={r.dns} id={r.dns_id} /></td>
                  <td className={cn(tdCls, "tabular-nums")}>{r.targets_ok}/{r.targets_total}</td>
                  <td className={cn(tdCls, "tabular-nums")}>{r.avg_ttfb_ms ? `${r.avg_ttfb_ms} мс` : "—"}</td>
                  <td className={cn(tdCls, "tabular-nums")}>{r.avg_speed_bps ? `${kb(r.avg_speed_bps)} КБ/с` : "—"}</td>
                  <td className={cn(tdCls, "tabular-nums")}>{r.coefficient ? Math.round(r.coefficient) : "—"}</td>
                  <td className={cn(tdCls, "flex flex-wrap gap-1.5")}>
                    {r.success && <Button mini onClick={() => applyStrategyToConfig(r.args)}>Применить</Button>}
                    <Button mini title="Экспорт (ZIP)" onClick={() => exportStrategy(r.name || r.strategy_id, r.l7 || "", r.args).catch((e) => toast((e as Error).message, "err"))}>⤓</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
        <Pager total={sorted.length} page={page} setPage={setPage} pageSize={pageSize} setPageSize={setPageSize} />
      </Card>
    </>
  );
}

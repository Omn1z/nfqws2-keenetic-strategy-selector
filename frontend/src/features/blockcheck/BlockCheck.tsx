import { useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { kb } from "@/lib/format";
import { usePoll } from "@/lib/hooks";
import { summarizeTargetChecks } from "@/lib/targetChecks";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { VerdictBadge } from "@/components/ui/Badge";
import { Field, Input, Select } from "@/components/ui/form";
import { PageHeader, StatsStrip, compactCard } from "@/components/ui/FeaturePage";
import { Args, EmptyRow, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import { SourceSelector } from "@/components/SourceSelector";
import type { SourceSelectorHandle } from "@/components/SourceSelector";
import type { BlockCheck as BC, TargetCheck, TargetSource } from "@/types/api";
import { blockCheckCounts, visibleBlockCheckTargets, type CheckFilter } from "./presentation";

export function BlockCheckSummary({ check }: { check: BC | null }) {
  const counts = blockCheckCounts(check?.targets ?? []);
  const status = { running: "В работе", done: "Завершена", cancelled: "Отменена", error: "Ошибка" };
  return <StatsStrip label="Сводка проверки" items={[
    { label: "Статус проверки", value: check ? status[check.status] : "Готов", hint: "Проверка без обхода", tone: check?.status === "error" ? "bad" : "neutral" },
    { label: "Проверено целей", value: check ? `${check.done} / ${check.total}` : "—", hint: check?.total ? `${Math.round(check.done * 100 / check.total)}% завершено` : "Ожидание запуска" },
    { label: "Заблокировано", value: check ? counts.blocked : "—", hint: "По результатам проверки", tone: counts.blocked ? "bad" : "neutral" },
    { label: "Доступно напрямую", value: check ? counts.available : "—", hint: "Подтверждён ответ OK", tone: counts.available ? "ok" : "neutral" },
    { label: "Не определено", value: check ? counts.undetermined : "—", hint: `Локальные ошибки: ${counts.localErrors}`, tone: counts.undetermined ? "warn" : "neutral" },
  ]} />;
}

export function BlockCheckResults({ targets, query, filter, onQuery, onFilter, running, hasCheck }: {
  targets: TargetCheck[]; query: string; filter: CheckFilter;
  onQuery: (query: string) => void; onFilter: (filter: CheckFilter) => void;
  running: boolean; hasCheck: boolean;
}) {
  const visible = visibleBlockCheckTargets(targets, query, filter);
  return <Card title="Результаты проверки" sub="заблокированные сверху" className={compactCard}>
    <div className="mb-3 flex flex-wrap items-center gap-2">
      <Input aria-label="Поиск результатов BlockCheck" value={query} onChange={event => onQuery(event.target.value)} placeholder="Цель / код / ошибка" className="min-w-0 flex-1 sm:min-w-48" />
      <Select aria-label="Фильтр результатов BlockCheck" value={filter} onChange={event => onFilter(event.target.value as CheckFilter)} className="w-full sm:w-auto">
        <option value="all">Все результаты</option><option value="blocked">Блокировки</option><option value="ok">Доступные</option><option value="local_error">Локальные ошибки</option>
      </Select>
      <span className="text-xs tabular-nums text-muted">{visible.length} / {targets.length}</span>
    </div>
    <TableWrap>
      <table className={cn(tableCls, "min-w-[560px]")}>
        <thead><tr><th className={thBase}>Цель</th><th className={thBase}>Статус</th><th className={thBase}>Задержка</th><th className={thBase}>Скорость</th><th className={thBase}>Код</th></tr></thead>
        <tbody>
          {visible.length === 0 && <EmptyRow colSpan={5}>{targets.length ? "Нет целей под выбранный фильтр." : running ? "Ожидаем первые результаты проверки…" : hasCheck ? "Результатов пока нет." : "Запустите проверку."}</EmptyRow>}
          {visible.map((target, index) => <tr key={target.host + index} className="hover:bg-line-soft">
            <td className={cn(tdCls, "min-w-[150px] max-w-[260px] [overflow-wrap:anywhere]")}>{target.host}</td>
            <td className={tdCls}><VerdictBadge v={target.verdict} />{target.err && <Args>{target.err}</Args>}</td>
            <td className={cn(tdCls, "whitespace-nowrap tabular-nums")}>{target.ttfb_ms ? `${target.ttfb_ms} мс` : "—"}</td>
            <td className={cn(tdCls, "whitespace-nowrap tabular-nums")}>{target.speed_bps ? `${kb(target.speed_bps)} КБ/с` : "—"}</td>
            <td className={cn(tdCls, "tabular-nums")}>{target.code || "—"}</td>
          </tr>)}
        </tbody>
      </table>
    </TableWrap>
  </Card>;
}

export default function BlockCheck() {
  const { lists, geo } = useStore();
  const srcRef = useRef<SourceSelectorHandle>(null);
  const [threads, setThreads] = useState("4");
  const [bc, setBc] = useState<BC | null>(null);
  const [running, setRunning] = useState(false);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<CheckFilter>("all");

  usePoll(async () => {
    if (!bc) return;
    try {
      const r = await api<BC>("GET", `/api/blockcheck/${bc.id}`);
      setBc(r);
      if (r.status !== "running") {
        setRunning(false);
        const { blocked, localErrors } = summarizeTargetChecks(r.targets ?? []);
        if (r.status === "error") toast(r.error || "Проверка не завершена из-за локальной ошибки", "err");
        else if (r.status === "cancelled") toast("Проверка отменена", "warn");
        else toast(`Проверка завершена: заблокировано ${blocked} из ${r.total}${localErrors ? `; не определено из-за локальной ошибки: ${localErrors}` : ""}`, localErrors ? "warn" : "ok");
      }
    } catch (e) { setRunning(false); toast((e as Error).message, "err"); }
  }, 1000, running);

  const start = async () => {
    if (!srcRef.current) return;
    let target: TargetSource;
    try { target = await srcRef.current.resolve(); } catch (e) { toast((e as Error).message, "err"); return; }
    try { const r = await api<BC>("POST", "/api/blockcheck", { ...target, threads: parseInt(threads, 10) || 4 }); setBc(r); setRunning(true); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const cancel = async () => { setRunning(false); if (bc) { try { await api("POST", `/api/blockcheck/${bc.id}/cancel`); } catch { /* already stopping */ } } };

  const targets = bc?.targets ?? [];
  const pct = bc?.total ? Math.round((bc.done * 100) / bc.total) : 0;

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader title="BlockCheck" description="Проверка доступности доменов и IP напрямую, без обхода." actions={<>
          <Button variant="primary" onClick={start} disabled={running}>▶ Проверить</Button>
          {running && <Button variant="danger" onClick={cancel}>■ Отменить</Button>}
      </>} />
      <BlockCheckSummary check={bc} />
      <Card title="Параметры проверки" className={compactCard}>
        <p className="mb-4 text-xs leading-relaxed text-ink-soft">Проверяет доступность доменов/IP напрямую: тестовое соединение исключается из основного сервиса nfqws2 и не обходится — видно, что реально блокирует провайдер (RST, таймаут, обрыв на ~16 КБ).</p>
        <div className="grid items-end gap-4 sm:grid-cols-[minmax(0,1fr)_112px]">
          <section aria-label="Цели проверки" className="min-w-0"><h3 className="mb-3 text-xs font-medium">Источник целей</h3><SourceSelector ref={srcRef} lists={lists} geo={geo} /></section>
          <Field label="Потоков" hint="1–8"><Input type="number" min={1} max={8} value={threads} onChange={(e) => setThreads(e.target.value)} /></Field>
        </div>
        {bc?.error && <p role="alert" className="mt-2 text-xs text-bad [overflow-wrap:anywhere]">{bc.error}</p>}
        {running && bc && (
          <div className="mt-2">
            <div className="h-2 overflow-hidden rounded-full bg-line"><div className="h-full rounded-full bg-accent transition-[width]" style={{ width: `${pct}%` }} /></div>
            <span className="text-xs text-muted">{bc.done}/{bc.total} целей · {bc.threads} потоков · {bc.status}</span>
          </div>
        )}
      </Card>
      <BlockCheckResults targets={targets} query={query} filter={filter} onQuery={setQuery} onFilter={setFilter} running={running} hasCheck={!!bc} />
    </div>
  );
}

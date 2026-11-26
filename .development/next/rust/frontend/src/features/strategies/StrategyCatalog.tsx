import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { TableWrap, tableCls, tdCls, thBase, EmptyRow } from "@/components/ui/Table";
import { cn } from "@/lib/cn";
import type { Strategy } from "@/types/api";

export interface StrategyFilters { search: string; l7: string; source: string; }

export function filterStrategies(strategies: Strategy[], filters: StrategyFilters): Strategy[] {
  const query = filters.search.trim().toLowerCase();
  return strategies.filter(strategy =>
    (!filters.l7 || (strategy.l7 || "").trim().toLowerCase() === filters.l7.toLowerCase()) &&
    (!filters.source || strategy.source === filters.source) &&
    (!query || [strategy.id, strategy.name, strategy.l7, strategy.args, strategy.source].some(value => (value || "").toLowerCase().includes(query))));
}

export function strategyL7Options(strategies: Strategy[]): string[] {
  return [...new Set(strategies.map(strategy => (strategy.l7 || "").trim().toLowerCase()).filter(Boolean))].sort();
}

function StrategyArgs({ args }: { args: string }) {
  if (!args) return <span className="text-muted">—</span>;
  const preview = args.length > 180 ? `${args.slice(0, 180)}…` : args;
  return <details className="group/args min-w-[220px] max-w-[440px]">
    <summary className="cursor-pointer rounded-sm text-xs text-ink-soft outline-none focus-visible:ring-2 focus-visible:ring-ring/40">
      <span className="group-open/args:hidden">Показать аргументы</span><span className="hidden group-open/args:inline">Свернуть аргументы</span>
      <span className="mt-1 block font-mono text-[11px] leading-relaxed text-muted [overflow-wrap:anywhere] group-open/args:hidden">{preview}</span>
    </summary>
    <pre className="mt-2 whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-ink-soft [overflow-wrap:anywhere]">{args}</pre>
  </details>;
}

export function StrategyCatalog({ strategies, busy, onExport, onEdit, onDelete, filtered }: {
  strategies: Strategy[];
  busy: string | null;
  onExport: (strategy: Strategy) => void;
  onEdit: (strategy: Strategy) => void;
  onDelete: (id: string) => void;
  filtered: boolean;
}) {
  return <TableWrap scrollable>
    <table className={cn(tableCls, "min-w-[900px]")}>
      <thead><tr>{["ID", "Название", "L7", "Аргументы", "Источник", "Действия"].map(label => <th key={label} scope="col" className={cn(thBase, "text-xs")}>{label}</th>)}</tr></thead>
      <tbody>
        {strategies.length === 0 && <EmptyRow colSpan={6}>{filtered ? "По выбранным фильтрам стратегии не найдены." : "В каталоге пока нет стратегий. Добавьте свою или импортируйте ZIP."}</EmptyRow>}
        {strategies.map(strategy => <tr key={strategy.id} className="hover:bg-line-soft">
          <td className={cn(tdCls, "min-w-[130px] max-w-[200px] font-mono text-[11px] text-ink-soft [overflow-wrap:anywhere]")}>{strategy.id}</td>
          <th scope="row" className={cn(tdCls, "min-w-[170px] max-w-[250px] text-left text-xs font-medium [overflow-wrap:anywhere]")}>{strategy.name || "—"}</th>
          <td className={cn(tdCls, "min-w-[64px] whitespace-nowrap font-mono text-xs")}>{strategy.l7 || "—"}</td>
          <td className={tdCls}><StrategyArgs args={strategy.args} /></td>
          <td className={tdCls}><Badge>{strategy.source || "—"}</Badge></td>
          <td className={cn(tdCls, "min-w-[150px]")}>
            <div className="flex flex-wrap gap-1.5">
              <Button mini title="Экспорт стратегии и blob-файлов в ZIP" aria-label={`Экспортировать ${strategy.name || strategy.id} в ZIP`} disabled={busy !== null} onClick={() => onExport(strategy)}>{busy === `export:${strategy.id}` ? "Экспорт…" : "ZIP ↓"}</Button>
              {strategy.source === "custom" && <>
                <Button mini disabled={busy !== null} onClick={() => onEdit(strategy)}>Изменить</Button>
                <Button mini variant="danger" title="Удалить стратегию" aria-label={`Удалить стратегию ${strategy.name || strategy.id}`} disabled={busy !== null} onClick={() => onDelete(strategy.id)}>{busy === `delete:${strategy.id}` ? "Удаление…" : "Удалить"}</Button>
              </>}
            </div>
          </td>
        </tr>)}
      </tbody>
    </table>
  </TableWrap>;
}

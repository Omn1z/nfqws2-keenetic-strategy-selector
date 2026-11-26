import { Button } from "@/components/ui/Button";
import { StatsStrip } from "@/components/ui/FeaturePage";
import { cn } from "@/lib/cn";
import type { List } from "@/types/api";

export type ListFilter = "all" | "domains" | "ips" | "strategies";
export const entryCount = (entries: readonly string[] | null = []) => (entries ?? []).filter(entry => entry.trim()).length;

export function visibleLists(lists: List[], query: string, filter: ListFilter): List[] {
  const text = query.trim().toLowerCase();
  return lists.filter(list =>
    (filter !== "domains" || entryCount(list.domains) > 0) &&
    (filter !== "ips" || entryCount(list.ips) > 0) &&
    (filter !== "strategies" || (list.successful_strategies?.length ?? 0) > 0) &&
    (!text || [list.id, list.name, ...(list.domains ?? []), ...(list.ips ?? [])].some(value => (value || "").toLowerCase().includes(text))));
}

export function listSavePayload(list: List) {
  return { id: list.id, name: list.name.trim(), domains: list.domains, ips: list.ips,
    base_strategy_ids: list.base_strategy_ids ?? [], successful_strategies: list.successful_strategies ?? [] };
}

export function ListsSummary({ lists, selected }: { lists: List[]; selected: List | null }) {
  const hint = selected ? selected.name || "Без имени" : "Список не выбран";
  return <StatsStrip label="Сводка списков целей" items={[
    { label: "Списков", value: lists.length, hint: "сохранено в каталоге" },
    { label: "Доменов в редакторе", value: selected ? entryCount(selected.domains) : "—", hint },
    { label: "IP / CIDR в редакторе", value: selected ? entryCount(selected.ips) : "—", hint },
    { label: "Сохранённых стратегий", value: selected ? selected.successful_strategies?.length ?? 0 : "—", hint: "из результатов прогонов" },
  ]} />;
}

export function ListsCatalog({ lists, selectedId, busy, filtered, onSelect, onDelete }: {
  lists: List[]; selectedId?: string; busy: string | null; filtered: boolean;
  onSelect: (id: string) => void; onDelete: (id: string, name: string) => void;
}) {
  return <nav aria-label="Каталог списков целей" className="max-h-[520px] overflow-y-auto">
    {!lists.length && <p className="py-4 text-xs text-muted">{filtered ? "Списки под выбранный фильтр не найдены." : "Сохранённых списков пока нет. Создайте новый список."}</p>}
    <ul className="m-0 flex list-none flex-col gap-2 p-0">
      {lists.map(list => <li key={list.id} className={cn("flex min-w-0 items-start gap-2 rounded-lg border p-2.5", selectedId === list.id ? "border-accent bg-accent-w" : "border-line bg-panel")}>
        <button type="button" className="min-w-0 flex-1 rounded-sm text-left outline-none focus-visible:ring-2 focus-visible:ring-ring/40 disabled:cursor-wait" disabled={busy !== null} aria-current={selectedId === list.id ? "true" : undefined} onClick={() => onSelect(list.id)}>
          <span className="block text-xs font-medium [overflow-wrap:anywhere]">{list.name || "(без имени)"}</span>
          <span className="mt-1 block font-mono text-[10px] text-muted [overflow-wrap:anywhere]">{list.id}</span>
          <span className="mt-1.5 block text-[11px] leading-relaxed text-ink-soft">{busy === `select:${list.id}` ? "Открываем…" : `${entryCount(list.domains)} дом. · ${entryCount(list.ips)} IP · ${list.successful_strategies?.length ?? 0} стратегий`}</span>
        </button>
        <Button mini variant="danger" title="Удалить список" aria-label={`Удалить список ${list.name || list.id}`} disabled={busy !== null} onClick={() => onDelete(list.id, list.name)}>×</Button>
      </li>)}
    </ul>
  </nav>;
}

import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/Button";

export interface ChecklistItem {
  value: string;
  label: string;
  sub?: string;
}

interface ChecklistProps {
  title: string;
  hint?: string;
  items: ChecklistItem[];
  value: string[];
  onChange: (v: string[]) => void;
  disabled?: boolean;
  compact?: boolean;
}

/** Controlled multi-select with a smart select-all toggle. */
export function Checklist({ title, hint, items, value, onChange, disabled, compact = false }: ChecklistProps) {
  const sel = new Set(value);
  const allOn = items.length > 0 && items.every((i) => sel.has(i.value));
  const toggleAll = () => onChange(allOn ? [] : items.map((i) => i.value));
  const toggle = (v: string) => {
    const s = new Set(sel);
    if (s.has(v)) s.delete(v);
    else s.add(v);
    onChange([...s]);
  };
  return (
    <div className={cn("flex-1", compact ? "min-w-0" : "min-w-[220px]")}>
      <div className="mb-1.5 flex items-center justify-between gap-2.5">
        <span className={cn("min-w-0 font-medium text-ink-soft", compact ? "text-xs [overflow-wrap:anywhere]" : "text-[13px]")}>
          {title} {!compact && hint && <span className="font-normal text-muted">{hint}</span>}
        </span>
        <Button mini className="shrink-0 whitespace-nowrap" title={allOn ? "Снять все" : "Выбрать все"} disabled={disabled} onClick={toggleAll}>{compact ? allOn ? "Снять" : "Все" : allOn ? "Снять все" : "Выбрать все"}</Button>
      </div>
      {compact && hint && <p className="mb-2 text-[11px] leading-relaxed text-muted">{hint}</p>}
      <div className={cn("max-h-[168px] overflow-y-auto rounded-lg border border-line bg-input p-1", disabled && "pointer-events-none opacity-50")}>
        {items.length === 0 && <div className="p-2.5 text-xs text-muted">—</div>}
        {items.map((it) => (
          <label key={it.value} className={cn("flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-ink hover:bg-line-soft", compact ? "text-xs" : "text-[13px]")}>
            <input type="checkbox" className="h-4 w-4 shrink-0 accent-[var(--c-accent)]" checked={sel.has(it.value)} disabled={disabled} onChange={() => toggle(it.value)} />
            <span className={compact ? "min-w-0 [overflow-wrap:anywhere]" : undefined}>{it.label}</span>
            {it.sub && <span className="ml-auto shrink-0 text-[11.5px] text-muted">{it.sub}</span>}
          </label>
        ))}
      </div>
    </div>
  );
}

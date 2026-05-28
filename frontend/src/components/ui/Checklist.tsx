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
}

/** Controlled multi-select with a smart select-all toggle. */
export function Checklist({ title, hint, items, value, onChange, disabled }: ChecklistProps) {
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
    <div className="min-w-[220px] flex-1">
      <div className="mb-1.5 flex items-center justify-between gap-2.5">
        <span className="text-[13px] font-medium text-ink-soft">
          {title} {hint && <span className="font-normal text-muted">{hint}</span>}
        </span>
        <Button mini disabled={disabled} onClick={toggleAll}>{allOn ? "Снять все" : "Выбрать все"}</Button>
      </div>
      <div className={cn("max-h-[168px] overflow-y-auto rounded-lg border border-line bg-input p-1", disabled && "pointer-events-none opacity-50")}>
        {items.length === 0 && <div className="p-2.5 text-xs text-muted">—</div>}
        {items.map((it) => (
          <label key={it.value} className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-[13px] text-ink hover:bg-line-soft">
            <input type="checkbox" className="h-4 w-4 accent-[var(--c-accent)]" checked={sel.has(it.value)} disabled={disabled} onChange={() => toggle(it.value)} />
            <span>{it.label}</span>
            {it.sub && <span className="ml-auto text-[11.5px] text-muted">{it.sub}</span>}
          </label>
        ))}
      </div>
    </div>
  );
}

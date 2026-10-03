import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/cn";
import { listCategories, type ListCategory } from "./listCategory";

export function ListCategories({ value, onChange, counts, disabled = false }: {
  value: ListCategory;
  onChange: (value: ListCategory) => void;
  counts: Record<ListCategory, number>;
  disabled?: boolean;
}) {
  return <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Категория списков">
    {listCategories.map(item => <Button key={item.id} mini variant={value === item.id ? "default" : "ghost"} disabled={disabled}
      className={cn("min-h-8", value === item.id && "bg-line-soft dark:bg-line-soft")}
      title={item.extension} aria-pressed={value === item.id} onClick={() => onChange(item.id)}>
      {item.label} <span className="tabular-nums text-muted-foreground">{counts[item.id]}</span>
    </Button>)}
  </div>;
}

import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

/** Compact section styling shared by the overview and working screens. */
export const compactCard = "mb-0 min-w-0 p-4 sm:p-4 [&_[data-slot=card-header]]:mb-3 [&_[data-slot=card-title]]:text-sm [&_[data-slot=card-description]]:text-xs";

export function PageHeader({ title, description, actions, meta }: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  meta?: ReactNode;
}) {
  return <header className="flex flex-wrap items-start justify-between gap-3">
    <div className="min-w-0">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1"><h1 className="text-base font-semibold">{title}</h1>{meta && <span className="text-xs text-muted">{meta}</span>}</div>
      {description && <p className="mt-1 text-xs leading-relaxed text-ink-soft [overflow-wrap:anywhere]">{description}</p>}
    </div>
    {actions && <div className="flex max-w-full flex-wrap items-center gap-2">{actions}</div>}
  </header>;
}

export interface StatItem {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "neutral" | "ok" | "warn" | "bad";
}

export function StatsStrip({ items, label = "Ключевые показатели" }: { items: StatItem[]; label?: string }) {
  const five = items.length === 5;
  const three = items.length === 3;
  const columns = five ? "sm:grid-cols-3 xl:grid-cols-5" : items.length === 4 ? "sm:grid-cols-2 xl:grid-cols-4" : items.length === 3 ? "sm:grid-cols-3" : "sm:grid-cols-2";
  return <section aria-label={label} className={cn("grid grid-cols-2 gap-2", columns)}>
    {items.map((item, index) => <div key={item.label} className={cn("min-w-0 rounded-lg border border-line bg-panel px-3 py-2.5", five && index === 4 && "col-span-2 xl:col-span-1", three && index === 2 && "col-span-2 sm:col-span-1")}>
      <p className="text-xs text-ink-soft">{item.label}</p>
      <div className={cn("mt-1 text-lg font-semibold leading-tight tabular-nums [overflow-wrap:anywhere] sm:text-xl", item.tone === "ok" && "text-ok", item.tone === "warn" && "text-warn", item.tone === "bad" && "text-bad")}>{item.value}</div>
      {item.hint != null && <div className="mt-1 text-[11px] leading-relaxed text-muted [overflow-wrap:anywhere]">{item.hint}</div>}
    </div>)}
  </section>;
}

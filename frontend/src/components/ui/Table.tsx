import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export const tableCls = "w-full border-collapse text-[13px]";
export const thBase = "sticky top-0 z-10 whitespace-nowrap border-b border-line bg-panel px-2.5 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted";
export const tdCls = "border-b border-line-soft px-2.5 py-2.5 align-top";

export interface Sort {
  key: string;
  dir: number;
}

/** Flip direction when re-clicking the active column, else sort by `k` with `dir`. */
export const nextSort = (s: Sort, k: string, dir = -1): Sort => (s.key === k ? { key: k, dir: -s.dir } : { key: k, dir });

export function TableWrap({ scrollable, children }: { scrollable?: boolean; children: ReactNode }) {
  return <div className={cn("overflow-x-auto", scrollable && "max-h-[520px] overflow-auto")}>{children}</div>;
}

export function SortTh({ label, k, sort, onSort, className }: { label: string; k: string; sort: Sort; onSort: (k: string) => void; className?: string }) {
  return (
    <th onClick={() => onSort(k)} className={cn(thBase, "cursor-pointer select-none transition-colors hover:text-accent", sort.key === k && "text-accent", className)}>
      {label}
      {sort.key === k ? (sort.dir > 0 ? " ↑" : " ↓") : ""}
    </th>
  );
}

/** Monospace nfqws2 args clamped to 3 lines, full text in the tooltip. */
export const Args = ({ children }: { children?: string }) => (
  <div className="args-clamp mt-0.5 font-mono text-[11px] text-muted" title={children}>{children}</div>
);

export const EmptyRow = ({ colSpan, children }: { colSpan: number; children: ReactNode }) => (
  <tr><td colSpan={colSpan} className="px-2.5 py-5 text-center text-muted">{children}</td></tr>
);

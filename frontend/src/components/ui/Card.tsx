import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

interface CardProps {
  title?: ReactNode;
  sub?: ReactNode;
  /** Right-aligned slot in the header (actions, badge, filter). */
  head?: ReactNode;
  className?: string;
  children?: ReactNode;
}

export function Card({ title, sub, head, className, children }: CardProps) {
  return (
    <div
      data-slot="card"
      className={cn("mb-4 rounded-xl border border-border bg-card p-4 text-card-foreground shadow-sm sm:p-5", className)}
    >
      {(title || head) && (
        <div className="mb-3.5 flex flex-wrap items-center gap-x-2.5 gap-y-1">
          {title && <h2 className="text-[15px] font-semibold">{title}</h2>}
          {sub && <span className="text-xs font-normal text-muted">{sub}</span>}
          {head && <div className="ml-auto">{head}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

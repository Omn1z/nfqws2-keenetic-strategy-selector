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
      className={cn("group/card mb-4 rounded-lg bg-card p-4 text-sm text-card-foreground shadow-sm ring-1 ring-foreground/5 dark:ring-foreground/10 sm:p-5", className)}
    >
      {(title || head) && (
        <div data-slot="card-header" className="mb-4 flex flex-wrap items-center gap-x-3 gap-y-1.5">
          {title && <h2 data-slot="card-title" className="font-heading text-base font-medium">{title}</h2>}
          {sub && <span data-slot="card-description" className="text-sm font-normal text-muted-foreground">{sub}</span>}
          {head && <div data-slot="card-action" className="ml-auto">{head}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

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
    <div className={cn("mb-[18px] rounded-xl border border-line bg-panel p-5 shadow-sm", className)}>
      {(title || head) && (
        <div className="mb-3.5 flex items-baseline gap-2.5">
          {title && <h2 className="text-[15px] font-semibold">{title}</h2>}
          {sub && <span className="text-xs font-normal text-muted">{sub}</span>}
          {head && <div className="ml-auto self-center">{head}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

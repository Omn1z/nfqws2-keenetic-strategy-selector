import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export type BadgeKind = "ok" | "bad" | "warn" | "neutral";

const KIND: Record<BadgeKind, string> = {
  ok: "bg-ok-bg text-ok",
  bad: "bg-bad-bg text-bad",
  warn: "bg-warn-bg text-warn",
  neutral: "bg-line-soft text-ink-soft",
};

export function Badge({ kind = "neutral", className, children }: { kind?: BadgeKind; className?: string; children: ReactNode }) {
  return (
    <span className={cn("inline-block whitespace-nowrap rounded-full px-2.5 py-0.5 text-[11px] font-semibold", KIND[kind], className)}>
      {children}
    </span>
  );
}

const VERDICT: Record<string, [string, BadgeKind]> = {
  ok: ["доступен", "ok"],
  cap16k: ["обрыв 16КБ", "bad"],
  reset: ["RST", "bad"],
  timeout: ["таймаут", "bad"],
  refused: ["отказ", "warn"],
  dns: ["DNS", "warn"],
  error: ["ошибка", "bad"],
};

export function VerdictBadge({ v }: { v: string }) {
  const [label, kind] = VERDICT[v] ?? [v || "?", "bad"];
  return <Badge kind={kind}>{label}</Badge>;
}

/** Underlined chip highlighting which DNS produced a result (system = muted). */
export function DnsBadge({ name, id }: { name?: string; id?: string }) {
  if (!name) return <span>—</span>;
  return (
    <span className={cn("whitespace-nowrap text-[11.5px] font-semibold underline underline-offset-2", id ? "text-accent-d decoration-accent" : "text-muted decoration-line")}>
      {name}
    </span>
  );
}

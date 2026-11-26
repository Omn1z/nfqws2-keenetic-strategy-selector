import { cn } from "@/lib/cn";

/** Pulsing placeholder block for loading states. */
export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-line-soft", className)} />;
}

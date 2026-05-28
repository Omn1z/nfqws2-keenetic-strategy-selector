import { cn } from "@/lib/cn";

export const Spinner = ({ className }: { className?: string }) => (
  <div className={cn("h-10 w-10 animate-spin rounded-full border-4 border-line border-t-accent", className)} />
);

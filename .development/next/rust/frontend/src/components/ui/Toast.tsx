import { useEffect, useState } from "react";
import { cn } from "@/lib/cn";

export type ToastKind = "ok" | "err" | "warn";

let push: ((msg: string, kind?: ToastKind) => void) | null = null;

/** Show a transient toast from anywhere; rendered by <Toaster/>. */
export function toast(msg: string, kind?: ToastKind): void {
  push?.(msg, kind);
}

interface ToastState {
  msg: string;
  kind?: ToastKind;
  id: number;
}

const KIND: Record<ToastKind, string> = { ok: "border-ok/30 bg-ok-bg text-ok", err: "border-bad/30 bg-bad-bg text-bad", warn: "border-warn/30 bg-warn-bg text-warn" };

export function Toaster() {
  const [t, setT] = useState<ToastState | null>(null);
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    push = (msg, kind) => {
      setT({ msg, kind, id: Date.now() });
      clearTimeout(timer);
      timer = setTimeout(() => setT(null), 4200);
    };
    return () => { push = null; clearTimeout(timer); };
  }, []);
  if (!t) return null;
  return (
    <div
      key={t.id}
      role="status"
      aria-live="polite"
      className={cn(
        "fixed bottom-4 left-4 right-4 z-[60] rounded-lg border px-4 py-3 text-sm leading-5 shadow-lg sm:bottom-5 sm:left-auto sm:right-5 sm:max-w-sm",
        t.kind ? KIND[t.kind] : "border-border bg-popover text-popover-foreground",
      )}
    >
      {t.msg}
    </div>
  );
}

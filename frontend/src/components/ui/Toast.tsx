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

const KIND: Record<ToastKind, string> = { ok: "bg-ok", err: "bg-bad", warn: "bg-warn" };

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
      className={cn(
        "fixed bottom-4 left-4 right-4 z-[60] rounded-xl px-4 py-3 text-sm text-white shadow-2xl sm:bottom-5 sm:left-auto sm:right-5 sm:max-w-sm",
        t.kind ? KIND[t.kind] : "bg-slate-800",
      )}
    >
      {t.msg}
    </div>
  );
}

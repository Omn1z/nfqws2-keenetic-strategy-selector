import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: ReactNode }) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2.5 text-[13px] text-ink-soft">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={cn("relative h-[22px] w-10 shrink-0 rounded-full transition-colors", checked ? "bg-accent" : "bg-track")}
      >
        <span className={cn("absolute top-0.5 h-[18px] w-[18px] rounded-full bg-white shadow transition-all", checked ? "left-5" : "left-0.5")} />
      </button>
      {label}
    </label>
  );
}

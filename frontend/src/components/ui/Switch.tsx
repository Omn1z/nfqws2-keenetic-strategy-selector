import type { ReactNode } from "react";
import { Switch as BaseSwitch } from "@base-ui/react/switch";
import { cn } from "@/lib/cn";

/**
 * Toggle backed by Base UI Switch (keyboard + hidden input + a11y). Visuals are
 * driven by the controlled `checked` prop so it matches the Keenetic look exactly.
 * Not wrapped in a <label> (Base UI's hidden input inside a label double-toggles);
 * the optional text is a sibling with its own click + aria-label on the control.
 */
export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2.5 text-[13px] text-ink-soft">
      <BaseSwitch.Root
        checked={checked}
        onCheckedChange={(v) => onChange(v)}
        aria-label={typeof label === "string" ? label : undefined}
        className={cn(
          "relative h-[22px] w-10 shrink-0 cursor-pointer rounded-full outline-none transition-colors focus-visible:ring-2 focus-visible:ring-ring/40",
          checked ? "bg-accent" : "bg-track",
        )}
      >
        <BaseSwitch.Thumb
          className={cn("absolute top-0.5 h-[18px] w-[18px] rounded-full bg-white shadow transition-all", checked ? "left-5" : "left-0.5")}
        />
      </BaseSwitch.Root>
      {label != null && (
        <span className="cursor-pointer select-none" onClick={() => onChange(!checked)}>
          {label}
        </span>
      )}
    </span>
  );
}

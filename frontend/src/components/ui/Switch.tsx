import { useId } from "react";
import type { AriaAttributes, ReactNode } from "react";
import { Switch as BaseSwitch } from "@base-ui/react/switch";
import { cn } from "@/lib/cn";

/**
 * Toggle backed by Base UI Switch (keyboard + hidden input + a11y). Visuals are
 * driven by the controlled `checked` prop and shared theme tokens.
 * Not wrapped in a <label> (Base UI's hidden input inside a label double-toggles);
 * the optional text is a sibling with its own click + aria-labelledby link.
 */
type SwitchProps = {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: ReactNode;
  disabled?: boolean;
  size?: "sm" | "default";
} & Pick<AriaAttributes, "aria-label" | "aria-labelledby" | "aria-describedby" | "aria-invalid">;

export function Switch({ checked, onChange, label, disabled = false, size = "default", "aria-label": ariaLabel, "aria-labelledby": ariaLabelledBy, ...aria }: SwitchProps) {
  const labelId = useId();
  return (
    <span className={cn("inline-flex items-center gap-2.5 text-[13px] text-ink-soft", disabled && "opacity-50")}>
      <BaseSwitch.Root
        checked={checked}
        onCheckedChange={(v) => onChange(v)}
        disabled={disabled}
        aria-label={ariaLabel}
        aria-labelledby={ariaLabelledBy ?? (ariaLabel == null && label != null ? labelId : undefined)}
        {...aria}
        data-slot="switch"
        data-size={size}
        className="peer group/switch relative inline-flex shrink-0 cursor-pointer items-center rounded-2xl border-2 outline-none transition-[color,background-color,border-color,box-shadow] after:absolute after:-inset-x-3 after:-inset-y-2 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/30 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 data-[size=default]:h-5 data-[size=default]:w-8 data-[size=sm]:h-4 data-[size=sm]:w-6 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 data-checked:border-primary data-checked:bg-primary data-unchecked:border-transparent data-unchecked:bg-rhea-input/90 data-disabled:cursor-not-allowed"
      >
        <BaseSwitch.Thumb
          data-slot="switch-thumb"
          className="pointer-events-none block rounded-2xl bg-background shadow-sm ring-0 transition-transform not-dark:bg-clip-padding group-data-[size=default]/switch:size-4 group-data-[size=sm]/switch:size-3 data-checked:translate-x-[calc(100%-4px)] dark:data-checked:bg-primary-foreground data-unchecked:translate-x-0 dark:data-unchecked:bg-foreground"
        />
      </BaseSwitch.Root>
      {label != null && (
        <span id={labelId} className={cn("select-none", disabled ? "cursor-not-allowed" : "cursor-pointer")} onClick={() => { if (!disabled) onChange(!checked); }}>
          {label}
        </span>
      )}
    </span>
  );
}

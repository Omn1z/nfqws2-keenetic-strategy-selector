import type { ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

type Variant = "primary" | "default" | "ghost" | "danger";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  mini?: boolean;
}

const VARIANT: Record<Variant, string> = {
  primary: "border-accent bg-accent text-white shadow-sm hover:bg-accent-d hover:border-accent-d",
  default: "border-line bg-panel text-ink hover:border-track",
  ghost: "border-transparent bg-transparent text-ink hover:bg-line-soft",
  danger: "border-transparent bg-transparent text-bad hover:bg-bad-bg",
};

export function Button({ variant = "default", mini, className, type = "button", ...rest }: ButtonProps) {
  return (
    <button
      type={type}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 rounded-lg border font-semibold transition active:translate-y-px disabled:pointer-events-none disabled:opacity-50",
        mini ? "rounded-md px-2.5 py-1.5 text-xs" : "px-4 py-2 text-[13.5px]",
        VARIANT[variant],
        className,
      )}
      {...rest}
    />
  );
}

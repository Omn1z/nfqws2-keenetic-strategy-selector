import type { ButtonHTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

// shadcn-style button: cva variants + data-slot, themed through the token bridge.
// Variant/size vocabulary kept as the project's (primary/default/ghost/danger + mini)
// so existing call sites don't change.
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-lg border font-semibold outline-none transition active:translate-y-px focus-visible:ring-2 focus-visible:ring-ring/40 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary: "border-primary bg-primary text-primary-foreground shadow-sm hover:border-primary/90 hover:bg-primary/90",
        default: "border-border bg-card text-foreground hover:border-track",
        ghost: "border-transparent bg-transparent text-foreground hover:bg-line-soft",
        danger: "border-transparent bg-transparent text-bad hover:bg-bad-bg",
      },
      size: {
        default: "px-4 py-2 text-[13.5px]",
        mini: "rounded-md px-2.5 py-1.5 text-xs",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
  mini?: boolean;
}

export function Button({ variant, size, mini, className, type = "button", ...rest }: ButtonProps) {
  return (
    <button
      type={type}
      data-slot="button"
      className={cn(buttonVariants({ variant, size: mini ? "mini" : size }), className)}
      {...rest}
    />
  );
}

export { buttonVariants };

import type { ButtonHTMLAttributes } from "react";
import { Button as ButtonPrimitive } from "@base-ui/react/button";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

// Adapted from shadcn's base-rhea registry, with Small radius and the existing
// project variant names (primary = default, default = outline, danger = destructive).
// Long translated labels may wrap instead of overflowing narrow screens.
const buttonVariants = cva(
  "group/button inline-flex min-w-0 max-w-full items-center justify-center rounded-md border border-transparent bg-clip-padding text-center font-medium leading-5 outline-none select-none transition-[color,background-color,border-color,box-shadow,transform] focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/30 active:not-aria-[haspopup]:translate-y-px disabled:pointer-events-none disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 [overflow-wrap:anywhere] [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        primary: "bg-primary text-primary-foreground hover:bg-primary/80",
        default: "border-border bg-background text-foreground hover:bg-line-soft aria-expanded:bg-line-soft dark:bg-transparent dark:hover:bg-rhea-input/30",
        ghost: "bg-transparent text-foreground hover:bg-line-soft aria-expanded:bg-line-soft dark:hover:bg-line-soft/50",
        danger: "bg-destructive/10 text-destructive hover:bg-destructive/20 focus-visible:border-destructive/40 focus-visible:ring-destructive/20 dark:bg-destructive/20 dark:hover:bg-destructive/30 dark:focus-visible:ring-destructive/40",
      },
      size: {
        default: "min-h-8 gap-1.5 px-3 py-1 text-sm",
        mini: "min-h-6 gap-1 px-2.5 py-0.5 text-xs [&_svg:not([class*='size-'])]:size-3",
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
    <ButtonPrimitive
      type={type}
      data-slot="button"
      className={cn(buttonVariants({ variant, size: mini ? "mini" : size }), className)}
      {...rest}
    />
  );
}

export { buttonVariants };

import type { InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from "react";
import { Input as InputPrimitive } from "@base-ui/react/input";
import { cn } from "@/lib/cn";
export { Select } from "./Select";

// shadcn base-rhea fields, using the Small radius and a separate input token to
// keep older project surfaces that use bg-input backward compatible.
export const fieldCls =
  "w-full min-h-8 min-w-0 max-w-full rounded-md border border-transparent bg-rhea-input/50 px-2.5 py-1 text-base leading-5 text-foreground outline-none transition-[color,box-shadow] duration-200 placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/30 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 disabled:cursor-not-allowed disabled:opacity-50 md:text-sm";

export function Field({ label, hint, className, children }: { label?: ReactNode; hint?: ReactNode; className?: string; children: ReactNode }) {
  return (
    <label data-slot="field-label" className={cn("block min-w-0 max-w-full text-sm font-medium leading-5 text-foreground", className)}>
      {label != null && (
        <span className="mb-1.5 block">
          {label}
          {hint && <span className="ml-1 font-normal text-muted">{hint}</span>}
        </span>
      )}
      {children}
    </label>
  );
}

export const Input = ({ className, ...p }: InputHTMLAttributes<HTMLInputElement>) => <InputPrimitive data-slot="input" className={cn(fieldCls, "file:inline-flex file:h-6 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground disabled:pointer-events-none", className)} {...p} />;
export const Textarea = ({ className, ...p }: TextareaHTMLAttributes<HTMLTextAreaElement>) => (
  <textarea data-slot="textarea" className={cn(fieldCls, "min-h-24 resize-y py-2 font-mono leading-6", className)} {...p} />
);

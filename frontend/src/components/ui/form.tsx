import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

// Shared field shell. Token-based (border/bg/ring) so it adapts to the theme.
export const fieldCls =
  "w-full rounded-lg border border-line bg-input px-3 py-2 text-[13.5px] text-ink outline-none transition placeholder:text-muted focus:border-accent focus:ring-2 focus:ring-accent-w disabled:cursor-not-allowed disabled:opacity-50";

export function Field({ label, hint, className, children }: { label?: ReactNode; hint?: ReactNode; className?: string; children: ReactNode }) {
  return (
    <label className={cn("block text-[13px] font-medium text-ink-soft", className)}>
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

export const Input = ({ className, ...p }: InputHTMLAttributes<HTMLInputElement>) => <input className={cn(fieldCls, className)} {...p} />;
export const Select = ({ className, ...p }: SelectHTMLAttributes<HTMLSelectElement>) => <select className={cn(fieldCls, "cursor-pointer", className)} {...p} />;
export const Textarea = ({ className, ...p }: TextareaHTMLAttributes<HTMLTextAreaElement>) => (
  <textarea className={cn(fieldCls, "resize-y font-mono text-xs", className)} {...p} />
);

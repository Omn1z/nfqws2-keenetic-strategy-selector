import type { ReactNode } from "react";
import { Dialog } from "@base-ui/react/dialog";
import { cn } from "@/lib/cn";

interface ModalProps {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  /** Right-aligned action buttons row at the bottom. */
  actions?: ReactNode;
  size?: "sm" | "md" | "lg";
}

const widths: Record<NonNullable<ModalProps["size"]>, string> = {
  sm: "w-[min(calc(100vw-1rem),28rem)]",
  md: "w-[min(calc(100vw-1rem),36rem)]",
  lg: "w-[min(calc(100vw-1rem),42rem)]",
};

/**
 * Centered overlay dialog backed by Base UI (focus-trap + scroll-lock + portal).
 * Same API as before — the parent mounts <Modal> only while open, so we drive
 * Base UI with `open` fixed true and translate open→false into onClose().
 * Click-outside and Escape both close.
 */
export function Modal({ title, onClose, children, actions, size = "md" }: ModalProps) {
  return (
    <Dialog.Root
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-[70] bg-[rgba(20,30,45,.55)] backdrop-blur-sm transition-opacity data-[ending-style]:opacity-0 data-[starting-style]:opacity-0" />
        <Dialog.Popup
          className={cn(
            "fixed left-1/2 top-1/2 z-[71] flex max-h-[calc(100dvh-1rem)] max-w-none -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-xl border border-border bg-card text-card-foreground shadow-2xl outline-none transition-all data-[ending-style]:scale-95 data-[ending-style]:opacity-0 data-[starting-style]:scale-95 data-[starting-style]:opacity-0",
            widths[size],
          )}
        >
          <Dialog.Title className="shrink-0 px-4 pt-4 text-[15px] font-semibold sm:px-5 sm:pt-5">{title}</Dialog.Title>
          <div className="min-h-0 min-w-0 flex-1 overflow-y-auto overflow-x-hidden px-4 pb-4 pt-2 text-[13px] leading-relaxed text-ink-soft [overflow-wrap:anywhere] sm:px-5">
            <div className="min-w-0 max-w-full [&_*]:min-w-0 [&_img]:max-w-full [&_pre]:max-w-full [&_table]:max-w-full">
              {children}
            </div>
          </div>
          {actions && (
            <div className="shrink-0 border-t border-line bg-card px-4 py-3 sm:px-5">
              <div className="flex min-w-0 flex-wrap justify-end gap-2.5">{actions}</div>
            </div>
          )}
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

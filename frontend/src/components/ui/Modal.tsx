import type { ReactNode } from "react";
import { Dialog } from "@base-ui/react/dialog";

interface ModalProps {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  /** Right-aligned action buttons row at the bottom. */
  actions?: ReactNode;
}

/**
 * Centered overlay dialog backed by Base UI (focus-trap + scroll-lock + portal).
 * Same API as before — the parent mounts <Modal> only while open, so we drive
 * Base UI with `open` fixed true and translate open→false into onClose().
 * Click-outside and Escape both close.
 */
export function Modal({ title, onClose, children, actions }: ModalProps) {
  return (
    <Dialog.Root
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-[70] bg-[rgba(20,30,45,.55)] backdrop-blur-sm transition-opacity data-[ending-style]:opacity-0 data-[starting-style]:opacity-0" />
        <Dialog.Popup className="fixed left-1/2 top-1/2 z-[71] max-h-[85vh] w-[calc(100vw-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-xl border border-border bg-card p-5 text-card-foreground shadow-2xl outline-none transition-all data-[ending-style]:scale-95 data-[ending-style]:opacity-0 data-[starting-style]:scale-95 data-[starting-style]:opacity-0">
          <Dialog.Title className="mb-2.5 text-[15px] font-semibold">{title}</Dialog.Title>
          <div className="text-[13px] leading-relaxed text-ink-soft [overflow-wrap:anywhere]">{children}</div>
          {actions && <div className="mt-4 flex flex-wrap justify-end gap-2.5">{actions}</div>}
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

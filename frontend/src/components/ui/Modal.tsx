import { useEffect } from "react";
import type { ReactNode } from "react";

interface ModalProps {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  /** Right-aligned action buttons row at the bottom. */
  actions?: ReactNode;
}

/** Centered overlay dialog. Click-outside and Escape both call onClose. */
export function Modal({ title, onClose, children, actions }: ModalProps) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      role="presentation"
      onClick={onClose}
      className="fixed inset-0 z-[70] grid place-items-center bg-[rgba(20,30,45,.55)] p-4 backdrop-blur-sm"
    >
      <div
        role="dialog"
        aria-modal
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md rounded-xl border border-line bg-panel p-5 shadow-2xl"
      >
        <h2 className="mb-2.5 text-[15px] font-semibold">{title}</h2>
        <div className="text-[13px] leading-relaxed text-ink-soft">{children}</div>
        {actions && <div className="mt-4 flex justify-end gap-2.5">{actions}</div>}
      </div>
    </div>
  );
}

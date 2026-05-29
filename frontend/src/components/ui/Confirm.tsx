import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";

interface ConfirmOpts {
  title: ReactNode;
  body?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
}
type Req = ConfirmOpts & { resolve: (ok: boolean) => void };

let push: ((r: Req) => void) | null = null;

/** Promise-based confirm backed by the Base UI Modal (consistent with the app).
 *  `if (!(await confirmDialog({ title }))) return;`. Falls back to window.confirm
 *  if the host isn't mounted. */
export function confirmDialog(opts: ConfirmOpts): Promise<boolean> {
  return new Promise((resolve) => {
    if (push) push({ ...opts, resolve });
    else resolve(window.confirm(typeof opts.title === "string" ? opts.title : "Подтвердить действие?"));
  });
}

/** Mounted once near the root; renders the active confirm dialog. */
export function ConfirmHost() {
  const [req, setReq] = useState<Req | null>(null);
  useEffect(() => {
    push = (r) => setReq(r);
    return () => { push = null; };
  }, []);
  if (!req) return null;
  const done = (ok: boolean) => { req.resolve(ok); setReq(null); };
  return (
    <Modal
      title={req.title}
      onClose={() => done(false)}
      actions={
        <>
          <Button variant="ghost" onClick={() => done(false)}>{req.cancelLabel ?? "Отмена"}</Button>
          <Button
            variant="primary"
            autoFocus={!req.danger}
            className={req.danger ? "border-bad bg-bad text-white hover:border-bad/90 hover:bg-bad/90" : undefined}
            onClick={() => done(true)}
          >
            {req.confirmLabel ?? "ОК"}
          </Button>
        </>
      }
    >
      {req.body}
    </Modal>
  );
}

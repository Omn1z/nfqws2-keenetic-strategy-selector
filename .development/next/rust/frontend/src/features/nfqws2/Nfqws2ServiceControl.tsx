import { useEffect, useRef, useState } from "react";
import { usePoll } from "@/lib/hooks";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { toast } from "@/components/ui/Toast";
import type { Nfqws2ServiceStatus } from "@/types/api";
import { Nfqws2ServiceController } from "./nfqws2ServiceControlModel";
import type { Nfqws2ServiceAction } from "./nfqws2ServiceControlModel";

export function useNfqws2ServiceControl() {
  const controller = useRef(new Nfqws2ServiceController());
  const mounted = useRef(false);
  const [status, setStatus] = useState<Nfqws2ServiceStatus | null>(null);
  const [error, setError] = useState("");
  const [pending, setPending] = useState<Nfqws2ServiceAction | null>(null);
  const accept = () => {
    if (!mounted.current) return;
    setStatus(controller.current.status); setError(controller.current.error);
  };
  useEffect(() => {
    mounted.current = true; controller.current.activate();
    return () => { mounted.current = false; controller.current.dispose(); };
  }, []);
  const refresh = async (signal?: AbortSignal) => {
    await controller.current.refresh(signal); accept();
  };
  usePoll(async signal => { if (!document.hidden) await refresh(signal); }, 5000);

  const run = async (action: Nfqws2ServiceAction): Promise<boolean> => {
    if (controller.current.pending) return false;
    // perform takes its synchronous lock before its first await.
    const operation = controller.current.perform(action);
    setPending(controller.current.pending);
    try {
      const result = await operation;
      if (!result) return false;
      toast(result.ok ? action === "stop" ? "Служба NFQWS2 остановлена" : action === "start" ? "Служба NFQWS2 включена" : "Служба NFQWS2 перезапущена" : "NFQWS2: " + (result.detail || "ошибка"), result.ok ? "ok" : "err");
      if (result.ok && action !== "stop") window.dispatchEvent(new CustomEvent("nfqws2-files-changed", { detail: { source: "restart" } }));
      return result.ok;
    } catch (cause) {
      toast((cause as Error).message, "err"); return false;
    } finally {
      if (mounted.current) { setPending(controller.current.pending); accept(); }
    }
  };
  return { status, error, pending, loading: status === null && !error, refresh, run,
    canRestart: status?.running === true && !status.manual_off && !error && pending === null };
}

interface Props {
  status: Nfqws2ServiceStatus | null;
  error: string;
  pending: Nfqws2ServiceAction | null;
  onToggle: (enabled: boolean) => void;
  onRestart: () => void;
}

export function Nfqws2ServiceControls({ status, error, pending, onToggle, onRestart }: Props) {
  const disabled = !status || !!error || pending !== null;
  return <>
    <Badge kind={error ? "warn" : status?.running ? "ok" : "neutral"}>{pending === "start" ? "Включение…" : pending === "stop" ? "Остановка…" : pending === "restart" ? "Перезапуск…" : error ? "Состояние неизвестно" : status ? status.running ? "Работает" : "Остановлена" : "Проверяем состояние…"}</Badge>
    <Switch checked={status?.running === true} disabled={disabled} onChange={onToggle} label="Служба NFQWS2" />
    <Button mini variant="primary" onClick={onRestart} disabled={disabled || !status?.running || status.manual_off} title="Применить сохранённые изменения и полностью перезапустить службу NFQWS2">{pending === "restart" ? "Перезапуск…" : "Перезапуск службы"}</Button>
  </>;
}

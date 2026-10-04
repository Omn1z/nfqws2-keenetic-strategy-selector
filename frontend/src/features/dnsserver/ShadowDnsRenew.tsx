import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/Button";
import { confirmDialog } from "@/components/ui/Confirm";
import { api } from "@/lib/api";
import type { DnsShadowRenewResponse, DnsShadowRenewResult, DnsShadowStatus } from "@/types/api";

type Props = {
  status?: DnsShadowStatus;
  disabled?: boolean;
  /** Acquires the parent's synchronous mutation lock after confirmation. */
  onBusyChange?: (busy: boolean) => boolean;
  onRefresh?: () => Promise<void> | void;
  onResult?: (result: DnsShadowRenewResult) => void;
};

// Keep the confirmation and mutation in one flow. Reading status or showing
// the card must never cause a WAN renewal; cancellation sends no POST.
export async function confirmAndRenewShadowDns(begin: () => boolean): Promise<DnsShadowRenewResult | null> {
  const confirmed = await confirmDialog({
    title: "Обновить DHCP-аренду? Возможен перерыв интернета.",
    body: "Keenetic обновит DHCP-аренду активного WAN. Интернет может ненадолго прерваться. DNS будут получены автоматически из ответа провайдера. Проверка ответа занимает до 16 секунд.",
    confirmLabel: "Обновить аренду и получить DNS",
  });
  if (!confirmed || !begin()) return null;
  const response = await api<DnsShadowRenewResponse>("POST", "/api/dnsserver/shadow/renew", { confirm: true }, { timeoutMs: 20_000 });
  if (!response?.ok || !response.result || !["resolved", "waiting", "no_dns", "nak"].includes(response.result.status)) {
    throw new Error("Не удалось прочитать результат обновления DHCP. Проверьте состояние Shadow DNS перед повторной попыткой.");
  }
  return response.result;
}

export function ShadowDnsRenewOutcome({ result, error }: { result: DnsShadowRenewResult | null; error: string }) {
  if (error) return <p role="alert" className="mt-2 text-xs text-bad [overflow-wrap:anywhere]">{error}</p>;
  if (!result) return null;
  const titles = {
    resolved: "DNS провайдера получены",
    waiting: "Ожидание ответа провайдера",
    no_dns: "Провайдер не передал DNS",
    nak: "DHCP-сервер отклонил обновление аренды",
  };
  return <div role={result.status === "nak" ? "alert" : "status"} className="mt-2 text-xs [overflow-wrap:anywhere]">
    <p className={result.status === "resolved" ? "text-ok" : "text-warn"}>{titles[result.status]}</p>
    {result.message && <p className="mt-1 text-muted">{result.message}</p>}
    {result.status === "resolved" && !!result.servers?.length && <p className="mt-1"><code>{result.servers.join(", ")}</code></p>}
    {(result.interface || result.device) && <p className="mt-1 text-muted">WAN: {result.interface}{result.device && result.device !== result.interface ? ` (${result.device})` : ""}</p>}
  </div>;
}

export function ShadowDnsRenew({ status, disabled = false, onBusyChange, onRefresh, onResult }: Props) {
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<DnsShadowRenewResult | null>(null);
  const [error, setError] = useState("");
  const mounted = useRef(false);
  const working = useRef(false);
  const current = useRef({ status, disabled, onBusyChange, onRefresh, onResult });
  current.current = { status, disabled, onBusyChange, onRefresh, onResult };
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  const renew = async () => {
    if (working.current || disabled) return;
    working.current = true;
    let started = false;
    try {
      const next = await confirmAndRenewShadowDns(() => {
        const latest = current.current;
        if (!mounted.current || latest.disabled || !latest.status?.enabled || latest.status.renewal_available !== true || latest.onBusyChange?.(true) === false) return false;
        started = true;
        setPending(true); setError(""); setResult(null);
        return true;
      });
      if (mounted.current && next) { setResult(next); current.current.onResult?.(next); }
    } catch (e) {
      if (mounted.current) setError(`${(e as Error).message} Обновление аренды могло уже начаться. Проверьте состояние и диагностику перед повторной попыткой.`);
    } finally {
      working.current = false;
      if (started) {
        if (mounted.current) setPending(false);
        current.current.onBusyChange?.(false);
        // Refresh live data only; unsaved DNS settings remain in the form.
        if (mounted.current) await current.current.onRefresh?.();
      }
    }
  };

  if (!status?.enabled || status.renewal_available !== true) return null;
  return <div className="mt-3 rounded-lg border border-line p-3">
    <div className="flex flex-wrap items-center gap-2">
      <Button mini disabled={disabled || pending} onClick={() => { void renew(); }}>{pending ? "Получение DNS…" : "Получить DNS сейчас"}</Button>
      {pending && <span role="status" className="text-xs text-muted">Ожидается ответ DHCP, до 16 секунд…</span>}
    </div>
    <p className="mt-2 text-xs text-muted">Если автоматический поиск не помог, можно обновить DHCP-аренду WAN и получить DNS из ответа провайдера. Действие потребует подтверждения: интернет может ненадолго прерваться.</p>
    <ShadowDnsRenewOutcome result={result} error={error} />
  </div>;
}

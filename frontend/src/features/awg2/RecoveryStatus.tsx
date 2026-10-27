import type { AwgClientStatus } from "@/types/api";

export function recoveryPhaseLabel(client: AwgClientStatus, nowSeconds: number): string {
  const verification = Math.max(0, (client.verification_until || 0) - nowSeconds);
  if (verification > 0) return `ожидаем handshake: ещё ${verification} с`;
  const retry = Math.max(0, (client.retry_at || 0) - nowSeconds);
  if (retry > 0) {
    // Older API snapshots and failed local starts have no verification phase.
    // Keep their deadline neutral rather than inventing a handshake outcome.
    return client.verification_until == null ? `повтор через ${retry} с` : `пауза перед повтором: ${retry} с`;
  }
  return "подключаемся / проверяем";
}

export default function RecoveryStatus({ client }: { client: AwgClientStatus }) {
  if (!client.recovering) return null;
  return <div className="mt-2 text-[11.5px] text-warn" role="status">
    <span><span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-current border-r-transparent align-[-1px]" /> Автовосстановление{client.retry_count ? ` · попыток: ${client.retry_count}` : ""} · {recoveryPhaseLabel(client, Math.floor(Date.now() / 1000))}</span>
    {client.recovery_error && <div className="mt-0.5 [overflow-wrap:anywhere]">{client.recovery_error}</div>}
  </div>;
}

import type { AwgClientStatus } from "@/types/api";

export function peerActivityLabel(client: AwgClientStatus, now: number): string {
  const age = (timestamp: number) => {
    const seconds = Math.max(0, Math.floor(now - timestamp));
    if (seconds < 60) return `${seconds} с назад`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} мин назад`;
    return `${Math.floor(seconds / 3600)} ч назад`;
  };
  const handshake = client.last_handshake > 0 ? `Хендшейк ${age(client.last_handshake)}` : "Хендшейка ещё не было";
  return client.last_peer_activity && client.last_peer_activity > client.last_handshake
    ? `${handshake} · Входящий трафик ${age(client.last_peer_activity)}`
    : handshake;
}

export function recoveryPhaseLabel(client: AwgClientStatus, nowSeconds: number): string {
  if (client.checking_peer) return "ждём ответ пира";
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

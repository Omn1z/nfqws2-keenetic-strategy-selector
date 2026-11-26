import type { Awg2ServerSummary, AwgConnectionTestResult, AwgDoubleTunnelMode } from "@/types/api";

export const doubleTunnelModes: ReadonlyArray<{ value: AwgDoubleTunnelMode; label: string; hint: string }> = [
  { value: "permanent", label: "Постоянный", hint: "Основной AWG всегда подключается через выбранный внешний VPN." },
  { value: "preferred", label: "Резервный", hint: "При сбое прямого подключения роутер сначала пробует двойной туннель. Обычные резервы используются, если он недоступен." },
  { value: "last_resort", label: "Последний шанс", hint: "Двойной туннель используется после исчерпания прямых адресов и обычных резервов." },
  { value: "automatic", label: "Автоматически", hint: "После сбоя роутер сначала пробует двойной туннель и затем проверяет обычные резервы. Готовый резерв заменяет двойной путь." },
];

export function normalizeDoubleTunnelMode(mode: string | undefined): AwgDoubleTunnelMode {
  return doubleTunnelModes.find((option) => option.value === mode)?.value ?? "last_resort";
}

export function backupIDs(primary: string, ids: readonly string[]): string[] {
  return [...new Set(ids.map((id) => id.trim()).filter((id) => id && id !== primary))];
}

export function moveBackup(ids: readonly string[], index: number, direction: -1 | 1): string[] {
  const next = [...ids];
  const destination = index + direction;
  if (index < 0 || index >= ids.length || destination < 0 || destination >= ids.length) return next;
  [next[index], next[destination]] = [next[destination], next[index]];
  return next;
}

export function backupCreatesCycle(primary: string, candidate: string, servers: readonly Awg2ServerSummary[]): boolean {
  const byID = new Map(servers.map((server) => [server.id, server]));
  const seen = new Set<string>();
  const pending = [candidate];
  while (pending.length) {
    const id = pending.pop()!;
    if (id === primary) return true;
    if (seen.has(id)) continue;
    seen.add(id);
    pending.push(...(byID.get(id)?.failover?.fallback_tunnel_ids ?? []));
  }
  return false;
}

export function doubleTunnelCreatesCycle(primary: string, candidate: string, servers: readonly Awg2ServerSummary[]): boolean {
  const byID = new Map(servers.map((server) => [server.id, server]));
  const seen = new Set<string>();
  for (let id = candidate; id; id = byID.get(id)?.failover?.double_tunnel_id ?? "") {
    if (id === primary || seen.has(id)) return true;
    seen.add(id);
  }
  return false;
}

export function connectionTestPresentation(result: AwgConnectionTestResult): { label: string; kind: "ok" | "warn" | "bad" } {
  if (result.success && result.handshake && result.data_ok) return { label: "Связь подтверждена", kind: "ok" };
  if (result.handshake && result.data_ok) return { label: "Связь есть, проверка завершилась с ошибкой", kind: "warn" };
  if (result.handshake) return { label: "Handshake есть, передача данных не подтверждена", kind: "warn" };
  return { label: "Соединение не подтверждено", kind: "bad" };
}

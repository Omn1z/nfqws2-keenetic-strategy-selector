import type { Awg2ServerSummary, AwgConnectionTestResult } from "@/types/api";

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

export function connectionTestPresentation(result: AwgConnectionTestResult): { label: string; kind: "ok" | "warn" | "bad" } {
  if (result.success && result.handshake && result.data_ok) return { label: "Связь подтверждена", kind: "ok" };
  if (result.handshake && result.data_ok) return { label: "Связь есть, проверка завершилась с ошибкой", kind: "warn" };
  if (result.handshake) return { label: "Handshake есть, передача данных не подтверждена", kind: "warn" };
  return { label: "Соединение не подтверждено", kind: "bad" };
}

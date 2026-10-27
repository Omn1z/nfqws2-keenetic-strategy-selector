import { api } from "@/lib/api";
import type { Awg2ServerSummary, Awg2Status, AwgZone } from "@/types/api";

export interface DeleteConnectionSelection {
  mode: "transfer" | "waiting";
  replacementID: string;
}

export type DeleteConnectionResponse = Awg2Status & { warning?: string };

export function deleteConnectionCandidates(servers: readonly Awg2ServerSummary[], sourceID: string): Awg2ServerSummary[] {
  return servers.filter((server) => server.id !== sourceID).sort((a, b) =>
    Number(b.connected) - Number(a.connected) || Number(b.enabled) - Number(a.enabled));
}

export function initialDeleteConnectionSelection(servers: readonly Awg2ServerSummary[], sourceID: string): DeleteConnectionSelection {
  const candidates = deleteConnectionCandidates(servers, sourceID);
  const replacement = candidates.find((candidate) => !deletionWouldCreateCycle(servers, sourceID, candidate.id)) ?? candidates[0];
  return { mode: replacement ? "transfer" : "waiting", replacementID: replacement?.id ?? "" };
}

export function deleteConnectionReferences(st: Awg2Status, sourceID: string): {
  primaryRules: AwgZone[]; fallbackRules: AwgZone[]; connectionBackups: number;
} {
  const rules = st.routing_rules ?? st.routing_config?.zones ?? st.config.routing.zones ?? [];
  return {
    primaryRules: rules.filter((rule) => rule.tunnel_id === sourceID),
    fallbackRules: rules.filter((rule) => rule.tunnel_id !== sourceID && rule.fallback_tunnel_ids?.includes(sourceID)),
    connectionBackups: st.servers.filter((server) => server.id !== sourceID && server.failover?.fallback_tunnel_ids?.includes(sourceID)).length,
  };
}

// Replacing references can close a cycle even though both original profiles
// were valid. Use the graph after removal, with the backend's self/dedup rules.
export function deletionWouldCreateCycle(servers: readonly Awg2ServerSummary[], sourceID: string, replacementID: string): boolean {
  const inheritedBackups = servers.find((server) => server.id === sourceID)?.failover?.fallback_tunnel_ids ?? [];
  const graph = new Map(servers.filter((server) => server.id !== sourceID).map((server) => {
    const backups = [...(server.failover?.fallback_tunnel_ids ?? []), ...(server.id === replacementID ? inheritedBackups : [])];
    return [server.id, [...new Set(backups.map((id) => id === sourceID ? replacementID : id))].filter((id) => id !== server.id)];
  }));
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (id: string): boolean => {
    if (visiting.has(id)) return true;
    if (visited.has(id) || !graph.has(id)) return false;
    visiting.add(id);
    for (const next of graph.get(id)!) if (visit(next)) return true;
    visiting.delete(id);
    visited.add(id);
    return false;
  };
  return [...graph.keys()].some(visit);
}

export function deleteConnectionProblem(servers: readonly Awg2ServerSummary[], sourceID: string, selection: DeleteConnectionSelection): string {
  if (!servers.some((server) => server.id === sourceID)) return "Исходное подключение уже отсутствует. Закройте диалог и проверьте список VPN.";
  if (selection.mode === "waiting") return "";
  if (!selection.replacementID) return "Выберите подключение для переноса правил.";
  if (selection.replacementID === sourceID) return "Для переноса нужно другое подключение.";
  if (!servers.some((server) => server.id === selection.replacementID)) return "Выбранное подключение больше недоступно. Выберите другое или оставьте правила без подключения.";
  if (deletionWouldCreateCycle(servers, sourceID, selection.replacementID)) return "Перенос создаст цикл резервных подключений. Выберите другое подключение или измените резервные списки.";
  return "";
}

export async function deleteConnection(st: Awg2Status, sourceID: string, selection: DeleteConnectionSelection): Promise<DeleteConnectionResponse> {
  const problem = deleteConnectionProblem(st.servers, sourceID, selection);
  if (problem) throw new Error(problem);
  const query = selection.mode === "transfer" ? `?replacement_id=${encodeURIComponent(selection.replacementID)}` : "";
  return api<DeleteConnectionResponse>("DELETE", `/api/awg2/servers/${encodeURIComponent(sourceID)}${query}`);
}

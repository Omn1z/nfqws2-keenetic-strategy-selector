import { connFailing } from "@/lib/format";
import type { Sort } from "@/components/ui/Table";
import type { Conn } from "@/types/api";

export type ProtocolFilter = "all" | "tcp" | "udp" | "icmp";

const sortValue = (connection: Conn, key: string): string | number => {
  switch (key) {
    case "proto": return connection.proto;
    case "state": return connection.state || (connection.unreplied ? "UNREPLIED" : "");
    case "src": return connection.src;
    case "dst": return connection.dst;
    case "dport": return connection.dport;
    case "bytes": return connection.bytes + connection.reply_bytes;
    case "zone": return connection.zone;
    default: return 0;
  }
};

export function connectionRows(connections: Conn[], { query, failOnly, protocol, sort, hosts }: {
  query: string;
  failOnly: boolean;
  protocol: ProtocolFilter;
  sort: Sort;
  hosts: Record<string, string>;
}): Conn[] {
  const search = query.toLowerCase().trim();
  return connections.filter(connection => {
    if (failOnly && !connFailing(connection)) return false;
    const proto = connection.proto.toLowerCase();
    if (protocol !== "all" && (protocol === "icmp" ? !proto.startsWith("icmp") : proto !== protocol)) return false;
    return !search || [connection.proto, connection.state, connection.src, connection.dst, String(connection.dport || ""), connection.zone,
      connection.unreplied ? "UNREPLIED нет ответа" : "", hosts[connection.src] ?? "", hosts[connection.dst] ?? ""]
      .some(value => value.toLowerCase().includes(search));
  }).sort((a, b) => {
    const first = sortValue(a, sort.key), second = sortValue(b, sort.key);
    return first < second ? -sort.dir : first > second ? sort.dir : 0;
  });
}

export function connectionSummary(connections: Conn[]) {
  const protocols = { tcp: 0, udp: 0, icmp: 0, other: 0 };
  let failing = 0, established = 0;
  for (const connection of connections) {
    if (connFailing(connection)) failing++;
    if (connection.state === "ESTABLISHED") established++;
    const proto = connection.proto.toLowerCase();
    if (proto === "tcp" || proto === "udp") protocols[proto]++;
    else if (proto.startsWith("icmp")) protocols.icmp++;
    else protocols.other++;
  }
  return { total: connections.length, failing, established, protocols };
}

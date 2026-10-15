import type { AwgRoutingDiscoveredRule, AwgRoutingDiscoveries, AwgRoutingLearnedEntry, AwgZone } from "@/types/api";
import { ruleRoute } from "./routingRules";

export function routingDiscoveryCatchAll(rule: AwgZone): boolean {
  return rule.domains.some(domain => domain.trim() === "*") || rule.ips.some(ip => ["0.0.0.0/0", "::/0"].includes(ip.trim()));
}

/** Names, displayed priority and switches can change without changing scope. */
export function routingDiscoveryIdentity(rule: AwgZone): string {
  return JSON.stringify({
    route: ruleRoute(rule),
    tunnel_id: rule.tunnel_id ?? "",
    waiting_for_connection: rule.waiting_for_connection === true,
    fallback_tunnel_ids: rule.fallback_tunnel_ids ?? [],
    domains: rule.domains ?? [],
    include_subdomains: rule.include_subdomains ?? null,
    ips: rule.ips ?? [],
    source_ips: rule.source_ips ?? [],
  });
}

/** An index alone is unsafe after a reorder, edit, import or delayed read. */
export function matchingRoutingDiscovery(snapshot: AwgRoutingDiscoveries | null, rule: AwgZone, index: number): AwgRoutingDiscoveredRule | null {
  const observed = snapshot?.rules.find(item => item.rule_index === index);
  return observed && routingDiscoveryIdentity(observed.rule) === routingDiscoveryIdentity(rule) ? observed : null;
}

export function visibleRoutingDiscoveries(entries: AwgRoutingLearnedEntry[], showAll: boolean): AwgRoutingLearnedEntry[] {
  return entries.filter(entry => showAll || entry.additional).sort((a, b) => b.last_seen - a.last_seen || a.domain.localeCompare(b.domain));
}

export function routingDiscoveryConfirmed(snapshot: AwgRoutingDiscoveries, entry: AwgRoutingLearnedEntry): boolean {
  return snapshot.active && snapshot.ready && entry.confirmed;
}

export function routingDiscoveryTime(value: number): { label: string; dateTime?: string } {
  if (!Number.isFinite(value) || value <= 0) return { label: "—" };
  const date = new Date(value * 1000);
  if (!Number.isFinite(date.getTime())) return { label: "—" };
  return { label: date.toLocaleString("ru-RU", { hour12: false }), dateTime: date.toISOString() };
}

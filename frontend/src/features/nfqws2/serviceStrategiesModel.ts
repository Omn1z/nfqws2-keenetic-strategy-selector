export type ServiceGroupKind = "domains" | "ips";

export interface ServiceGroup {
  id: string;
  name: string;
  kind: ServiceGroupKind;
  entries: string[];
  strategy: string;
}

export interface ServiceStrategy {
  id: string;
  name: string;
  enabled: boolean;
  groups: ServiceGroup[];
}

export interface ServicePreview {
  tcp_ports: string;
  udp_ports: string;
  profiles: number;
  warnings: string[];
  args: string;
}

export interface ServiceState extends Omit<ServicePreview, "args"> {
  services: ServiceStrategy[];
  revision: string;
  restart_required: boolean;
}

export interface DomainCheckResult {
  domain: string;
  ok: boolean;
  detail: string;
  ms: number;
}

let serviceIDSequence = 0;
/** Router UIs often use plain HTTP, where crypto.randomUUID is unavailable. */
export function newServiceID(cryptoSource: { randomUUID?: () => string } | undefined = globalThis.crypto): string {
  return cryptoSource?.randomUUID ? cryptoSource.randomUUID() : `service-${Date.now().toString(36)}-${(++serviceIDSequence).toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/** Keep raw textarea lines in the draft; normalize only at the API boundary. */
export function serviceEntries(entries: string[]): string[] {
  return [...new Set(entries.flatMap(entry => entry.split(/\r?\n/)).map(entry => entry.trim()).filter(entry => entry && !entry.startsWith("#")))];
}

export function servicesPayload(services: ServiceStrategy[]): ServiceStrategy[] {
  return services.map(service => ({
    ...service,
    name: service.name.trim(),
    groups: service.groups.map(group => ({ ...group, name: group.name.trim(), entries: serviceEntries(group.entries), strategy: group.strategy.trim() })),
  }));
}

/** A zone also matches subdomains, but HTTPS needs one concrete host to probe. */
export function serviceCheckDomains(service: ServiceStrategy | undefined): string[] {
  if (!service) return [];
  return [...new Set(service.groups.filter(group => group.kind === "domains").flatMap(group => serviceEntries(group.entries))
    .map(domain => domain.toLowerCase().replace(/^\*\./, "").replace(/^\./, "").replace(/\.$/, "")))];
}

export function newServiceGroup(kind: ServiceGroupKind, id: string, ordinal = 1): ServiceGroup {
  return { id, kind, name: `${kind === "domains" ? "Домены" : "IP-зоны"}${ordinal > 1 ? ` ${ordinal}` : ""}`, entries: [], strategy: "" };
}

export function servicesSignature(services: ServiceStrategy[]): string {
  return JSON.stringify(servicesPayload(services));
}

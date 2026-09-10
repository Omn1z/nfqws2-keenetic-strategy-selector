import type { DnsServerRule, DnsServerUpstream } from "@/types/api";
import type { UpstreamForm } from "./UpstreamPool";

export type RuleGroupForm = {
  id: string;
  enabled: boolean;
  include_subdomains: boolean;
  pool: UpstreamForm[];
  domains: string;
  rule_ids: Record<string, string>;
};

const MAX_DOMAINS = 512;
const upstreamForm = (v: DnsServerUpstream): UpstreamForm => ({ address: v.address, bootstrap: (v.bootstrap_ips ?? []).join(", ") });
const collectUpstream = (v: UpstreamForm): DnsServerUpstream => ({ address: v.address.trim(), bootstrap_ips: v.bootstrap.split(/[\s,;]+/).filter(Boolean) });

function normalizeRuleDomain(value: string): string {
  let domain = value.trim().toLowerCase();
  if (!domain || /[\s/:?#@%\\\[\]*]/.test(domain)) throw new Error(`Некорректный домен «${value}»: укажите имя без URL, пути и маски.`);
  // URL applies browser IDNA conversion; avoid its IPv4 shorthand expansion
  // for ASCII DNS names, which must keep the server's existing semantics.
  if (/[^\x00-\x7f]/.test(domain)) {
    try { domain = new URL(`http://${domain}`).hostname; }
    catch { throw new Error(`Некорректный домен «${value}».`); }
  }
  domain = domain.replace(/\.$/, "");
  if (!domain || domain.length > 253 || domain.split(".").some((label) => !label || label.length > 63 || !/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/.test(label))) {
    throw new Error(`Некорректный домен «${value}».`);
  }
  return domain;
}

function parseDomains(value: string): string[] {
  const domains = new Set<string>();
  for (const token of value.split(/[\s,;]+/).filter(Boolean)) domains.add(normalizeRuleDomain(token));
  return [...domains];
}

export function newRuleGroup(pool?: UpstreamForm[]): RuleGroupForm {
  return {
    id: `dns-group-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
    enabled: true, include_subdomains: true,
    pool: pool?.length ? pool.map((v) => ({ ...v })) : [{ address: "", bootstrap: "" }],
    domains: "", rule_ids: Object.create(null),
  };
}

// Group only identical routing settings. In particular a disabled rule or a
// different subdomain policy must not silently inherit another rule's flags.
export function groupRules(rules: DnsServerRule[]): RuleGroupForm[] {
  const grouped = new Map<string, RuleGroupForm>();
  for (const rule of rules) {
    const providers = [rule.upstream, ...(rule.pool ?? [])];
    const key = JSON.stringify([rule.enabled, rule.include_subdomains, providers.map((v) => [v.address, v.bootstrap_ips ?? []])]);
    let group = grouped.get(key);
    if (!group) {
      group = { id: rule.id, enabled: rule.enabled, include_subdomains: rule.include_subdomains, pool: providers.map(upstreamForm), domains: "", rule_ids: Object.create(null) };
      grouped.set(key, group);
    }
    const domain = normalizeRuleDomain(rule.domain);
    group.domains += `${group.domains ? "\n" : ""}${domain}`;
    group.rule_ids[domain] = rule.id;
  }
  return [...grouped.values()];
}

// Keep the established flat API/storage format. Existing tabs, backups and the
// resolver retain exactly the same per-domain matching and pool isolation.
export function collectRuleGroups(groups: RuleGroupForm[]): DnsServerRule[] {
  const result: DnsServerRule[] = [];
  const enabledDomains = new Set<string>();
  const ids = new Set<string>();
  for (const [index, group] of groups.entries()) {
    const domains = parseDomains(group.domains);
    if (!domains.length) throw new Error(`Группа ${index + 1}: укажите хотя бы один домен.`);
    if (result.length + domains.length > MAX_DOMAINS) throw new Error(`Не более ${MAX_DOMAINS} доменов во всех группах.`);
    if (!group.pool.length || group.pool.some((v) => !v.address.trim())) throw new Error(`Группа ${index + 1}: укажите адрес DoH для каждого сервера пула.`);
    for (const domain of domains) {
      if (group.enabled && enabledDomains.has(domain)) throw new Error(`Домен «${domain}» указан в нескольких включённых группах.`);
      if (group.enabled) enabledDomains.add(domain);
      let id = Object.prototype.hasOwnProperty.call(group.rule_ids, domain) ? group.rule_ids[domain] : `${group.id}-${domain}`;
      const baseID = id;
      for (let suffix = 2; ids.has(id); suffix++) id = `${baseID}-${suffix}`;
      ids.add(id);
      const [upstream, ...pool] = group.pool.map(collectUpstream);
      result.push({ id, enabled: group.enabled, include_subdomains: group.include_subdomains, domain, upstream, pool });
    }
  }
  return result;
}

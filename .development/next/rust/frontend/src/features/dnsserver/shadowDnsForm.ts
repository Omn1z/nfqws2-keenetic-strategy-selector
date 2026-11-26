import type { DnsServerStatus, DnsShadowConfig, DnsShadowDomain } from "@/types/api";

export const SHADOW_DOMAIN_LIMIT = 4096;
export const SHADOW_ROUTE_LABEL = "Shadow DNS → провайдер";
export type ShadowForm = { enabled: boolean; patterns: string };

export function defaultShadowDomains(): DnsShadowDomain[] {
  return ["ru", "xn--p1ai", "vk.*", "avito.*"].map((domain) => ({ domain, include_subdomains: true }));
}

export function shadowForm(value?: DnsShadowConfig): ShadowForm {
  const domains = value?.domains ?? defaultShadowDomains();
  return { enabled: value?.enabled ?? false, patterns: domains.map((rule) => `${rule.include_subdomains ? "*." : ""}${rule.domain.replace(/(^|\.)xn--p1ai(?=\.|$)/g, "$1рф")}`).join("\n") };
}

function normalizeShadowDomain(value: DnsShadowDomain): DnsShadowDomain {
  const original = value.domain;
  let domain = original.trim().toLowerCase();
  const suffix = domain.startsWith("*.") || domain.startsWith(".");
  if (domain.startsWith("*.")) domain = domain.slice(2);
  else if (domain.startsWith(".")) domain = domain.slice(1);
  domain = domain.replace(/\.$/, "");
  if (!domain || /[\s/:?#@%\\\[\]]/.test(domain)) throw new Error(`Shadow DNS: некорректный домен «${original}». Укажите домен без URL или пути.`);
  let anchored = false;
  const labels = domain.split(".").map((label) => {
    if (label === "*") return label;
    anchored = true;
    if (/[^\x00-\x7f]/.test(label)) {
      try { label = new URL(`http://${label}`).hostname; }
      catch { throw new Error(`Shadow DNS: некорректный домен «${original}».`); }
    }
    if (!label || label.length > 63 || !/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/.test(label)) throw new Error(`Shadow DNS: некорректный домен «${original}».`);
    return label;
  });
  domain = labels.join(".");
  if (!anchored || domain.length > 253) {
    throw new Error(`Shadow DNS: некорректный домен «${original}».`);
  }
  return { domain, include_subdomains: suffix || value.include_subdomains };
}

export function collectShadowDomains(rules: DnsShadowDomain[]): DnsShadowDomain[] {
  const unique = new Map<string, DnsShadowDomain>();
  for (const value of rules) {
    const next = normalizeShadowDomain(value);
    const previous = unique.get(next.domain);
    if (previous) previous.include_subdomains ||= next.include_subdomains;
    else unique.set(next.domain, next);
    if (unique.size > SHADOW_DOMAIN_LIMIT) throw new Error(`Shadow DNS: не более ${SHADOW_DOMAIN_LIMIT} доменов.`);
  }
  return [...unique.values()];
}

export function appendShadowDomains(existing: DnsShadowDomain[], text: string, includeSubdomains: boolean): DnsShadowDomain[] {
  const additions = text.split(/[\s,;]+/).filter(Boolean).map((domain) => ({ domain, include_subdomains: includeSubdomains }));
  return collectShadowDomains([...existing, ...additions]);
}

export function collectShadow(form: ShadowForm): DnsShadowConfig {
  const domains = appendShadowDomains([], form.patterns, false);
  if (form.enabled && !domains.length) throw new Error("Shadow DNS: добавьте хотя бы один домен.");
  return { enabled: form.enabled, servers: [], domains };
}

export function dnsRouteLabel(id: string | undefined, routes: DnsServerStatus["routes"] = []): string {
  if (id === "shadow") return SHADOW_ROUTE_LABEL;
  return routes.find((route) => route.id === id)?.name || (id === "nfqws" ? "NFQWS" : id === "cache" ? "Кэш" : id === "blocked" ? "Локальная блокировка" : id || "—");
}

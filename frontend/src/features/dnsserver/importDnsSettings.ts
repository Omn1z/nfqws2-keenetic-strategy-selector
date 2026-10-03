import type { DnsSettingsImportPlan, DnsSettingsImportRequest } from "@/types/api";

export const DNS_SETTINGS_FILE_LIMIT = 16 * 1024 * 1024;

// Keep the original document intact; only the router validates and normalizes
// saved settings, including fields introduced by a newer UI.
export function parseDnsSettingsDocument(text: string): void {
  if (new TextEncoder().encode(text).byteLength > DNS_SETTINGS_FILE_LIMIT) throw new Error("Файл настроек DNS превышает 16 МиБ.");
  let value: unknown;
  try { value = JSON.parse(text.replace(/^\uFEFF/, "")); }
  catch { throw new Error("Файл не содержит корректный JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Выберите JSON экспорта DNS Server.");
  const doc = value as Record<string, unknown>;
  if (doc.format !== "nfqws2-strategy-dnsserver" || doc.version !== 1 || !doc.config || typeof doc.config !== "object" || Array.isArray(doc.config)) {
    throw new Error("Неподдерживаемый формат или версия экспорта DNS Server.");
  }
}

export function initialDnsImportMapping(plan: DnsSettingsImportPlan): string {
  return plan.vpn.state === "matched" ? plan.vpn.matched_id ?? "" : "";
}

export function buildDnsImportRequest(document: string, plan: DnsSettingsImportPlan, mapping: string): DnsSettingsImportRequest {
  parseDnsSettingsDocument(document);
  if (!plan.base_hash) throw new Error("Сначала обновите предварительный просмотр.");
  const request: DnsSettingsImportRequest = { document, base_hash: plan.base_hash };
  if (["auto", "off"].includes(plan.vpn.state)) return request;
  const candidate = plan.vpn.candidates.find((v) => v.ref === mapping);
  if (!candidate || !candidate.fingerprint) throw new Error("Выберите VPN-подключение для импортируемых настроек.");
  request.mapping = candidate.ref;
  request.mapping_fingerprint = candidate.fingerprint;
  return request;
}

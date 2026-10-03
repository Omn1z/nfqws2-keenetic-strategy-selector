import type { AwgRoutingConfig, AwgRulesDocument, AwgRulesImportMode, AwgRulesImportPlan, AwgRulesImportRequest, AwgRulesMappings, AwgZone } from "@/types/api";

export const RULES_FILE_LIMIT = 2 * 1024 * 1024;

export const ruleRoute = (z: AwgZone) => z.route === "direct" || (z.route !== "tunnel" && z.mode === "exclude") ? "direct" : "tunnel";

export const ruleWaiting = (zone: AwgZone, tunnelIDs: ReadonlySet<string>) =>
  !!zone.waiting_for_connection || (zone.tunnel_id ? !tunnelIDs.has(zone.tunnel_id) : ruleRoute(zone) === "tunnel");

/** Existing rules never acquire the currently selected profile implicitly. */
export const prepareRuleConnection = (zone: AwgZone, tunnelIDs: ReadonlySet<string>): AwgZone => ({
  ...zone,
  tunnel_id: zone.tunnel_id || "",
  waiting_for_connection: ruleWaiting(zone, tunnelIDs),
  fallback_tunnel_ids: (zone.fallback_tunnel_ids || []).map((id) => id.trim())
    .filter((id, i, all) => id && id !== zone.tunnel_id && all.indexOf(id) === i),
});

export function parseRulesDocument(text: string): AwgRulesDocument {
  if (new TextEncoder().encode(text).byteLength > RULES_FILE_LIMIT) throw new Error("Файл правил превышает 2 МиБ.");
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new Error("Файл не содержит корректный JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Неверный формат файла правил.");
  const doc = value as Partial<AwgRulesDocument>;
  if (doc.format !== "nfqws2-strategy-routing" || doc.version !== 1 ||
      !doc.routing || !Array.isArray(doc.routing.zones) || !Array.isArray(doc.connections)) {
    throw new Error("Нужен экспорт правил NFQWS2 Strategy версии 1.");
  }
  const refs = new Set<string>();
  for (const connection of doc.connections) {
    if (!connection || typeof connection.ref !== "string" || !connection.ref.trim() || refs.has(connection.ref)) {
      throw new Error("В файле отсутствует ссылка на подключение или ссылки повторяются.");
    }
    refs.add(connection.ref);
  }
  return doc as AwgRulesDocument;
}

/** Trust only an exact unique match already verified by the backend preview. */
export function initialRuleMappings(plan: AwgRulesImportPlan): AwgRulesMappings {
  const mappings: AwgRulesMappings = Object.create(null);
  for (const item of plan.connections) {
    const exact = item.candidates.filter((candidate) => candidate.fingerprint && candidate.fingerprint === item.source.fingerprint);
    if (item.state === "matched" && !item.reason && item.source.fingerprint && item.matched_tunnel_id &&
        exact.length === 1 && exact[0].id === item.matched_tunnel_id) {
      mappings[item.source.ref] = item.matched_tunnel_id;
    }
  }
  return mappings;
}

export function validatedRuleMappings(plan: AwgRulesImportPlan, mappings: AwgRulesMappings, targetIDs: ReadonlySet<string>): AwgRulesMappings {
  const result: AwgRulesMappings = Object.create(null);
  for (const item of plan.connections) {
    const ref = item.source.ref;
    if (!Object.hasOwn(mappings, ref)) throw new Error(`Выберите подключение для «${item.source.label || ref}» или оставьте правило в ожидании.`);
    const target = mappings[ref];
    if (typeof target !== "string" || (target !== "" && !targetIDs.has(target))) {
      throw new Error(`Выбранное подключение для «${item.source.label || ref}» больше недоступно. Повторите выбор.`);
    }
    if (target && !item.candidates.some((candidate) => candidate.id === target && candidate.fingerprint)) {
      throw new Error(`Для «${item.source.label || ref}» нет подтверждённых параметров выбранного VPN. Повторно проверьте файл.`);
    }
    result[ref] = target;
  }
  return result;
}

export function ruleMappingFingerprints(plan: AwgRulesImportPlan, mappings: AwgRulesMappings): Record<string, string> {
  const result: Record<string, string> = Object.create(null);
  for (const item of plan.connections) {
    const target = mappings[item.source.ref];
    if (target) {
      const fingerprint = item.candidates.find((candidate) => candidate.id === target)?.fingerprint;
      if (!fingerprint) throw new Error("Повторно проверьте файл: параметры выбранного подключения не подтверждены.");
      result[item.source.ref] = fingerprint;
    }
  }
  return result;
}

export function captureRoutingDraft(routing: AwgRoutingConfig, tunnelIDs: ReadonlySet<string>): AwgRoutingConfig {
  // Detach the base from later status updates and omit private Symbol metadata.
  return JSON.parse(JSON.stringify({ ...routing, zones: routing.zones.map((zone) => prepareRuleConnection(zone, tunnelIDs)) })) as AwgRoutingConfig;
}

export function refreshedRuleMappings(previous: AwgRulesImportPlan, mappings: AwgRulesMappings, next: AwgRulesImportPlan): AwgRulesMappings {
  const result = initialRuleMappings(next);
  for (const item of next.connections) {
    const ref = item.source.ref;
    if (!Object.hasOwn(mappings, ref)) continue;
    const target = mappings[ref];
    if (target === "") { result[ref] = ""; continue; }
    const before = previous.connections.find((entry) => entry.source.ref === ref)?.candidates.find((entry) => entry.id === target)?.fingerprint;
    const after = item.candidates.find((entry) => entry.id === target)?.fingerprint;
    if (before && before === after) result[ref] = target;
  }
  return result;
}

export function buildRuleImportRequest(document: string, plan: AwgRulesImportPlan, mappings: AwgRulesMappings,
  targetIDs: ReadonlySet<string>, mode: AwgRulesImportMode, base: AwgRoutingConfig): AwgRulesImportRequest {
  if (!plan.policy_hash) throw new Error("Повторно проверьте файл: версия текущих правил не подтверждена.");
  const resolved = validatedRuleMappings(plan, mappings, targetIDs);
  return { document, mappings: resolved, mapping_fingerprints: ruleMappingFingerprints(plan, resolved), mode,
    ...(mode === "append" ? { base_routing: base } : {}), expected_policy_hash: plan.policy_hash };
}

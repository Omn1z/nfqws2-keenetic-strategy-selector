import assert from "node:assert/strict";
import test from "node:test";
import type { AwgRoutingConfig, AwgRulesImportPlan, AwgZone } from "@/types/api";
import { buildRuleImportRequest, captureRoutingDraft, initialRuleMappings, parseRulesDocument, prepareRuleConnection, refreshedRuleMappings, RULES_FILE_LIMIT, ruleMappingFingerprints, validatedRuleMappings } from "./routingRules";

const zone = (): AwgZone => ({ name: "video", route: "tunnel", tunnel_id: "deleted", waiting_for_connection: true,
  domains: ["full:example.com", "list:user"], include_subdomains: false, ips: ["203.0.113.0/24"],
  source_ips: ["192.168.3.2"], fallback_tunnel_ids: ["missing-backup", "live-backup"], enabled: true, order: 5 });

function plan(state: "matched" | "missing" | "ambiguous" = "matched"): AwgRulesImportPlan {
  return { rule_count: 1, waiting_rule_count: 0, policy_hash: "original-policy", connections: [{ source: { ref: "old", label: "Germany", fingerprint: "server-a" },
    state, matched_tunnel_id: state === "matched" ? "live" : undefined,
    candidates: [{ id: "live", label: "Germany", fingerprint: "server-a" }, { id: "another", label: "France", fingerprint: "server-b" }] }] };
}

test("editing a waiting rule keeps its deleted primary and missing backup references without selecting another VPN", () => {
  const original = zone();
  const result = prepareRuleConnection(original, new Set(["selected-new", "live-backup"]));
  assert.deepEqual(result, original);
  assert.notEqual(result.fallback_tunnel_ids, original.fallback_tunnel_ids);
});

test("an unknown or empty primary becomes waiting while explicit selection is required even if its ID reappears", () => {
  const original = zone();
  assert.equal(prepareRuleConnection({ ...original, waiting_for_connection: false }, new Set(["another"])).waiting_for_connection, true);
  assert.equal(prepareRuleConnection({ ...original, tunnel_id: "" }, new Set(["another"])).tunnel_id, "");
  assert.equal(prepareRuleConnection(original, new Set(["deleted"])).waiting_for_connection, true);
  const assigned = prepareRuleConnection({ ...original, tunnel_id: "chosen", waiting_for_connection: false }, new Set(["chosen"]));
  assert.equal(assigned.waiting_for_connection, false);
  assert.equal(assigned.tunnel_id, "chosen");
  assert.deepEqual(assigned.fallback_tunnel_ids, original.fallback_tunnel_ids);
});

test("direct rules retain explicit waiting and deleted owner references, while an ownerless direct rule can remain standalone", () => {
  const original = zone();
  const result = prepareRuleConnection({ ...original, route: "direct" }, new Set());
  assert.equal(result.waiting_for_connection, true);
  assert.deepEqual(result.fallback_tunnel_ids, original.fallback_tunnel_ids);
  assert.equal(prepareRuleConnection({ ...original, route: "direct", waiting_for_connection: false }, new Set()).waiting_for_connection, true);
  assert.equal(prepareRuleConnection({ ...original, route: "direct", tunnel_id: "", waiting_for_connection: false }, new Set()).waiting_for_connection, false);
  assert.equal(prepareRuleConnection({ ...original, route: "direct", tunnel_id: "live", waiting_for_connection: false }, new Set(["live"])).waiting_for_connection, false);
});

test("only one exact complete fingerprint match selects a connection automatically, even across different local IDs", () => {
  assert.equal(initialRuleMappings(plan()).old, "live");
  const incomplete = plan();
  incomplete.connections[0].source.fingerprint = "";
  assert.equal(Object.hasOwn(initialRuleMappings(incomplete), "old"), false);
  const duplicate = plan();
  duplicate.connections[0].candidates[1].fingerprint = "server-a";
  assert.equal(Object.hasOwn(initialRuleMappings(duplicate), "old"), false);
  assert.equal(Object.hasOwn(initialRuleMappings(plan("ambiguous")), "old"), false);
});

test("same ID or name with a changed server never auto-selects and an explicit remap pins the target fingerprint", () => {
  const changed = plan("missing");
  changed.connections[0].reason = "identity_changed";
  changed.connections[0].source.ref = "live";
  changed.connections[0].candidates[0].fingerprint = "server-new";
  assert.equal(Object.hasOwn(initialRuleMappings(changed), "live"), false);
  const mappings = validatedRuleMappings(changed, { live: "live" }, new Set(["live"]));
  assert.equal(ruleMappingFingerprints(changed, mappings).live, "server-new");
});

test("every unresolved connection needs an explicit mapping or an explicit wait, including prototype-looking refs", () => {
  const preview = plan("missing");
  assert.throws(() => validatedRuleMappings(preview, {}, new Set(["live"])), /Выберите подключение/);
  const waiting = validatedRuleMappings(preview, { old: "" }, new Set(["live"]));
  assert.equal(waiting.old, "");
  assert.deepEqual(Object.keys(ruleMappingFingerprints(preview, waiting)), []);
  preview.connections[0].source.ref = "__proto__";
  assert.throws(() => validatedRuleMappings(preview, {}, new Set(["live"])), /Выберите подключение/);
  const explicit = { ["__proto__"]: "" };
  assert.equal(validatedRuleMappings(preview, explicit, new Set())["__proto__"], "");
});

test("a removed or incomplete selected target rejects import without changing the plan, mapping or current rules", () => {
  const preview = plan();
  const currentRules = Object.freeze([Object.freeze(zone())]);
  const mappings = Object.freeze({ old: "live" });
  const snapshot = JSON.stringify({ preview, currentRules, mappings });
  assert.throws(() => validatedRuleMappings(preview, mappings, new Set()), /больше недоступно/);
  assert.equal(JSON.stringify({ preview, currentRules, mappings }), snapshot);
  preview.connections[0].candidates[0].fingerprint = "";
  assert.throws(() => validatedRuleMappings(preview, mappings, new Set(["live"])), /нет подтверждённых параметров/);
  assert.equal(mappings.old, "live");
  assert.equal(currentRules[0].tunnel_id, "deleted");
});

test("file validation rejects malformed, oversized, unsupported and duplicate-reference documents before preview", () => {
  const document = { format: "nfqws2-strategy-routing", version: 1, routing: { zones: [zone()] }, connections: [{ ref: "old" }] };
  assert.equal(parseRulesDocument(JSON.stringify(document)).routing.zones[0].tunnel_id, "deleted");
  assert.throws(() => parseRulesDocument("{oops"), /корректный JSON/);
  assert.throws(() => parseRulesDocument(JSON.stringify({ ...document, version: 2 })), /версии 1/);
  assert.throws(() => parseRulesDocument(JSON.stringify({ ...document, connections: [{ ref: "old" }, { ref: "old" }] })), /повторяются/);
  assert.throws(() => parseRulesDocument(" ".repeat(RULES_FILE_LIMIT + 1)), /превышает 2 МиБ/);
});

test("append retries keep the same detached draft base and policy hash after later status updates", () => {
  const visible: AwgRoutingConfig = { mode: "zones", zones: [zone()], mtu: 1420, killswitch: true, domain_source: "dnsproxy" };
  const captured = captureRoutingDraft(visible, new Set(["live"]));
  const preview = plan();
  const mappings = initialRuleMappings(preview);
  const first = buildRuleImportRequest("raw document", preview, mappings, new Set(["live"]), "append", captured);
  visible.zones.push({ ...zone(), name: "a later status rule" });
  visible.zones[0].domains.push("a-later-edit.example");
  visible.killswitch = false;
  const retry = buildRuleImportRequest("raw document", preview, mappings, new Set(["live"]), "append", captured);
  assert.deepEqual(retry, first);
  assert.equal(retry.base_routing?.zones.length, 1);
  assert.equal(retry.base_routing?.killswitch, true);
  assert.equal(retry.base_routing?.zones[0].domains.includes("a-later-edit.example"), false);
  assert.equal(retry.expected_policy_hash, "original-policy");
  assert.equal(Object.hasOwn(buildRuleImportRequest("raw document", preview, mappings, new Set(["live"]), "replace", captured), "base_routing"), false);
});

test("repreview retains explicit wait and unchanged manual mappings but drops a target whose identity changed", () => {
  const old = plan("missing");
  assert.equal(refreshedRuleMappings(old, { old: "another" }, plan("missing")).old, "another");
  const changed = plan("missing");
  changed.connections[0].candidates[1].fingerprint = "another-new-server";
  assert.equal(Object.hasOwn(refreshedRuleMappings(old, { old: "another" }, changed), "old"), false);
  assert.equal(refreshedRuleMappings(old, { old: "" }, changed).old, "");
});

test("an incomplete preview cannot produce a destructive import request", () => {
  const incomplete = { ...plan(), policy_hash: "" };
  const base: AwgRoutingConfig = { mode: "off", zones: [], mtu: 1420, killswitch: false, domain_source: "resolve" };
  assert.throws(() => buildRuleImportRequest("raw", incomplete, { old: "live" }, new Set(["live"]), "replace", base), /версия текущих правил не подтверждена/);
  assert.deepEqual(base.zones, []);
});

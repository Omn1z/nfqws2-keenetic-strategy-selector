import assert from "node:assert/strict";
import test from "node:test";
import type { DnsSettingsImportPlan } from "@/types/api";
import { buildDnsImportRequest, DNS_SETTINGS_FILE_LIMIT, initialDnsImportMapping, parseDnsSettingsDocument } from "./importDnsSettings";

const document = JSON.stringify({ format: "nfqws2-strategy-dnsserver", version: 1, config: { enabled: false } });
const candidate = { ref: "local-vpn", fingerprint: "same-server-interface", label: "VPN", endpoint: "192.0.2.1:443", client_iface: "awg0", protocol: "amneziawg" };
const plan = { base_hash: "saved-state", vpn: { source_id: "foreign-vpn", state: "selection_required", candidates: [candidate] } } as DnsSettingsImportPlan;

test("DNS import accepts old exports and UTF-8 BOM but rejects unrelated documents and versions", () => {
  parseDnsSettingsDocument(document);
  parseDnsSettingsDocument("\uFEFF" + document);
  for (const text of ["[", "null", "[]", "{}", document.replace('"version":1', '"version":2'), document.replace("nfqws2-strategy-dnsserver", "routing-rules")]) {
    assert.throws(() => parseDnsSettingsDocument(text));
  }
});
test("DNS import bounds UTF-8 bytes, not JS string length", () => {
  const oversized = JSON.stringify({ format: "nfqws2-strategy-dnsserver", version: 1, config: { x: "я".repeat(DNS_SETTINGS_FILE_LIMIT / 2) } });
  assert.ok(oversized.length < DNS_SETTINGS_FILE_LIMIT);
  assert.throws(() => parseDnsSettingsDocument(oversized), /16 МиБ/);
});
test("legacy or mismatched VPN IDs never become an automatic selection", () => {
  assert.equal(initialDnsImportMapping(plan), "");
  assert.throws(() => buildDnsImportRequest(document, plan, ""), /Выберите VPN/);
  assert.throws(() => buildDnsImportRequest(document, plan, "foreign-vpn"), /Выберите VPN/);
  const before = JSON.stringify(plan);
  assert.deepEqual(buildDnsImportRequest(document, plan, "local-vpn"), { document, base_hash: "saved-state", mapping: "local-vpn", mapping_fingerprint: "same-server-interface" });
  assert.equal(JSON.stringify(plan), before);
});
test("matched VPN selection is bound to its current fingerprint and a preview base", () => {
  const matched = { ...plan, vpn: { ...plan.vpn, state: "matched" as const, matched_id: "local-vpn" } };
  assert.equal(initialDnsImportMapping(matched), "local-vpn");
  assert.throws(() => buildDnsImportRequest(document, { ...matched, base_hash: "" }, "local-vpn"), /предварительный/);
  assert.throws(() => buildDnsImportRequest(document, { ...matched, vpn: { ...matched.vpn, candidates: [] } }, "local-vpn"), /Выберите VPN/);
});
test("auto and off import preserve their mode and do not invent a concrete VPN", () => {
  for (const state of ["auto", "off"] as const) {
    const current = { ...plan, vpn: { ...plan.vpn, state } };
    assert.deepEqual(buildDnsImportRequest(document, current, "local-vpn"), { document, base_hash: "saved-state" });
  }
});

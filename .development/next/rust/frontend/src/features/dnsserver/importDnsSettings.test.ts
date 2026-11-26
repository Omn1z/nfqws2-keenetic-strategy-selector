import assert from "node:assert/strict";
import test from "node:test";
import type { DnsSettingsImportPlan } from "@/types/api";
import { buildDnsImportRequest, DNS_SETTINGS_FILE_LIMIT, initialDnsImportMapping, parseDnsSettingsDocument } from "./importDnsSettings";

const document = JSON.stringify({ format: "nfqws2-strategy-dnsserver", version: 1, config: { enabled: false } });
const candidate = { ref: "local-vpn", fingerprint: "same-server-interface", label: "VPN", endpoint: "192.0.2.1:443", client_iface: "awg0", protocol: "amneziawg" };
const plan = { base_hash: "saved-state", config: { route_mode: "auto" }, vpn: { source_id: "foreign-vpn", state: "selection_required", candidates: [candidate] } } as DnsSettingsImportPlan;

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
test("legacy, missing and ambiguous VPN identities default to local auto without trusting IDs", () => {
  for (const state of ["selection_required", "missing", "ambiguous"] as const) {
    const current = { ...plan, vpn: { ...plan.vpn, state, candidates: [{ ...candidate, ref: "foreign-vpn" }] } };
    assert.equal(initialDnsImportMapping(current), "auto");
    assert.deepEqual(buildDnsImportRequest(document, current, initialDnsImportMapping(current)), { document, base_hash: "saved-state", mapping: "auto" });
  }
  assert.throws(() => buildDnsImportRequest(document, plan, ""), /Выберите «Автоматически»/);
  assert.throws(() => buildDnsImportRequest(document, plan, "foreign-vpn"), /Выберите «Автоматически»/);
  const before = JSON.stringify(plan);
  assert.deepEqual(buildDnsImportRequest(document, plan, "local-vpn"), { document, base_hash: "saved-state", mapping: "local-vpn", mapping_fingerprint: "same-server-interface" });
  assert.equal(JSON.stringify(plan), before);
});
test("matched VPN selection is bound to its current fingerprint and a preview base", () => {
  const matched = { ...plan, vpn: { ...plan.vpn, state: "matched" as const, matched_id: "local-vpn" } };
  assert.equal(initialDnsImportMapping(matched), "local-vpn");
  assert.throws(() => buildDnsImportRequest(document, { ...matched, base_hash: "" }, "local-vpn"), /предварительный/);
  assert.throws(() => buildDnsImportRequest(document, { ...matched, vpn: { ...matched.vpn, candidates: [] } }, "local-vpn"), /Выберите «Автоматически»/);
});
test("auto and off defaults are preserved but can be replaced with a local VPN", () => {
  for (const state of ["auto", "off"] as const) {
    const current = { ...plan, vpn: { ...plan.vpn, state } };
    assert.equal(initialDnsImportMapping(current), state);
    assert.deepEqual(buildDnsImportRequest(document, current, state), { document, base_hash: "saved-state", mapping: state });
    assert.deepEqual(buildDnsImportRequest(document, current, "local-vpn"), { document, base_hash: "saved-state", mapping: "local-vpn", mapping_fingerprint: candidate.fingerprint });
  }
});

test("import remains possible when the target router has no configured VPN", () => {
  for (const state of ["auto", "missing", "selection_required", "ambiguous", "matched"] as const) {
    const current = { ...plan, vpn: { ...plan.vpn, state, matched_id: "gone", candidates: [] } };
    const mapping = initialDnsImportMapping(current);
    assert.equal(mapping, "auto");
    assert.deepEqual(buildDnsImportRequest(document, current, mapping), { document, base_hash: "saved-state", mapping: "auto" });
  }
});

test("confirmed VPN can be changed to auto without carrying its fingerprint", () => {
  const current = { ...plan, vpn: { ...plan.vpn, state: "matched" as const, matched_id: candidate.ref } };
  assert.deepEqual(buildDnsImportRequest(document, current, "auto"), { document, base_hash: "saved-state", mapping: "auto" });
});

test("automatic migration preserves VPN-only mode and cannot disable it", () => {
  const current = { ...plan, config: { ...plan.config, route_mode: "vpn_only" as const }, vpn: { ...plan.vpn, state: "auto" as const, resolution: "missing" as const, candidates: [] } };
  const vpnDocument = JSON.stringify({ format: "nfqws2-strategy-dnsserver", version: 1, config: { awg_fallback: "foreign-vpn", route_mode: "vpn_only" } });
  const before = JSON.stringify(current);
  assert.deepEqual(buildDnsImportRequest(vpnDocument, current, initialDnsImportMapping(current)), { document: vpnDocument, base_hash: "saved-state", mapping: "auto" });
  assert.throws(() => buildDnsImportRequest(vpnDocument, current, "off"), /Только VPN/);
  assert.equal(JSON.stringify(current), before);
});

test("unverified local candidates cannot be selected explicitly or by a stale matched ID", () => {
  const current = { ...plan, vpn: { ...plan.vpn, state: "matched" as const, matched_id: candidate.ref, candidates: [{ ...candidate, fingerprint: "" }] } };
  assert.equal(initialDnsImportMapping(current), "auto");
  assert.throws(() => buildDnsImportRequest(document, current, candidate.ref), /Выберите «Автоматически»/);
});

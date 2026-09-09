import assert from "node:assert/strict";
import test from "node:test";
import type { DnsServerRule, DnsServerUpstream } from "@/types/api";
import { collectRuleGroups, groupRules, newRuleGroup } from "./ruleGroups";

const xbox = (): DnsServerUpstream => ({ address: "https://xbox-dns.ru/dns-query", bootstrap_ips: ["192.0.2.10"] });
const secondary = (): DnsServerUpstream => ({ address: "https://dns.example/dns-query", bootstrap_ips: ["192.0.2.20", "2001:db8::20"] });
const rule = (domain: string, patch: Partial<DnsServerRule> = {}): DnsServerRule => ({
  id: `saved-${domain}`, enabled: true, domain, include_subdomains: true, upstream: xbox(), pool: [], ...patch,
});
const byDomain = (values: DnsServerRule[]) => [...values].sort((a, b) => a.domain.localeCompare(b.domain));

test("existing Xbox rules become one group and round-trip without losing IDs or settings", () => {
  const saved = [rule("claude.com"), rule("grok.com"), rule("claude.ai")];
  const original = structuredClone(saved);
  const groups = groupRules(saved);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].enabled, true);
  assert.equal(groups[0].include_subdomains, true);
  assert.deepEqual(groups[0].pool, [{ address: xbox().address, bootstrap: "192.0.2.10" }]);
  assert.deepEqual(byDomain(collectRuleGroups(groups)), byDomain(saved));
  assert.deepEqual(saved, original);
});

test("the full ordered provider pool and both routing flags determine a group", () => {
  const saved = [
    rule("a.example", { pool: [secondary()] }),
    rule("b.example", { pool: [secondary()] }),
    rule("disabled.example", { enabled: false, pool: [secondary()] }),
    rule("exact.example", { include_subdomains: false, pool: [secondary()] }),
    rule("bootstrap.example", { upstream: { ...xbox(), bootstrap_ips: ["192.0.2.11"] }, pool: [secondary()] }),
    rule("secondary-bootstrap.example", { pool: [{ ...secondary(), bootstrap_ips: ["192.0.2.21"] }] }),
    rule("reordered.example", { upstream: secondary(), pool: [xbox()] }),
    rule("primary-only.example"),
  ];
  const groups = groupRules(saved);
  assert.equal(groups.length, 7);
  assert.deepEqual(byDomain(collectRuleGroups(groups)), byDomain(saved));
});

test("editing a group's providers and flags applies to all its domains while retaining saved IDs", () => {
  const saved = [rule("claude.com"), rule("grok.com")];
  const groups = groupRules(saved);
  groups[0].pool = [
    { address: "https://new.example/dns-query", bootstrap: "192.0.2.1; 2001:db8::1" },
    { address: secondary().address, bootstrap: "192.0.2.2" },
  ];
  groups[0].enabled = false;
  groups[0].include_subdomains = false;
  const collected = collectRuleGroups(groups);
  assert.equal(collected.length, 2);
  for (const value of collected) {
    assert.equal(value.id, `saved-${value.domain}`);
    assert.equal(value.enabled, false);
    assert.equal(value.include_subdomains, false);
    assert.deepEqual(value.upstream, { address: "https://new.example/dns-query", bootstrap_ips: ["192.0.2.1", "2001:db8::1"] });
    assert.deepEqual(value.pool, [{ address: secondary().address, bootstrap_ips: ["192.0.2.2"] }]);
  }
});

test("pasted lists normalize case, trailing dots and IDNA, ignore blank lines and deduplicate domains", () => {
  const groups = groupRules([rule("claude.com")]);
  groups[0].domains = " CLAUDE.COM.\n\nclaude.com, Grok.com; claude.ai\tПРИМЕР.РФ. \r\n ";
  const collected = collectRuleGroups(groups);
  assert.deepEqual(collected.map((value) => value.domain), ["claude.com", "grok.com", "claude.ai", "xn--e1afmkfd.xn--p1ai"]);
  assert.equal(collected[0].id, "saved-claude.com");
  assert.equal(new Set(collected.map((value) => value.id)).size, 4);
  assert.ok(collected.every((value) => value.id));
  assert.deepEqual(collectRuleGroups(groups), collected, "repeated saves produce stable IDs for added domains");
  assert.deepEqual(collectRuleGroups(groupRules(collected)), collected, "saved IDNA domains survive reopening the editor");
});

test("deleting a domain removes only its rule and new domains get distinct stable IDs", () => {
  const groups = groupRules([rule("claude.com"), rule("grok.com"), rule("claude.ai")]);
  groups[0].domains = "grok.com\nnew.example";
  const collected = collectRuleGroups(groups);
  assert.deepEqual(collected.map((value) => value.domain), ["grok.com", "new.example"]);
  assert.equal(collected[0].id, "saved-grok.com");
  assert.notEqual(collected[1].id, collected[0].id);
  assert.notEqual(collected[1].id, "saved-claude.com");
  assert.deepEqual(collectRuleGroups(groups), collected);
});

test("conflicting enabled domain groups are rejected but disabled alternatives can be retained", () => {
  const groups = groupRules([
    rule("claude.com"),
    rule("grok.com", { upstream: secondary() }),
  ]);
  groups[1].domains = "CLAUDE.COM.";
  assert.throws(() => collectRuleGroups(groups));
  groups[1].enabled = false;
  const collected = collectRuleGroups(groups);
  assert.equal(collected.length, 2);
  assert.deepEqual(collected.map((value) => value.enabled), [true, false]);
  assert.ok(collected.every((value) => value.domain === "claude.com"));
});

test("URL-shaped, wildcard and malformed domain tokens fail instead of silently changing routing", () => {
  const group = newRuleGroup([{ address: xbox().address, bootstrap: "" }]);
  for (const domains of ["https://claude.com", "*.claude.com", "claude.com/path", "foo..example", "-bad.example", "bad-.example", "user@example.com", "example.com:443", "a".repeat(64) + ".example"]) {
    group.domains = domains;
    assert.throws(() => collectRuleGroups([group]), `invalid domain was accepted: ${domains}`);
  }
});

test("empty groups are explicit errors while an empty group list removes all special rules", () => {
  assert.deepEqual(groupRules([]), []);
  assert.deepEqual(collectRuleGroups([]), []);
  const group = newRuleGroup([{ address: xbox().address, bootstrap: "" }]);
  group.domains = " \n ; , \r\n";
  assert.throws(() => collectRuleGroups([group]));
});

test("a domain group cannot be saved with a missing or unfinished provider row", () => {
  const group = newRuleGroup([{ address: xbox().address, bootstrap: "" }]);
  group.domains = "claude.com";
  group.pool = [];
  assert.throws(() => collectRuleGroups([group]));
  group.pool = [{ address: xbox().address, bootstrap: "" }, { address: " \t", bootstrap: "192.0.2.10" }];
  assert.throws(() => collectRuleGroups([group]));
});

test("legacy rules without pool fields and DNS labels matching object properties preserve valid IDs", () => {
  const saved = [rule("__proto__"), rule("constructor"), rule("_service.example")];
  for (const value of saved) delete value.pool;
  const groups = groupRules(saved);
  assert.equal(groups.length, 1);
  const collected = collectRuleGroups(groups);
  assert.deepEqual(collected, saved.map((value) => ({ ...value, pool: [] })));
  groups[0].domains += "\ntostring";
  const expanded = collectRuleGroups(groups);
  assert.equal(typeof expanded[3].id, "string");
  assert.ok(expanded[3].id);
  assert.equal(new Set(expanded.map((value) => value.id)).size, 4);
});

test("the 512-domain limit applies across groups after normalization and deduplication", () => {
  const groups = [
    newRuleGroup([{ address: xbox().address, bootstrap: "" }]),
    newRuleGroup([{ address: secondary().address, bootstrap: "" }]),
  ];
  groups[0].domains = Array.from({ length: 256 }, (_, i) => `left${i}.example`).join("\n") + "\nLEFT0.EXAMPLE.";
  groups[1].domains = Array.from({ length: 256 }, (_, i) => `right${i}.example`).join("\n");
  const collected = collectRuleGroups(groups);
  assert.equal(collected.length, 512);
  assert.equal(new Set(collected.map((value) => value.id)).size, 512);
  groups[1].domains += "\nover-limit.example";
  assert.throws(() => collectRuleGroups(groups));
});

test("group conversions and new groups do not share mutable provider data", () => {
  const saved = [rule("a.example", { pool: [secondary()] }), rule("b.example", { pool: [secondary()] })];
  const original = structuredClone(saved);
  const groups = groupRules(saved);
  const formSnapshot = structuredClone(groups);
  const collected = collectRuleGroups(groups);
  collected[0].upstream.bootstrap_ips.push("192.0.2.30");
  collected[0].pool![0].bootstrap_ips.push("192.0.2.31");
  collected[0].pool![0].address = "https://changed.example/dns-query";
  assert.deepEqual(collected[1], original[1]);
  assert.deepEqual(saved, original);
  assert.deepEqual(structuredClone(groups), formSnapshot);
  const pool = [{ address: xbox().address, bootstrap: "192.0.2.10" }];
  const first = newRuleGroup(pool);
  const second = newRuleGroup(pool);
  assert.notEqual(first.id, second.id);
  first.pool[0].address = "https://changed.example/dns-query";
  first.rule_ids["new.example"] = "new-id";
  assert.equal(pool[0].address, xbox().address);
  assert.equal(second.pool[0].address, xbox().address);
  assert.deepEqual(Object.keys(second.rule_ids), []);
});

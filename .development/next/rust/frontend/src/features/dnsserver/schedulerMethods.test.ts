import assert from "node:assert/strict";
import test from "node:test";
import type { DnsServerSchedulerCandidate, DnsServerSchedulerSnapshot } from "@/types/api";
import { allAvailableSchedulerMethodsDisabled, applyDisabledSchedulerMethods } from "./schedulerMethods";

const candidate = (patch: Partial<DnsServerSchedulerCandidate> = {}): DnsServerSchedulerCandidate => ({
  position: 1, route: "nfqws", route_name: "NFQWS", upstream: "https://dns.example/dns-query", available: true,
  score: 95, reliability: 1, latency_ms: 100, latency_penalty: 5, failure_penalty: 0,
  attempts: 12, successes: 10, failures: 1, consecutive_failures: 0,
  last_error: "", last_attempt_at: "2026-09-09T12:00:00Z", exploration: false, ...patch,
});
const snapshot = (candidates: DnsServerSchedulerCandidate[], patch: Partial<DnsServerSchedulerSnapshot> = {}): DnsServerSchedulerSnapshot => ({
  domain: "", pool_source: "default", formula: "score", parallel_limit: 32, tracked_pairs: candidates.length, candidates, ...patch,
});

test("saved method state targets the exact URL and route across views while retaining history and rows", () => {
  const first = candidate({ probing: true, exploration: true, last_error: "last historical failure" });
  const values = [first, candidate({ route: "awg:warp" }), candidate({ upstream: "https://dns.example/another-profile" })];
  const before = snapshot(values, { active_probes: 1 });
  const original = structuredClone(before);
  const disabled = [{ upstream: first.upstream, route: first.route }];
  const result = applyDisabledSchedulerMethods(before, disabled);
  assert.equal(result.candidates.length, 3, "disabled rows must remain available for re-enabling");
  assert.deepEqual(result.candidates.map((value) => value.disabled), [true, false, false]);
  assert.equal(result.candidates[0].position, 0);
  assert.equal(result.candidates[0].probing, false);
  assert.equal(result.candidates[0].exploration, false);
  assert.equal(result.active_probes, 0);
  assert.equal(result.candidates[0].attempts, 12);
  assert.equal(result.candidates[0].successes, 10);
  assert.equal(result.candidates[0].last_error, "last historical failure");
  assert.deepEqual(before, original, "an in-flight snapshot must not be mutated");
  const domainView = snapshot([first], { domain: "claude.ai", pool_source: "claude.ai" });
  assert.equal(applyDisabledSchedulerMethods(domainView, disabled).candidates[0].disabled, true);
});

test("an acknowledged enable removes stale disabled flags without resetting measurements", () => {
  const previous = snapshot([candidate({ disabled: true, position: 0, available: false })]);
  const enabled = applyDisabledSchedulerMethods(previous, []);
  assert.equal(enabled.candidates[0].disabled, false);
  assert.equal(enabled.candidates[0].available, false, "enabling cannot invent route availability");
  assert.equal(enabled.candidates[0].score, previous.candidates[0].score);
  assert.equal(enabled.candidates[0].attempts, previous.candidates[0].attempts);
  assert.equal(enabled.active_probes, undefined, "old snapshots need no synthetic probe counters");
});

test("all-disabled warning requires available methods and ignores unavailable alternatives", () => {
  assert.equal(allAvailableSchedulerMethodsDisabled(snapshot([])), false);
  assert.equal(allAvailableSchedulerMethodsDisabled(snapshot([candidate({ available: false, disabled: true })])), false);
  assert.equal(allAvailableSchedulerMethodsDisabled(snapshot([candidate()])), false, "missing disabled is enabled for old responses");
  assert.equal(allAvailableSchedulerMethodsDisabled(snapshot([candidate({ disabled: true }), candidate({ available: false, disabled: false })])), true);
  assert.equal(allAvailableSchedulerMethodsDisabled(snapshot([candidate({ disabled: true }), candidate({ route: "awg:warp", disabled: false })])), false);
});

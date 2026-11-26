import assert from "node:assert/strict";
import test from "node:test";
import type { DnsServerSchedulerSnapshot } from "@/types/api";
import { dnsSchedulerState } from "./dnsSchedulerState";

const snapshot = { candidates: [] } as unknown as DnsServerSchedulerSnapshot;
test("disabled scheduler and sole candidate have distinct explanations while legacy views still work", () => {
  assert.equal(dnsSchedulerState(snapshot).active, true);
  assert.equal(dnsSchedulerState({ ...snapshot, enabled: false }).active, false);
  assert.match(dnsSchedulerState({ ...snapshot, enabled: false }).message, /Кэш и fast-dns/);
  assert.match(dnsSchedulerState({ ...snapshot, reason: "single_candidate", effective: false }).message, /одно сочетание/);
  assert.match(dnsSchedulerState({ ...snapshot, reason: "no_candidates", effective: false }).message, /нет доступных/);
  assert.equal(dnsSchedulerState({ ...snapshot, enabled: true, effective: true }).active, true);
});

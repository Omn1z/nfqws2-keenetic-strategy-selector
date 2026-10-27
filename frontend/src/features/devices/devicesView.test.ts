import assert from "node:assert/strict";
import test from "node:test";
import type { Device } from "@/types/api";
import { deviceRows, deviceSummary } from "./devicesView";

const device = (overrides: Partial<Device> = {}): Device => ({
  ip: "192.168.1.2", mac: "aa:bb:cc:dd:ee:ff", hostname: "Workstation", iface: "br0", total: 3, established: 2,
  failing: 1, bytes_up: 1024, bytes_down: 2048, working: ["1.1.1.1:443"], failing_dsts: ["[2001:db8::1]:443"], ...overrides,
});

test("device search finds hostname, MAC, interface and every IPv6 address", () => {
  const item = device({ ipv6: ["fd00::2", "fe80::abcd"] });
  for (const query of [" workstation ", "AA:BB", "BR0", "FE80::ABCD", "192.168.1.2"]) assert.deepEqual(deviceRows([item], query, false), [item]);
  assert.deepEqual(deviceRows([item], "unmatched", false), []);
});

test("device problem filter preserves host grouping, order and target lists", () => {
  const healthy = device({ ip: "192.168.1.3", failing: 0, failing_dsts: [] });
  const missingCount = device({ ip: "192.168.1.4", failing: 0 });
  const item = device();
  const items = [healthy, missingCount, item];
  assert.deepEqual(deviceRows(items, "", true), [missingCount, item]);
  assert.deepEqual(deviceRows(items, "192.168.1.4", true)[0].failing_dsts, ["[2001:db8::1]:443"]);
  assert.deepEqual(items, [healthy, missingCount, item]);
});

test("device summary totals sessions and traffic from the complete snapshot", () => {
  const items = [device(), device({ ip: "192.168.1.3", total: 7, established: 7, failing: 0, failing_dsts: [], bytes_up: 4096, bytes_down: 8192 })];
  assert.deepEqual(deviceSummary(items), { hosts: 2, failingHosts: 1, established: 9, total: 10, failing: 1, bytes: 15360 });
  assert.deepEqual(deviceSummary([]), { hosts: 0, failingHosts: 0, established: 0, total: 0, failing: 0, bytes: 0 });
});

test("missing device traffic stays unavailable instead of showing a fabricated zero", () => {
  assert.equal(deviceSummary([device({ bytes_up: undefined })]).bytes, null);
  assert.equal(deviceSummary([device({ bytes_down: undefined })]).bytes, null);
  assert.equal(deviceSummary([device(), device({ bytes_up: undefined })]).bytes, null);
});

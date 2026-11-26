import assert from "node:assert/strict";
import test from "node:test";
import type { Conn } from "@/types/api";
import { connectionRows, connectionSummary } from "./connectionsView";

const connection = (overrides: Partial<Conn> = {}): Conn => ({
  l3: "ipv4", proto: "tcp", state: "ESTABLISHED", ttl: 60, src: "192.168.1.2", dst: "1.1.1.1", sport: 50000,
  dport: 443, packets: 1, bytes: 100, reply_bytes: 200, assured: true, unreplied: false, fastnat: false, mac: "", zone: "slan", ...overrides,
});
const filters = { query: "", failOnly: false, protocol: "all" as const, sort: { key: "bytes", dir: -1 }, hosts: {} };

test("connection protocol filter includes IPv4 and IPv6 ICMP and composes with search", () => {
  const items = [connection(), connection({ proto: "icmp", dport: 0 }), connection({ proto: "icmpv6", src: "fd00::2", dport: 0 }), connection({ proto: "udp" })];
  assert.deepEqual(connectionRows(items, { ...filters, protocol: "icmp" }).map(item => item.proto), ["icmp", "icmpv6"]);
  assert.deepEqual(connectionRows(items, { ...filters, protocol: "icmp", query: " FD00::2 " }).map(item => item.proto), ["icmpv6"]);
  assert.equal(connectionRows(items, { ...filters, protocol: "tcp" }).length, 1);
});

test("connection search finds source and destination hostnames and no-reply states", () => {
  const item = connection({ unreplied: true, state: "" });
  const hosts = { [item.src]: "Workstation", [item.dst]: "LocalResolver" };
  for (const query of [" workstation ", "LOCALRESOLVER", "unreplied", "нет ответа"]) assert.deepEqual(connectionRows([item], { ...filters, query, hosts }), [item]);
  assert.equal(connectionRows([item], { ...filters, query: "absent" }).length, 0);
});

test("connection failures and totals use existing conntrack semantics", () => {
  const items = [connection(), connection({ state: "SYN_SENT" }), connection({ proto: "udp", state: "", unreplied: true }), connection({ proto: "icmpv6", state: "" }), connection({ proto: "unknown", state: "" })];
  assert.equal(connectionRows(items, { ...filters, failOnly: true }).length, 2);
  assert.deepEqual(connectionSummary(items), { total: 5, failing: 2, established: 1, protocols: { tcp: 2, udp: 1, icmp: 1, other: 1 } });
});

test("connection sorting counts both traffic directions without mutating the snapshot", () => {
  const up = connection({ bytes: 500, reply_bytes: 0 });
  const down = connection({ bytes: 1, reply_bytes: 1000 });
  const items = [up, down];
  assert.deepEqual(connectionRows(items, filters), [down, up]);
  assert.deepEqual(connectionRows(items, { ...filters, sort: { key: "bytes", dir: 1 } }), [up, down]);
  assert.deepEqual(items, [up, down]);
});

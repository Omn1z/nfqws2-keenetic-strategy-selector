import assert from "node:assert/strict";
import test from "node:test";
import type { DnsServerLogEntry, DnsServerLogSnapshot } from "@/types/api";
import { DnsLogFeed } from "./dnsLogFeed";

const entry = (id: number): DnsServerLogEntry => ({ id, time: "2026-10-02T00:00:00Z", level: "info", event: "answer", domain: `${id}.example`, qtype: "A" });
const snapshot = (ids: number[], patch: Partial<DnsServerLogSnapshot> = {}): DnsServerLogSnapshot => ({
  enabled: true, bytes: ids.length * 128, max_bytes: 128 * 1024,
  oldest_id: ids[0] ?? 0, last_id: ids.at(-1) ?? 0, dropped: 0, entries: ids.map(entry), ...patch,
});
const ids = (value: DnsServerLogSnapshot) => value.entries.map((v) => v.id);
const seed = (feed: DnsLogFeed, value: DnsServerLogSnapshot) => feed.accept(feed.read(), value)!.snapshot;

test("initial log load is full and subsequent requests ask only after the accepted tail", () => {
  const feed = new DnsLogFeed();
  const initial = feed.read();
  assert.equal(initial.path, "/api/dnsserver/logs");
  assert.equal(initial.after, 0);
  feed.accept(initial, snapshot([4, 5, 6], { dropped: 3 }));
  const tail = feed.read();
  assert.equal(tail.path, "/api/dnsserver/logs?after=6");
  const result = feed.accept(tail, snapshot([7, 8], { oldest_id: 4, last_id: 8, bytes: 5 * 128, dropped: 3 }))!;
  assert.equal(result.reload, false);
  assert.deepEqual(ids(result.snapshot), [4, 5, 6, 7, 8]);
  assert.equal(feed.read().after, 8);
});

test("an unchanged tail neither triggers a full read nor replaces the displayed snapshot", () => {
  const feed = new DnsLogFeed();
  const previous = seed(feed, snapshot([1, 2, 3]));
  for (let i = 0; i < 10; i++) {
    const request = feed.read();
    assert.equal(request.path, "/api/dnsserver/logs?after=3");
    const result = feed.accept(request, { ...previous, entries: [] })!;
    assert.equal(result.reload, false);
    assert.equal(result.snapshot, previous);
  }
});

test("an empty loaded ring uses cursor zero and preserves the unchanged empty display", () => {
  const feed = new DnsLogFeed();
  const previous = seed(feed, snapshot([]));
  const request = feed.read();
  assert.equal(request.path, "/api/dnsserver/logs?after=0");
  const result = feed.accept(request, snapshot([]))!;
  assert.equal(result.reload, false);
  assert.equal(result.snapshot, previous);
});

test("incremental merging evicts exactly the rows older than the server's retained oldest ID", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([1, 2, 3, 4]));
  const incoming = snapshot([5, 6], { oldest_id: 3, dropped: 2, bytes: 4 * 128 });
  const original = structuredClone(incoming);
  const result = feed.accept(feed.read(), incoming)!;
  assert.deepEqual(ids(result.snapshot), [3, 4, 5, 6]);
  assert.equal(result.snapshot.oldest_id, 3);
  assert.equal(result.snapshot.dropped, 2);
  assert.equal(result.snapshot.bytes, incoming.bytes);
  assert.deepEqual(incoming, original);
});

test("a paused viewer can resume after a large gap without retaining evicted history", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([1, 2, 3]));
  const result = feed.accept(feed.read(), snapshot([100, 101, 102], { dropped: 99 }))!;
  assert.deepEqual(ids(result.snapshot), [100, 101, 102]);
  assert.equal(result.reload, false);
  assert.equal(feed.read().after, 102);
});

test("external Clear with a monotonic last ID removes the local history even when no new entries arrive", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([11, 12, 13], { dropped: 10 }));
  const cleared = feed.accept(feed.read(), snapshot([], { last_id: 13 }))!;
  assert.equal(cleared.reload, false);
  assert.deepEqual(ids(cleared.snapshot), []);
  assert.equal(cleared.snapshot.oldest_id, 0);
  assert.equal(feed.read().after, 13);
  const next = feed.accept(feed.read(), snapshot([14, 15]))!;
  assert.deepEqual(ids(next.snapshot), [14, 15]);
});

test("external Clear followed by new entries resets dropped metadata without falsely detecting a restart", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([11, 12, 13], { dropped: 10 }));
  const result = feed.accept(feed.read(), snapshot([14, 15], { dropped: 0 }))!;
  assert.equal(result.reload, false);
  assert.deepEqual(ids(result.snapshot), [14, 15]);
  assert.equal(result.snapshot.dropped, 0);
});

test("a restarted process discards stale history and requires a full snapshot until it succeeds", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([100, 101, 102], { dropped: 99 }));
  const restart = feed.accept(feed.read(), snapshot([], { oldest_id: 1, last_id: 2, bytes: 256 }))!;
  assert.equal(restart.reload, true);
  assert.deepEqual(ids(restart.snapshot), []);
  assert.equal(feed.read().path, "/api/dnsserver/logs");
  // A failed/cancelled full request never accepts a response. The next poll
  // still loads the missing prefix instead of silently moving to its tail.
  const retry = feed.read();
  assert.equal(retry.after, 0);
  const result = feed.accept(retry, snapshot([1, 2, 3]))!;
  assert.equal(result.reload, false);
  assert.deepEqual(ids(result.snapshot), [1, 2, 3]);
  assert.equal(feed.read().after, 3);
});

test("metadata detects a restarted ring that has caught up in ID but reset its old retained range", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([50, 51, 52], { dropped: 49 }));
  const result = feed.accept(feed.read(), snapshot([53], { oldest_id: 1, last_id: 53, dropped: 0 }))!;
  assert.equal(result.reload, true);
  assert.deepEqual(ids(result.snapshot), []);
  assert.equal(feed.read().after, 0);
});

test("a new instance invalidates old history even when its IDs already overtake the cursor with identical oldest/dropped metadata", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([1, 2, 3], { instance_id: "old-process" }));
  const tail = feed.read();
  assert.equal(tail.after, 3);
  const result = feed.accept(tail, snapshot([4, 5], { instance_id: "new-process", oldest_id: 1, dropped: 0 }))!;
  assert.equal(result.reload, true);
  assert.deepEqual(ids(result.snapshot), []);
  assert.equal(result.snapshot.instance_id, "new-process");
  const full = feed.read();
  assert.equal(full.path, "/api/dnsserver/logs");
  const fresh = feed.accept(full, snapshot([1, 2, 3, 4, 5], { instance_id: "new-process", entries: [1, 2, 3, 4, 5].map((id) => ({ ...entry(id), message: "new process history" })) }))!;
  assert.equal(fresh.reload, false);
  assert.deepEqual(ids(fresh.snapshot), [1, 2, 3, 4, 5]);
  assert.ok(fresh.snapshot.entries.every((value) => value.message === "new process history"));
});

test("Clear preserves a known instance ID, while a new empty instance still forces a full reload", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([1, 2, 3], { instance_id: "same-process" }));
  const clear = feed.accept(feed.read(), snapshot([], { instance_id: "same-process", last_id: 3 }))!;
  assert.equal(clear.reload, false);
  assert.deepEqual(ids(clear.snapshot), []);
  assert.equal(clear.snapshot.instance_id, "same-process");
  const result = feed.accept(feed.read(), snapshot([], { instance_id: "new-process" }))!;
  assert.equal(result.reload, true);
  assert.equal(result.snapshot.instance_id, "new-process");
  assert.deepEqual(ids(result.snapshot), []);
  assert.equal(feed.read().path, "/api/dnsserver/logs");
  feed.accept(feed.read(), snapshot([], { instance_id: "new-process" }));
  const loadedEmpty = feed.accept(feed.read(), snapshot([], { instance_id: "third-process" }))!;
  assert.equal(loadedEmpty.reload, true, "a zero cursor must not hide replacement of an already loaded empty ring");
});

test("an instance ID appearing on an older panel response replaces legacy history instead of silently reusing it", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([1, 2, 3]));
  const result = feed.accept(feed.read(), snapshot([4], { instance_id: "upgraded-process", oldest_id: 1 }))!;
  assert.equal(result.reload, true);
  assert.deepEqual(ids(result.snapshot), []);
  assert.equal(feed.read().after, 0);
});

test("an acknowledged Clear invalidates an older in-flight read so it cannot resurrect deleted rows", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([1, 2, 3]));
  const oldRead = feed.read();
  feed.invalidate();
  assert.equal(feed.isCurrent(oldRead), false);
  const cleared = feed.replace(snapshot([], { last_id: 3 }));
  assert.deepEqual(ids(cleared), []);
  assert.equal(feed.accept(oldRead, snapshot([4], { oldest_id: 1 })), null);
  assert.equal(feed.read().after, 3);
});

test("a failed or uncertain mutation retains the old cursor while rejecting its earlier reads", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([1, 2, 3]));
  const oldRead = feed.read();
  feed.invalidate();
  assert.equal(feed.accept(oldRead, snapshot([4], { oldest_id: 1 })), null);
  const next = feed.read();
  assert.equal(next.after, 3);
  // If Clear committed but its ACK was lost, the next ordinary poll still
  // reconciles the confirmed empty state instead of keeping stale rows.
  assert.deepEqual(ids(feed.accept(next, snapshot([], { last_id: 3 }))!.snapshot), []);
});

test("an older response arriving after a newer accepted read cannot rewind the cursor or trigger a false restart", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([1, 2, 3]));
  const older = feed.read();
  const newer = feed.read();
  const latest = feed.accept(newer, snapshot([4, 5], { oldest_id: 1 }))!;
  assert.deepEqual(ids(latest.snapshot), [1, 2, 3, 4, 5]);
  assert.equal(feed.isCurrent(older), false);
  assert.equal(feed.accept(older, snapshot([4], { oldest_id: 1 })), null);
  assert.equal(feed.read().after, 5);
});

test("repeated incremental tails stay bounded to the actual retained ring and never duplicate IDs", () => {
  const feed = new DnsLogFeed();
  seed(feed, snapshot([1]));
  for (let id = 2; id <= 5000; id++) {
    const oldest = Math.max(1, id - 63);
    const result = feed.accept(feed.read(), snapshot([id - 1, id], { oldest_id: oldest, last_id: id, dropped: oldest - 1, bytes: Math.min(64, id) * 128 }))!;
    assert.equal(result.reload, false);
    assert.equal(result.snapshot.entries.length, Math.min(64, id));
    assert.equal(new Set(ids(result.snapshot)).size, result.snapshot.entries.length);
    assert.equal(result.snapshot.entries[0].id, oldest);
    assert.equal(result.snapshot.entries.at(-1)?.id, id);
  }
});

test("unexpected rows outside the retained range and an oversized row count cannot grow local history", () => {
  const feed = new DnsLogFeed();
  const result = seed(feed, snapshot(Array.from({ length: 3000 }, (_, i) => i + 1), { entries: [entry(0), ...Array.from({ length: 3000 }, (_, i) => entry(i + 1)), entry(3001), entry(Number.NaN)] }));
  assert.ok(result.entries.length <= 2048);
  assert.ok(result.entries.reduce((total, value) => total + new TextEncoder().encode(JSON.stringify(value)).byteLength + 1, 0) <= 128 * 1024);
  assert.equal(result.entries.at(-1)?.id, 3000);
  assert.equal(result.entries.some((v) => !Number.isSafeInteger(v.id) || v.id < result.oldest_id || v.id > result.last_id), false);
});

test("the client retention guard counts UTF-8 bytes and respects a smaller advertised server ring", () => {
  const feed = new DnsLogFeed();
  const result = seed(feed, snapshot(Array.from({ length: 100 }, (_, i) => i + 1), { max_bytes: 4096,
    entries: Array.from({ length: 100 }, (_, i) => ({ ...entry(i + 1), message: "🚀ДНС".repeat(20) })) }));
  const bytes = result.entries.reduce((total, value) => total + new TextEncoder().encode(JSON.stringify(value)).byteLength + 1, 0);
  assert.ok(bytes <= 4096);
  assert.ok(result.entries.length < 100);
  assert.equal(result.entries.at(-1)?.id, 100);
});

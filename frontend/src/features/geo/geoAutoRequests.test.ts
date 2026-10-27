import assert from "node:assert/strict";
import test from "node:test";
import type { GeoAutoConfig } from "@/types/api";
import { createGeoAutoRequests, mergeGeoAutoDraft } from "./geoAutoRequests";

const initial: GeoAutoConfig = { enabled: false, interval_hours: 24, geosite_url: "site-old", geoip_url: "ip-old", last_fetched_at: 0, last_error: "", last_geosite_at: 0, last_geoip_at: 0, last_geosite_len: 0, last_geoip_len: 0 };

test("geo blur-save followed immediately by toggle and fetch retains every settings snapshot in order", async () => {
  const calls: string[] = [], acknowledged: GeoAutoConfig[] = [];
  let saved = initial;
  const requests = createGeoAutoRequests({
    save: async cfg => { calls.push(`save:${cfg.geosite_url}:${cfg.enabled}`); saved = { ...cfg }; return saved; },
    fetchNow: async () => { calls.push(`fetch:${saved.geosite_url}:${saved.enabled}`); return { ...saved, last_fetched_at: 123 }; },
    onAcknowledged: cfg => { acknowledged.push(cfg); },
  });
  requests.observe(initial);
  const blur = { ...initial, geosite_url: "site-new", interval_hours: 6 };
  const toggle = { ...blur, enabled: true };
  await Promise.all([requests.save(blur), requests.save(toggle), requests.fetch(toggle)]);
  assert.deepEqual(calls, ["save:site-new:false", "save:site-new:true", "fetch:site-new:true"]);
  assert.equal(acknowledged.at(-1)?.last_fetched_at, 123);
  assert.equal(initial.geosite_url, "site-old");
});

test("late geo acknowledgement updates metadata without overwriting newer URL, interval or toggle input", () => {
  const requested = { ...initial, geosite_url: "site-first" };
  const current = { ...requested, geosite_url: "site-newer", geoip_url: "ip-newer", enabled: true, interval_hours: 12 };
  const acknowledged = { ...requested, last_fetched_at: 234, last_geosite_len: 4096 };
  assert.deepEqual(mergeGeoAutoDraft(current, acknowledged, requested), { ...acknowledged, geosite_url: "site-newer", geoip_url: "ip-newer", enabled: true, interval_hours: 12 });
  assert.equal(mergeGeoAutoDraft(requested, acknowledged, requested), acknowledged);
});

test("queued geo requests detach their payload from later draft edits", async () => {
  const sent: GeoAutoConfig[] = [];
  const requests = createGeoAutoRequests({
    save: async cfg => { sent.push(cfg); return cfg; },
    fetchNow: async () => initial,
    onAcknowledged: () => {},
  });
  requests.observe(initial);
  const draft = { ...initial, geosite_url: "site-at-click" };
  const job = requests.save(draft);
  draft.geosite_url = "site-typed-later";
  await job;
  assert.equal(sent[0].geosite_url, "site-at-click");
});

test("geo fetch persists the current draft first and failed saves cannot fetch with old URLs or invent acknowledgements", async () => {
  const calls: string[] = [], acknowledged: GeoAutoConfig[] = [];
  let fail = true;
  const requests = createGeoAutoRequests({
    save: async cfg => { calls.push("save"); if (fail) throw new Error("save failed"); return cfg; },
    fetchNow: async () => { calls.push("fetch"); return { ...initial, geosite_url: "site-new", last_fetched_at: 345 }; },
    onAcknowledged: cfg => { acknowledged.push(cfg); },
  });
  requests.observe(initial);
  const draft = { ...initial, geosite_url: "site-new" };
  await assert.rejects(requests.fetch(draft), /save failed/);
  assert.deepEqual(calls, ["save"]);
  assert.deepEqual(acknowledged, [initial]);
  fail = false;
  await requests.fetch(draft);
  assert.deepEqual(calls, ["save", "save", "fetch"]);
  assert.equal(acknowledged.at(-1)?.last_fetched_at, 345);
});

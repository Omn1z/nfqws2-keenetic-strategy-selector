import assert from "node:assert/strict";
import test from "node:test";
import { blockingForm, collectBlocking } from "./Blocking";

test("legacy config without filtering remains disabled and empty", () => {
  assert.deepEqual(collectBlocking(blockingForm()), {
    enabled: false, lists: [], custom_rules: [], allowlist: [],
  });
});

test("rule editor preserves list selection and parses categories and narrow wildcards", () => {
  const config = collectBlocking({
    enabled: true,
    lists: ["adguard-dns", "blocklist-tracking"],
    customRules: "ads: ads.example.com\ntrackers: *-netseer-ipaddr-assoc.xy.fbcdn.net\nmixed: metrics.example.com\nother.example.com",
    allowlist: "safe.example.com\n*.trusted.example.com",
  });
  assert.deepEqual(config.custom_rules, [
    { category: "ads", domain: "ads.example.com" },
    { category: "trackers", domain: "*-netseer-ipaddr-assoc.xy.fbcdn.net" },
    { category: "mixed", domain: "metrics.example.com" },
    { category: "trackers", domain: "other.example.com" },
  ]);
  assert.deepEqual(config.allowlist, ["safe.example.com", "*.trusted.example.com"]);
  assert.deepEqual(collectBlocking(blockingForm(config)), config);
});

test("invalid rule line is identified before save", () => {
  assert.throws(() => collectBlocking({ enabled: true, lists: [], customRules: "ads: good.example\nunknown: bad.example", allowlist: "" }), /строка 2/);
  assert.throws(() => collectBlocking({ enabled: true, lists: [], customRules: "", allowlist: "https:\/\/example.com" }), /Исключение/);
});

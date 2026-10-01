import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { Blocking, blockingForm, collectBlocking } from "./Blocking";

test("legacy config without filtering remains disabled and empty", () => {
  assert.deepEqual(collectBlocking(blockingForm()), {
    enabled: false, lists: [], custom_rules: [], allowlist: [],
  });
});

test("rule editor preserves list selection and parses categories and narrow wildcards", () => {
  const config = collectBlocking({
    enabled: true,
    lists: ["adguard-dns"],
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

test("disabling the downloaded filter preserves editable manual rules and exclusions", () => {
  const config = {
    enabled: true, lists: [],
    custom_rules: [{ category: "ads" as const, domain: "manual.example" }],
    allowlist: ["trusted.example"],
  };
  assert.deepEqual(collectBlocking(blockingForm(config)), config);
});

test("filter controls show only AdGuard and retain manual rule editors", () => {
  const list = {
    category: "mixed" as const, url: "", homepage: "", description: "",
    selected: false, rules: 1000, last_updated: "", last_error: "",
  };
  const markup = renderToStaticMarkup(createElement(Blocking, {
    value: { enabled: true, lists: ["adguard-dns"], customRules: "ads: manual.example", allowlist: "trusted.example" },
    onChange: () => {}, savedEnabled: true, running: true, disabled: false,
    updateBusy: false, unsaved: false, onUpdate: () => {},
    status: {
      enabled: true, ready: true, rules: 1001, updating: false, last_updated: "", last_error: "",
      lists: [
        { ...list, id: "adguard-dns", name: "AdGuard DNS filter", selected: true },
        { ...list, id: "hagezi-light", name: "HaGeZi Light" },
        { ...list, id: "oisd-small", name: "OISD small" },
      ],
    },
  }));
  assert.match(markup, /AdGuard DNS filter/);
  assert.doesNotMatch(markup, /HaGeZi|OISD|до трёх/);
  assert.match(markup, /Обновить AdGuard/);
  assert.match(markup, /ads: manual\.example/);
  assert.match(markup, /trusted\.example/);
  assert.match(markup, /только собственные правила/);
});

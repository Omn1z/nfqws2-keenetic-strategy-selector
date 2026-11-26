import assert from "node:assert/strict";
import test from "node:test";
import { dnsConfigDirty, dnsConfigDraft, dnsConfigPayload, syncDnsConfigDraft } from "./dnsConfigDraft";

test("clean DNS drafts follow newer saved polls without becoming an accidental old configuration edit", () => {
  const old = dnsConfigDraft({ rules: ["old"], timeout: 3 }, "old-hash");
  const next = syncDnsConfigDraft(old, { rules: ["new", "second"], timeout: 5 }, "new-hash");
  assert.deepEqual(next.value, { rules: ["new", "second"], timeout: 5 });
  assert.equal(next.baseHash, "new-hash");
  assert.equal(dnsConfigDirty(next), false);
  assert.deepEqual(old.value.rules, ["old"]);
});

test("dirty DNS drafts retain their original save token when another tab changes settings", () => {
  const saved = dnsConfigDraft({ rules: ["old"], timeout: 3 }, "old-hash");
  const editing = { ...saved, value: { ...saved.value, timeout: 7 } };
  const polled = syncDnsConfigDraft(editing, { rules: ["new"], timeout: 5 }, "new-hash");
  assert.equal(polled, editing);
  assert.equal(dnsConfigDirty(polled), true);
  assert.deepEqual(dnsConfigPayload(polled, value => value), { rules: ["old"], timeout: 7, base_hash: "old-hash" });
  // Sending this old token makes the server reject the old tab, rather than
  // claiming that its old rule list was based on the latest saved settings.
  assert.notEqual(polled.baseHash, "new-hash");
});

test("a poll completing after an edit uses the current draft and cannot erase that edit", () => {
  const initial = dnsConfigDraft({ upstream: "first", rules: ["kept"] }, "first-hash");
  const editedWhileReading = { ...initial, value: { ...initial.value, upstream: "my draft" } };
  assert.equal(syncDnsConfigDraft(editedWhileReading, { upstream: "remote", rules: [] }, "remote-hash"), editedWhileReading);
  const acknowledged = dnsConfigDraft(editedWhileReading.value, "acknowledged-hash");
  assert.equal(dnsConfigDirty(acknowledged), false);
  assert.equal(dnsConfigPayload(acknowledged, value => value).base_hash, "acknowledged-hash");
});

test("DNS saves without a loaded revision fail before constructing a destructive request", () => {
  const draft = dnsConfigDraft({ rules: [] }, "");
  assert.throws(() => dnsConfigPayload(draft, value => value), /актуальные настройки/);
  assert.deepEqual(draft.value, { rules: [] });
});

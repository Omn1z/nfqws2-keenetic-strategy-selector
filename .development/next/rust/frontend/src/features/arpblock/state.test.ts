import assert from "node:assert/strict";
import test from "node:test";
import { canApplyARPBlockIsolation, editARPBlockIsolation, emptyARPBlockEditor, receiveARPBlockView } from "./state";
import type { ARPBlockView } from "./types";

const fixture = (): ARPBlockView => ({
  platform: "keenetic", supported: true, reason: "", revision: "first", checked_at: 1, clients: [],
  segments: [
    { id: "Bridge0", name: "Домашняя сеть", address: "192.168.3.1", members: ["WifiMaster0/AccessPoint0"], ssids: ["Home"], enabled: false, up: true, eligible: true, reason: "", home: true },
    { id: "Bridge1", name: "IoT", address: "192.168.4.1", members: ["WifiMaster0/AccessPoint1"], ssids: ["IoT"], enabled: true, up: true, eligible: true, reason: "", home: false },
  ],
});

test("ARP Block starts with observed state and sends only the selected segment and revision", () => {
  const initial = receiveARPBlockView(emptyARPBlockEditor, fixture());
  assert.equal(initial.selected, "Bridge0");
  assert.equal(initial.draft, null);
  assert.equal(canApplyARPBlockIsolation(initial), false);
  const edited = editARPBlockIsolation(initial, true);
  assert.deepEqual(edited.draft, { segment: "Bridge0", enabled: true, revision: "first" });
  assert.equal(canApplyARPBlockIsolation(edited), true, "a home segment can be explicitly changed");
  assert.equal(initial.view?.segments[0].enabled, false, "editing must not change the observed state");
  assert.equal(editARPBlockIsolation(edited, false).draft, null);
});

test("ARP Block refresh retains a dirty selection and detects configuration conflicts", () => {
  let state = receiveARPBlockView(emptyARPBlockEditor, fixture());
  state = editARPBlockIsolation({ ...state, selected: "Bridge1" }, false);
  const draft = state.draft;
  state = receiveARPBlockView(state, { ...fixture(), checked_at: 2 });
  assert.equal(state.selected, "Bridge1");
  assert.equal(state.draft, draft);
  assert.equal(canApplyARPBlockIsolation(state), true);
  state = receiveARPBlockView(state, { ...fixture(), revision: "changed", checked_at: 3 });
  assert.equal(state.draft, draft);
  assert.equal(canApplyARPBlockIsolation(state), false);
  assert.equal(editARPBlockIsolation(state, true), state, "a toggle must not silently adopt a conflicting revision");
  const reviewed = receiveARPBlockView({ ...state, draft: null }, state.view!);
  assert.deepEqual(editARPBlockIsolation(reviewed, false).draft, { segment: "Bridge1", enabled: false, revision: "changed" });
});

test("ARP Block preserves a removed draft target without applying it to another segment", () => {
  const state = editARPBlockIsolation(receiveARPBlockView(emptyARPBlockEditor, fixture()), true);
  const view = fixture();
  view.segments = view.segments.slice(1);
  const refreshed = receiveARPBlockView(state, view);
  assert.equal(refreshed.selected, "Bridge0");
  assert.equal(refreshed.draft?.segment, "Bridge0");
  assert.equal(canApplyARPBlockIsolation(refreshed), false);
  const reset = receiveARPBlockView({ ...refreshed, draft: null }, view);
  assert.equal(reset.selected, "Bridge1");
  assert.equal(reset.draft, null);
});

test("ARP Block cannot apply unsupported, unavailable, unversioned, or mismatched targets", () => {
  const ready = editARPBlockIsolation(receiveARPBlockView(emptyARPBlockEditor, fixture()), true);
  for (const view of [
    { ...fixture(), supported: false },
    { ...fixture(), revision: "" },
    { ...fixture(), segments: fixture().segments.map(segment => ({ ...segment, eligible: false })) },
  ]) {
    const state = receiveARPBlockView(ready, view);
    assert.equal(canApplyARPBlockIsolation(state), false);
    const pristine = { ...state, draft: null };
    assert.equal(editARPBlockIsolation(pristine, true), pristine);
  }
  assert.equal(canApplyARPBlockIsolation({ ...ready, selected: "Bridge1" }), false);
  assert.equal(canApplyARPBlockIsolation({ ...ready, draft: { ...ready.draft!, revision: "" } }), false);
});

test("ARP Block clean refresh reflects changes and prefers an eligible segment on initial load", () => {
  const view = fixture();
  view.segments[0].eligible = false;
  const state = receiveARPBlockView(emptyARPBlockEditor, view);
  assert.equal(state.selected, "Bridge1");
  const updated = fixture();
  updated.segments[1].enabled = false;
  const refreshed = receiveARPBlockView(state, updated);
  assert.equal(refreshed.selected, "Bridge1");
  assert.equal(refreshed.draft, null);
  assert.equal(refreshed.view?.segments[1].enabled, false);
  assert.equal(canApplyARPBlockIsolation(refreshed), false);
  assert.equal(receiveARPBlockView(emptyARPBlockEditor, { ...fixture(), segments: [] }).selected, "");
});

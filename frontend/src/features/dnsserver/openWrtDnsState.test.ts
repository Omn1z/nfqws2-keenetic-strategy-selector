import assert from "node:assert/strict";
import test from "node:test";
import type { OpenWrtDnsState } from "@/types/api";
import { initialOpenWrtDnsSelection, openWrtDnsApplyBlock, openWrtDnsEndpoint, openWrtDnsRestoreAllowed } from "./openWrtDnsState";

const state: OpenWrtDnsState = {
  supported: true, managed: false, revision: "revision-one", warnings: [],
  interfaces: [{ id: "lan", label: "LAN" }, { id: "wan", label: "WAN" }],
  instances: [{ id: "cfg01411c", label: "Основной DNS" }],
};
const flags = { dirty: false, running: true, busy: false };

test("OpenWrt DNS chooses WAN and a sole dnsmasq but never silently chooses among instances", () => {
  assert.deepEqual(initialOpenWrtDnsSelection(state), { interface: "wan", instance: "cfg01411c" });
  const multi = { ...state, instances: [...state.instances, { id: "iot", label: "IoT" }] };
  const selection = initialOpenWrtDnsSelection(multi);
  assert.equal(selection.instance, "");
  assert.match(openWrtDnsApplyBlock(multi, selection, flags), /экземпляр dnsmasq/);
  assert.equal(initialOpenWrtDnsSelection({ ...state, interfaces: [{ id: "uplink", label: "Провайдер" }] }).interface, "uplink");
});

test("OpenWrt DNS restores saved binding selection and rejects removed interface/instance IDs", () => {
  const managed = { ...state, managed: true, binding: { interface: "lan", instance: "cfg01411c", endpoint: { host: "192.168.1.1", port: 5355 } } };
  assert.equal(initialOpenWrtDnsSelection(managed).interface, "lan");
  assert.equal(initialOpenWrtDnsSelection(managed, { interface: "wan", instance: "cfg01411c" }).interface, "wan");
  assert.deepEqual(initialOpenWrtDnsSelection(managed, { interface: "deleted", instance: "old" }), { interface: "lan", instance: "cfg01411c" });
  assert.match(openWrtDnsApplyBlock(state, { interface: "deleted", instance: "cfg01411c" }, flags), /интерфейс/);
  assert.match(openWrtDnsApplyBlock(state, { interface: "wan", instance: "old" }, flags), /экземпляр/);
});

test("OpenWrt DNS requires saved running configuration and current revision before apply", () => {
  const selection = initialOpenWrtDnsSelection(state);
  assert.equal(openWrtDnsApplyBlock(state, selection, flags), "");
  assert.match(openWrtDnsApplyBlock(state, selection, { ...flags, dirty: true }), /сохраните или отмените/);
  assert.match(openWrtDnsApplyBlock(state, selection, { ...flags, running: false }), /включите/);
  assert.match(openWrtDnsApplyBlock(state, selection, { ...flags, busy: true }), /завершения/);
  assert.match(openWrtDnsApplyBlock({ ...state, revision: "" }, selection, flags), /устарело/);
  assert.equal(openWrtDnsApplyBlock({ ...state, conflict: "UCI изменён вручную" }, selection, flags), "UCI изменён вручную");
  assert.match(openWrtDnsApplyBlock({ ...state, supported: false }, selection, flags), /только на OpenWrt/);
  assert.match(openWrtDnsApplyBlock(null, selection, flags), /обновите/);
});

test("OpenWrt DNS restore remains available when DNS is stopped but cannot overwrite an external change", () => {
  const managed = { ...state, managed: true };
  assert.equal(openWrtDnsRestoreAllowed(managed, false), true);
  assert.equal(openWrtDnsRestoreAllowed(managed, true), false);
  assert.equal(openWrtDnsRestoreAllowed({ ...managed, conflict: "changed" }, false), false);
  assert.equal(openWrtDnsRestoreAllowed({ ...managed, revision: "" }, false), false);
  assert.equal(openWrtDnsRestoreAllowed({ ...managed, supported: false }, false), false);
  assert.equal(openWrtDnsRestoreAllowed(state, false), false);
  assert.equal(openWrtDnsRestoreAllowed(null, false), false);
});

test("OpenWrt DNS endpoint display includes saved port and brackets IPv6", () => {
  assert.equal(openWrtDnsEndpoint({ host: "192.168.1.1", port: 5355 }), "192.168.1.1:5355");
  assert.equal(openWrtDnsEndpoint({ host: "fd00::1", port: 5355 }), "[fd00::1]:5355");
});

test("OpenWrt interrupted owned transaction allows recovery but prevents reapply", () => {
  const pending = { ...state, managed: true, pending: true };
  assert.match(openWrtDnsApplyBlock(pending, initialOpenWrtDnsSelection(pending), flags), /Сначала восстановите/);
  assert.equal(openWrtDnsRestoreAllowed(pending, false), true);
  assert.equal(openWrtDnsRestoreAllowed({ ...pending, conflict: "Внешние изменения UCI" }, false), false);
});

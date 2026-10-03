import assert from "node:assert/strict";
import test from "node:test";
import { routingDefaultTunnelID } from "./RulesTable";

const tunnels = [
  { id: "warp", enabled: true, connected: true },
  { id: "germany", enabled: true, connected: true },
];

test("a new rule targets the selected connection even when WARP is first in the list", () => {
  assert.equal(routingDefaultTunnelID(tunnels, "germany"), "germany");
});

test("selecting an offline profile does not silently route its new rule through another VPN", () => {
  const profiles = [{ ...tunnels[0] }, { id: "germany", enabled: false, connected: false }];
  assert.equal(routingDefaultTunnelID(profiles, "germany"), "germany");
});

test("a missing or unfinished selected profile falls back to an available routing connection", () => {
  const profiles = [
    { id: "offline", enabled: false, connected: false },
    { id: "germany", enabled: true, connected: true },
    { id: "standby", enabled: true, connected: false },
  ];
  assert.equal(routingDefaultTunnelID(profiles, "unfinished"), "germany");
  assert.equal(routingDefaultTunnelID(profiles.map((s) => ({ ...s, connected: false })), "unfinished"), "germany");
});

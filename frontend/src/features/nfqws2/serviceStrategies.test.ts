import assert from "node:assert/strict";
import test from "node:test";
import { newServiceGroup, newServiceID, serviceCheckDomains, serviceEntries, servicesPayload, servicesSignature, type ServiceStrategy } from "./serviceStrategiesModel";

const fixture = (): ServiceStrategy => ({
  id: "facepunch", name: " FacePunch ", enabled: false,
  groups: [
    { ...newServiceGroup("domains", "web"), entries: ["  FacePunch.com  ", "", "# web domains", "*.steam.example", "FacePunch.com"], strategy: "\n--filter-tcp=443\n--lua-desync=multisplit:pos=1\n" },
    { ...newServiceGroup("domains", "cdn", 2), entries: ["facepunch.com.", ".cdn.example", "*.steam.example"], strategy: "--filter-udp=443" },
    { ...newServiceGroup("ips", "servers"), entries: ["192.0.2.0/24", "2001:db8::/32"], strategy: "--filter-udp=27015-27050" },
  ],
});

test("new service and group IDs also work on plain HTTP without crypto.randomUUID", () => {
  const first = newServiceID({});
  const second = newServiceID({});
  assert.match(first, /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/);
  assert.notEqual(first, second);
  assert.equal(newServiceID({ randomUUID: () => "known-uuid" }), "known-uuid");
});

test("entries normalize pasted lines without losing order or including comments", () => {
  assert.deepEqual(serviceEntries(["a.example\r\nb.example\n", " a.example ", "\t# comment", "", "192.0.2.0/24"]), ["a.example", "b.example", "192.0.2.0/24"]);
});

test("API payload trims boundaries and preserves strategies and independent groups", () => {
  const service = fixture();
  const before = structuredClone(service);
  const [payload] = servicesPayload([service]);
  assert.equal(payload.name, "FacePunch");
  assert.equal(payload.enabled, false);
  assert.deepEqual(payload.groups[0].entries, ["FacePunch.com", "*.steam.example"]);
  assert.equal(payload.groups[0].strategy, "--filter-tcp=443\n--lua-desync=multisplit:pos=1");
  assert.deepEqual(payload.groups[2].entries, ["192.0.2.0/24", "2001:db8::/32"]);
  assert.deepEqual(service, before, "normalization must leave the unsaved editor draft intact");
});

test("HTTPS check deduplicates concrete domain roots and never sends IP groups", () => {
  assert.deepEqual(serviceCheckDomains(fixture()), ["facepunch.com", "steam.example", "cdn.example"]);
  assert.deepEqual(serviceCheckDomains(undefined), []);
  assert.deepEqual(serviceCheckDomains({ ...fixture(), groups: [fixture().groups[2]] }), []);
});

test("dirty detection ignores list formatting but tracks enable, order and strategy changes", () => {
  const service = fixture();
  const signature = servicesSignature([service]);
  assert.equal(signature, servicesSignature(servicesPayload([service])));
  assert.notEqual(signature, servicesSignature([{ ...service, enabled: true }]));
  assert.notEqual(signature, servicesSignature([{ ...service, groups: [...service.groups].reverse() }]));
  assert.notEqual(signature, servicesSignature([{ ...service, groups: service.groups.map((group, i) => i === 0 ? { ...group, strategy: group.strategy + " --new" } : group) }]));
});

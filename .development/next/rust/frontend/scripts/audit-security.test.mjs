import assert from "node:assert/strict";
import test from "node:test";
import { evaluateAudit, EXCEPTION, normalizePublishedVersion } from "./audit-security.mjs";

const node = (name, via) => ({ name, severity: "high", isDirect: name === "vite", via, effects: [], range: "*", nodes: [`node_modules/${name}`], fixAvailable: false });
const leaf = () => ({ source: EXCEPTION.source, name: "picomatch", dependency: "picomatch", url: EXCEPTION.advisory, range: EXCEPTION.range, severity: "high" });
const report = (vulnerabilities = {}) => ({ auditReportVersion: 2, vulnerabilities, metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: Object.keys(vulnerabilities).length, critical: 0, total: Object.keys(vulnerabilities).length } } });
const fixture = () => ({
  full: report({ picomatch: node("picomatch", [leaf()]), fdir: node("fdir", ["picomatch"]), tinyglobby: node("tinyglobby", ["fdir", "picomatch"]), vite: node("vite", ["fdir", "tinyglobby", "picomatch"]) }),
  prod: report(),
  lock: { lockfileVersion: 3, packages: { "": { devDependencies: { vite: "7.3.7" } }, ...Object.fromEntries(["picomatch", "fdir", "tinyglobby", "vite"].map(name => [`node_modules/${name}`, { dev: true, version: name === "picomatch" ? "4.0.4" : "fixture" }])) } },
});
const options = { now: new Date("2026-11-18T12:00:00Z"), publishedVersion: "4.0.7" };
const check = f => evaluateAudit(f.full, f.prod, f.lock, options);

test("permits only the approved advisory through the four dev-only build dependencies", () => {
  assert.deepEqual(check(fixture()), { exception: true, affected: 4 });
  assert.deepEqual(evaluateAudit(report(), report(), {}, { now: new Date("2026-12-01") }), { exception: false, affected: 0 });
});

test("production findings or a runtime lockfile node can never use the build exception", () => {
  let f = fixture(); f.prod = report({ picomatch: node("picomatch", [leaf()]) });
  assert.throws(() => check(f), /Production/);
  f = fixture(); f.lock.packages["node_modules/picomatch"].dev = false;
  assert.throws(() => check(f), /dev-only/);
  f = fixture(); f.lock.packages[""].dependencies = { picomatch: "4.0.4" };
  assert.throws(() => check(f), /production dependency/);
});

test("a new advisory, changed range, package or version fails closed", () => {
  let f = fixture(); f.full.vulnerabilities.picomatch.via.push({ ...leaf(), url: "https://github.com/advisories/GHSA-other" });
  assert.throws(() => check(f), /Unapproved advisory/);
  f = fixture(); f.full.vulnerabilities.picomatch.via[0].range = "*";
  assert.throws(() => check(f), /Unapproved advisory/);
  f = fixture(); f.lock.packages["node_modules/picomatch"].version = "4.0.7";
  assert.throws(() => check(f), /locked picomatch/);
  f = fixture(); f.full.vulnerabilities.other = node("other", [leaf()]); f.full.metadata.vulnerabilities.high++; f.full.metadata.vulnerabilities.total++;
  assert.throws(() => check(f), /Unapproved dependency/);
});

test("report errors, unknown schemas and misleading totals are rejected", () => {
  for (const broken of [{ error: { code: "ECONNRESET" } }, { auditReportVersion: 1 }, { ...report(), extra: true }, { ...report(), metadata: {} }]) {
    const f = fixture(); f.full = broken; assert.throws(() => check(f));
  }
  const f = fixture(); f.full.metadata.vulnerabilities.total = 0;
  assert.throws(() => check(f), /totals/);
});

test("dangling closure edges, cycles and unexpected installed paths are rejected", () => {
  let f = fixture(); f.full.vulnerabilities.vite.via = ["missing"];
  assert.throws(() => check(f), /closure/);
  f = fixture(); f.full.vulnerabilities.picomatch.via = ["vite"];
  assert.throws(() => check(f), /closure/);
  f = fixture(); f.full.vulnerabilities.picomatch.nodes = ["node_modules/runtime/node_modules/picomatch"];
  assert.throws(() => check(f), /dev-only/);
});

test("the exception expires at the UTC boundary and stops if an upstream release changes", () => {
  const f = fixture();
  assert.equal(evaluateAudit(f.full, f.prod, f.lock, { ...options, now: new Date("2026-11-24T23:59:59.999Z") }).exception, true);
  assert.throws(() => evaluateAudit(f.full, f.prod, f.lock, { ...options, now: new Date(EXCEPTION.expires) }), /expired/);
  assert.throws(() => evaluateAudit(f.full, f.prod, f.lock, { ...options, publishedVersion: "4.0.8" }), /Upstream/);
  assert.throws(() => evaluateAudit(f.full, f.prod, f.lock, { ...options, publishedVersion: undefined }), /Upstream/);
});

test("npm published-version metadata permits only a version string or one-string array", () => {
  assert.equal(normalizePublishedVersion("4.0.7"), "4.0.7");
  assert.equal(normalizePublishedVersion(["4.0.7"]), "4.0.7");
  for (const invalid of [[], ["4.0.7", "4.0.8"], {}, null, 407, "latest", [null], [["4.0.7"]]]) {
    assert.throws(() => normalizePublishedVersion(invalid), /schema/);
  }
  const f = fixture();
  assert.throws(() => evaluateAudit(f.full, f.prod, f.lock, { ...options, publishedVersion: normalizePublishedVersion(["4.0.8"]) }), /Upstream/);
});

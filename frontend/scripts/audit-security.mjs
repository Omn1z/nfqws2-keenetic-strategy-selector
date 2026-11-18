import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

export const EXCEPTION = Object.freeze({
  advisory: "https://github.com/advisories/GHSA-fc5q-39xc-vjpf",
  source: 1247710,
  range: "<=4.0.7",
  locked: "4.0.4",
  published: "4.0.7",
  expires: "2026-11-25T00:00:00.000Z",
});
const closure = new Set(["picomatch", "fdir", "tinyglobby", "vite"]);
const severities = ["info", "low", "moderate", "high", "critical"];
const object = value => !!value && typeof value === "object" && !Array.isArray(value);
const requireCheck = (condition, message) => { if (!condition) throw new Error(message); };

export function normalizePublishedVersion(value) {
  const version = Array.isArray(value) && value.length === 1 ? value[0] : value;
  requireCheck(typeof version === "string" && /^\d+\.\d+\.\d+$/.test(version), "Unknown npm published-version schema");
  return version;
}

export function validateReport(report) {
  requireCheck(object(report) && !report.error && report.auditReportVersion === 2 && object(report.vulnerabilities), "Unknown or failed npm audit report");
  requireCheck(Object.keys(report).every(key => ["auditReportVersion", "vulnerabilities", "metadata"].includes(key)), "Unknown npm audit schema");
  const counts = report.metadata?.vulnerabilities;
  requireCheck(object(counts) && [...severities, "total"].every(key => Number.isInteger(counts[key]) && counts[key] >= 0), "Missing npm vulnerability totals");
  const actual = Object.fromEntries(severities.map(key => [key, 0]));
  for (const [name, item] of Object.entries(report.vulnerabilities)) {
    requireCheck(object(item) && item.name === name && severities.includes(item.severity) && typeof item.isDirect === "boolean" &&
      Array.isArray(item.via) && item.via.length > 0 && Array.isArray(item.nodes) && item.nodes.length > 0 &&
      Array.isArray(item.effects) && typeof item.range === "string", "Unknown npm vulnerability schema");
    actual[item.severity]++;
  }
  requireCheck(severities.every(key => counts[key] === actual[key]) && counts.total === Object.keys(report.vulnerabilities).length, "Inconsistent npm audit totals");
  return report.vulnerabilities;
}

// Every finding must resolve exclusively to the one temporary build advisory.
// Production findings, new advisory objects, dangling edges and cycles fail.
export function evaluateAudit(fullReport, productionReport, lock, { now = new Date(), publishedVersion } = {}) {
  const production = validateReport(productionReport);
  requireCheck(Object.keys(production).length === 0, "Production dependency audit must have zero findings");
  const findings = validateReport(fullReport);
  const names = Object.keys(findings);
  if (!names.length) return { exception: false, affected: 0 };
  requireCheck(now instanceof Date && Number.isFinite(now.getTime()) && now.getTime() < Date.parse(EXCEPTION.expires), "Temporary picomatch exception expired");
  requireCheck(publishedVersion === EXCEPTION.published, "Upstream picomatch release changed; update dependencies and remove the temporary exception");
  requireCheck(object(lock) && lock.lockfileVersion === 3 && object(lock.packages), "Unknown package-lock schema");
  requireCheck(lock.packages["node_modules/picomatch"]?.version === EXCEPTION.locked, "Exception only covers locked picomatch 4.0.4");
  const root = lock.packages[""];
  requireCheck(object(root), "Missing lockfile root package");
  for (const section of [root.dependencies, root.optionalDependencies]) {
    requireCheck(!section || Object.keys(section).every(name => !closure.has(name)), "Build tooling must not be a production dependency");
  }
  for (const name of names) {
    const item = findings[name];
    requireCheck(closure.has(name) && item.severity === "high", "Unapproved dependency finding");
    requireCheck(item.nodes.length === 1 && item.nodes[0] === `node_modules/${name}` && lock.packages[item.nodes[0]]?.dev === true, "Affected dependency is not the approved dev-only node");
  }
  const visited = new Set();
  const visiting = new Set();
  const visit = name => {
    requireCheck(closure.has(name) && object(findings[name]) && !visiting.has(name), "Invalid advisory dependency closure");
    if (visited.has(name)) return;
    visiting.add(name);
    for (const via of findings[name].via) {
      if (typeof via === "string") { visit(via); continue; }
      requireCheck(object(via) && name === "picomatch" && via.url === EXCEPTION.advisory && via.source === EXCEPTION.source &&
        via.name === "picomatch" && via.dependency === "picomatch" && via.range === EXCEPTION.range && via.severity === "high", "Unapproved advisory or affected range");
    }
    visiting.delete(name);
    visited.add(name);
  };
  for (const name of names) visit(name);
  requireCheck(visited.has("picomatch"), "Missing approved advisory leaf");
  return { exception: true, affected: names.length };
}

function npmJSON(args, cwd, audit = false) {
  const npm = process.env.npm_execpath;
  const command = npm ? process.execPath : "npm";
  const argv = [...(npm ? [npm] : []), ...args, "--registry=https://registry.npmjs.org"];
  const result = spawnSync(command, argv, { cwd, encoding: "utf8", timeout: 120_000, maxBuffer: 16 * 1024 * 1024 });
  requireCheck(!result.error && !result.signal && (result.status === 0 || audit && result.status === 1), "npm command failed; audit was not accepted");
  let report;
  try { report = JSON.parse(result.stdout); } catch { throw new Error("npm returned invalid JSON"); }
  if (audit) {
    const findings = validateReport(report);
    requireCheck(result.status === (Object.keys(findings).length ? 1 : 0), "Unexpected npm audit exit status");
  } else requireCheck(result.status === 0, "npm metadata request failed");
  return report;
}

export function runSecurityAudit(cwd) {
  const lock = JSON.parse(readFileSync(resolve(cwd, "package-lock.json"), "utf8"));
  const full = npmJSON(["audit", "--json", "--audit-level=low"], cwd, true);
  const production = npmJSON(["audit", "--omit=dev", "--json", "--audit-level=low"], cwd, true);
  const publishedVersion = Object.keys(full.vulnerabilities).length ? normalizePublishedVersion(npmJSON(["view", "picomatch", "version", "--json", "--prefer-online"], cwd)) : undefined;
  const result = evaluateAudit(full, production, lock, { publishedVersion });
  console.log("Production dependency audit: zero findings.");
  if (result.exception) console.log(`Temporary build-only GHSA-fc5q-39xc-vjpf exception: ${result.affected} dev dependencies; expires ${EXCEPTION.expires}. Upstream latest remains ${publishedVersion}.`);
  else console.log("Full dependency audit: zero findings.");
}

// Filename check also keeps the pure policy importable by the bundled UI tests.
if (process.argv[1]?.replaceAll("\\", "/").endsWith("/audit-security.mjs")) {
  try { runSecurityAudit(dirname(dirname(resolve(process.argv[1])))); }
  catch (error) { console.error(`Security audit failed: ${error.message}`); process.exitCode = 1; }
}

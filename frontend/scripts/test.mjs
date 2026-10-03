import { build } from "esbuild";
import { readdir, mkdtemp, rm, rmdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
async function collect(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const groups = await Promise.all(entries.map(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? collect(path) : /\.test\.(?:tsx?|mjs)$/.test(entry.name) ? [path] : [];
  }));
  return groups.flat().sort();
}
const tests = [...await collect(join(root, "src")), ...await collect(join(root, "scripts"))];
if (!tests.length) throw new Error("No frontend tests found");
const temporary = await mkdtemp(join(tmpdir(), "n2s-ui-tests-"));
const output = join(temporary, "tests.cjs");
try {
  await build({
    stdin: { contents: tests.map(path => `import ${JSON.stringify(path.replaceAll("\\", "/"))};`).join("\n"), resolveDir: root },
    bundle: true, platform: "node", format: "cjs", outfile: output,
    tsconfig: join(root, "tsconfig.json"), logLevel: "warning",
  });
  const result = spawnSync(process.execPath, ["--test", output], { cwd: root, stdio: "inherit" });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  await rm(output, { force: true });
  await rmdir(temporary);
}

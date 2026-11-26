import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const root = fileURLToPath(new URL("../../", import.meta.url));
const build = join(root, "dist", "compact-ui");
const embedded = join(root, "internal", "server", "compactweb");
const raw = join(build, "raw");
const manifest = await readFile(join(raw, "modules.json"));
const modules = new Set(Object.values(JSON.parse(manifest)));
await rm(embedded, { recursive: true, force: true });
await rm(join(build, "modules"), { recursive: true, force: true });
await mkdir(embedded, { recursive: true });
await writeFile(join(embedded, "modules.json"), manifest);

async function stage(dir = "") {
  for (const entry of await readdir(join(raw, dir), { withFileTypes: true })) {
    const path = dir ? dir + "/" + entry.name : entry.name;
    if (entry.isDirectory()) {
      await stage(path);
    } else if (path !== "modules.json") {
      if (!(modules.has(path) || path === "index.html" || path.startsWith("ui/"))) throw new Error(`Unknown UI asset ${path}`);
      const output = join(modules.has(path) ? build : embedded, path + ".gz");
      await mkdir(dirname(output), { recursive: true });
      await writeFile(output, gzipSync(await readFile(join(raw, path)), { level: 9 }));
    }
  }
}
await stage();

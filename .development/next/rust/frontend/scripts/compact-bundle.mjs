import { checkRouterDependencies } from "./inline-bundle.mjs";

const pages = new Map([
  ["Runs.tsx", "runs"], ["BlockCheck.tsx", "blockcheck"],
  ["Strategies.tsx", "strategies"], ["Geo.tsx", "geo"],
]);

export function compactChunkName(chunk) {
  const page = pages.get(chunk.facadeModuleId?.split(/[/\\]/).pop());
  return page ? `modules/${page}/${page}-[hash].js` : "ui/[name]-[hash].js";
}

export function compactBundle() {
  return { name: "router-compact", enforce: "post", generateBundle(_options, bundle) {
    checkRouterDependencies(bundle);
    const modules = {};
    for (const name of Object.keys(bundle)) {
      const chunk = bundle[name];
      if (chunk.type !== "chunk") continue;
      if (chunk.imports.some(path => path.startsWith("modules/"))) {
        throw new Error(`Optional pages must load independently: ${name}`);
      }
      if (name.startsWith("modules/")) modules[name.split("/")[1]] = name;
    }
    for (const id of pages.values()) if (!modules[id]) throw new Error(`Missing optional page: ${id}`);
    this.emitFile({ type: "asset", fileName: "modules.json", source: JSON.stringify(modules) });
  } };
}

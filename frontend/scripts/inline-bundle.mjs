// The router serves one embedded HTML file. Inline only build-owned assets,
// and fail if any new external chunk/asset would make that file incomplete.
export function inlineRouterBundle(bundle) {
  const html = bundle["index.html"];
  if (!html || html.type !== "asset" || typeof html.source !== "string") throw new Error("Missing index.html build asset");
  const consumed = new Set(["index.html"]);
  const assetFor = (url) => bundle[url.replace(/^(?:\.\/|\/)/, "")];
  const script = (url) => {
    const asset = assetFor(url);
    if (!asset || asset.type !== "chunk" || asset.imports.length || asset.dynamicImports.length) throw new Error(`Script is not self-contained: ${url}`);
    if (/<\/script\b|<!--/i.test(asset.code)) throw new Error(`Unsafe inline script delimiter: ${url}`);
    consumed.add(asset.fileName);
    return `<script type="module">${asset.code}</script>`;
  };
  const style = (url) => {
    const asset = assetFor(url);
    if (!asset || asset.type !== "asset" || !asset.fileName.endsWith(".css") || typeof asset.source !== "string") throw new Error(`Missing stylesheet: ${url}`);
    if (/<\/style\b/i.test(asset.source)) throw new Error(`Unsafe inline style delimiter: ${url}`);
    consumed.add(asset.fileName);
    return `<style>${asset.source}</style>`;
  };
  let output = html.source.replace(/<script\b[^>]*\bsrc="([^"]+)"[^>]*>\s*<\/script>/g, (_, url) => script(url));
  output = output.replace(/<link\b(?=[^>]*\brel="stylesheet")[^>]*\bhref="([^"]+)"[^>]*>/g, (_, url) => style(url));
  for (const name of Object.keys(bundle)) if (!consumed.has(name)) throw new Error(`Unembedded router asset: ${name}`);
  if (/<script\b[^>]*\bsrc\s*=|<link\b[^>]*\b(?:stylesheet|modulepreload)\b/i.test(output)) throw new Error("External resources remain in router HTML");
  html.source = output;
  for (const name of consumed) if (name !== "index.html") delete bundle[name];
}

export function routerSingleFile() {
  return { name: "router-single-file", enforce: "post", generateBundle(_options, bundle) { inlineRouterBundle(bundle); } };
}

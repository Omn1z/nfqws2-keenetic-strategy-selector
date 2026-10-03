import assert from "node:assert/strict";
import test from "node:test";
import { inlineRouterBundle } from "./inline-bundle.mjs";

const fixture = () => ({
  "index.html": { type: "asset", fileName: "index.html", source: '<head><script type="module" crossorigin src="./index.js"></script><link rel="stylesheet" crossorigin href="./index.css"></head>' },
  "index.js": { type: "chunk", fileName: "index.js", imports: [], dynamicImports: [], code: 'const text="$& literal";' },
  "index.css": { type: "asset", fileName: "index.css", source: '@font-face{src:url(data:font/woff2;base64,AA==)}body{color:red}' },
});
test("router build embeds script, stylesheet and font without replacement interpolation", () => {
  const bundle = fixture(); inlineRouterBundle(bundle);
  assert.deepEqual(Object.keys(bundle), ["index.html"]);
  assert.ok(bundle["index.html"].source.includes('const text="$& literal";'));
  assert.ok(bundle["index.html"].source.includes('data:font/woff2;base64,AA=='));
  assert.ok(!bundle["index.html"].source.includes('src="./'));
});
test("incomplete or external router builds fail without deleting original assets", () => {
  for (const change of [
    b => { b["extra.png"] = { type: "asset", fileName: "extra.png", source: "image" }; },
    b => { b["index.js"].imports = ["other.js"]; },
    b => { b["index.js"].dynamicImports = ["lazy.js"]; },
    b => { b["index.html"].source = b["index.html"].source.replace("./index.js", "https://example.org/script.js"); },
    b => { b["index.js"].code = 'const unsafe="</script>";'; },
    b => { b["index.css"].source = 'body:after{content:"</style>"}'; },
  ]) { const bundle = fixture(); change(bundle); assert.throws(() => inlineRouterBundle(bundle)); assert.ok(bundle["index.js"]); }
});

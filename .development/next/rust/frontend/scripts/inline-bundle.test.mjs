import assert from "node:assert/strict";
import test from "node:test";
import { inlineRouterBundle } from "./inline-bundle.mjs";

const fixture = () => ({
  "index.html": { type: "asset", fileName: "index.html", source: '<head><script type="module" crossorigin src="./index.js"></script><link rel="stylesheet" crossorigin href="./index.css"></head>' },
  "index.js": { type: "chunk", fileName: "index.js", imports: [], dynamicImports: [], modules: { "/ui/src/main.tsx": {} }, code: 'const text="$& literal";' },
  "index.css": { type: "asset", fileName: "index.css", source: '@font-face{src:url(data:font/woff2;base64,AA==)}body{color:red}' },
});
test("router build rejects picomatch runtime modules before inlining", () => {
  for (const id of [
    "/ui/node_modules/picomatch/lib/parse.js",
    "node_modules/picomatch/index.js",
    "C:\\ui\\node_modules\\picomatch\\lib\\parse.js",
    "/ui/node_modules/.pnpm/picomatch@4.0.4/node_modules/picomatch/index.js",
  ]) {
    const bundle = fixture();
    bundle["index.js"].modules[id] = {};
    const originalHTML = bundle["index.html"].source;
    assert.throws(() => inlineRouterBundle(bundle), /Build-only dependency picomatch/);
    assert.equal(bundle["index.html"].source, originalHTML);
    assert.ok(bundle["index.js"]);
    assert.ok(bundle["index.css"]);
  }
  // Check every output chunk, even one not referenced by the HTML entry.
  const bundle = fixture();
  bundle["extra.js"] = { type: "chunk", fileName: "extra.js", modules: { "/ui/node_modules/picomatch/index.js": {} } };
  assert.throws(() => inlineRouterBundle(bundle), /Build-only dependency picomatch/);
});
for (const name of ["fdir", "tinyglobby"]) {
  test(`router build rejects ${name} runtime modules before inlining`, () => {
    const bundle = fixture();
    bundle["index.js"].modules[`/ui/node_modules/.pnpm/${name}@1.0.0/node_modules/${name}/dist/index.js`] = {};
    const originalHTML = bundle["index.html"].source;
    assert.throws(() => inlineRouterBundle(bundle), new RegExp(`Build-only dependency ${name}`));
    assert.equal(bundle["index.html"].source, originalHTML);
    assert.ok(bundle["index.js"]);
    assert.ok(bundle["index.css"]);
  });
}
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

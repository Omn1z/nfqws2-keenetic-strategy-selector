import assert from "node:assert/strict";
import test from "node:test";
import { geoImportPayload, geoSummary, retainedGeoCategory } from "./geoView";

test("geo summaries count real categories and retain text databases", () => {
  assert.deepEqual(geoSummary([
    { name: "geosite.dat", kind: "geosite", categories: [{ name: "youtube", count: 1000 }, { name: "telegram", count: 5 }] },
    { name: "custom.dat", kind: "geosite", categories: [{ name: "custom", count: 1 }] },
    { name: "geoip.dat", kind: "geoip", categories: [{ name: "ru", count: 900 }] },
    { name: "local.txt", kind: "text", categories: [{ name: "all", count: 20 }] },
  ]), { files: 4, geosite: 3, geoip: 1, text: 1 });
  assert.deepEqual(geoSummary([]), { files: 0, geosite: 0, geoip: 0, text: 0 });
});

test("geo category refresh preserves the exact selection or requests a new explicit choice", () => {
  const categories = [{ name: "telegram", count: 20 }, { name: "google", count: 50 }];
  assert.equal(retainedGeoCategory("google", categories), "google");
  assert.equal(retainedGeoCategory("removed", categories), "");
  assert.equal(retainedGeoCategory("", categories), "");
  assert.equal(retainedGeoCategory("google", []), "");
});

test("geo imports preserve zero-for-all, target identity, category and trimmed new-list name", () => {
  assert.deepEqual(geoImportPayload("custom.dat", "google@ads", "0", "target-id", "  New list  "), {
    geo: "custom.dat", category: "google@ads", limit: 0, list_id: "target-id", list_name: "New list",
  });
  assert.equal(geoImportPayload("a.dat", "all", "", "", "").limit, 0);
  assert.equal(geoImportPayload("a.dat", "all", "25", "", "").limit, 25);
  for (const limit of ["-1", "2.5", "bad", "Infinity"]) assert.throws(() => geoImportPayload("a.dat", "all", limit, "", ""), /Лимит/);
});

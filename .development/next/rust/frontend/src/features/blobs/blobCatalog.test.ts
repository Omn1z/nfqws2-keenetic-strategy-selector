import assert from "node:assert/strict";
import test from "node:test";
import { availableBlobSelection, blobCatalog, blobRows } from "./blobCatalog";

const inventory = { custom: ["same.bin", "custom.bin"], system: ["same.bin", "system.bin"], trash: ["deleted.bin"] };

test("blob catalog matches custom-first backend resolution without changing physical inventories", () => {
  assert.deepEqual(blobCatalog(inventory), [{ name: "same.bin", custom: true }, { name: "custom.bin", custom: true }, { name: "system.bin", custom: false }]);
  assert.deepEqual(inventory.system, ["same.bin", "system.bin"]);
  assert.equal(inventory.custom.length + inventory.system.length, 4);
  assert.equal(blobCatalog(inventory).length, 3);
});

test("blob source and case-insensitive name filters compose with both sort directions", () => {
  const entries = blobCatalog(inventory);
  assert.deepEqual(blobRows(entries, " BIN ", "custom", { key: "name", dir: 1 }).map(entry => entry.name), ["custom.bin", "same.bin"]);
  assert.deepEqual(blobRows(entries, "", "all", { key: "name", dir: -1 }).map(entry => entry.name), ["system.bin", "same.bin", "custom.bin"]);
  assert.deepEqual(blobRows(entries, "", "system", { key: "type", dir: 1 }), [{ name: "system.bin", custom: false }]);
  assert.deepEqual(blobRows(entries, "absent", "all", { key: "name", dir: 1 }), []);
  assert.equal(entries[0].name, "same.bin");
});

test("catalog refresh removes only unavailable selections, retaining hidden and shadowed names", () => {
  const selected = new Set(["custom.bin", "system.bin", "same.bin", "deleted.bin"]);
  assert.deepEqual([...availableBlobSelection(selected, blobCatalog(inventory))], ["custom.bin", "system.bin", "same.bin"]);
  const afterCustomDeletion = blobCatalog({ ...inventory, custom: ["custom.bin"] });
  assert.deepEqual([...availableBlobSelection(selected, afterCustomDeletion)], ["custom.bin", "system.bin", "same.bin"]);
  const current = new Set(["system.bin"]);
  assert.equal(availableBlobSelection(current, blobCatalog(inventory)), current);
});

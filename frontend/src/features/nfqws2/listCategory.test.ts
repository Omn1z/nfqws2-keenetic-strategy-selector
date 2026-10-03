import assert from "node:assert/strict";
import test from "node:test";
import { listCategory } from "./listCategory";
import { folderEntries, uploadPath, type Asset } from "./fileExplorerModel";

test("only the final list-opkg suffix selects originals without hiding other list formats", () => {
  for (const path of ["user.list-opkg", "lists/auto.list-opkg", "lists/nested/ipset.LIST-OPKG", "lists/nested/auto.list-opkg.gz"]) assert.equal(listCategory(path), "original", path);
  for (const path of ["user.list", "lists/userlist.txt", "lists/user.list.gz", "lists/user.list-opkg.bak", "lists/archive.list-opkg/user.list", "lists/user.opkg", "lists/user-list-opkg"]) assert.equal(listCategory(path), "current", path);
});

test("list categories preserve file identity, metadata, search results and upload destinations", () => {
  const paths = ["lists/user.list", "lists/user.list-opkg", "lists/nested/auto.list", "lists/nested/auto.list-opkg", "lists/custom.txt"];
  const assets: Asset[] = paths.map(path => ({ path, kind: "list", size: 17, editable: true, protected: false, modified_at: "2026-10-03T10:00:00Z" }));
  const current = folderEntries(assets, "lists").filter(entry => entry.type === "folder" || listCategory(entry.path) === "current");
  assert.deepEqual(current.map(entry => entry.path), ["lists/nested", "lists/custom.txt", "lists/user.list"]);
  const found = folderEntries(assets, "lists", "AUTO").filter(entry => entry.type === "file" && listCategory(entry.path) === "original");
  assert.equal(found.length, 1);
  assert.equal(found[0].type, "file");
  if (found[0].type !== "file") throw new Error("expected original list file");
  assert.equal(found[0].asset, assets[3]);
  assert.equal(found[0].path, "lists/nested/auto.list-opkg");
  assert.equal(found[0].name, "nested/auto.list-opkg");
  assert.equal(found[0].modifiedAt, assets[3].modified_at);
  assert.equal(uploadPath("lists/nested", "auto.list-opkg"), found[0].path);
});

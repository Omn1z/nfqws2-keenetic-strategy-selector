import assert from "node:assert/strict";
import test from "node:test";
import { breadcrumbs, createModifiedTimeFormatter, filesFromDrop, folderEntries, knownFolders, parentFolder, physicalFolder, uploadPath } from "./fileExplorerModel";
import type { Asset } from "./fileExplorerModel";

const asset = (path: string): Asset => ({ path, kind: "list", size: 10, editable: true, protected: path === "nfqws2.conf" });
const files = ["nfqws2.conf", "configs/backup.conf", "lists/userlist.txt", "lists/nested/deep/a.txt", "lists/nested/b.txt", "lists-other/hidden.txt", "blobs/fake.bin"].map(asset);

test("modification times follow each actual file or directory and tolerate older servers", () => {
  const oldTime = "2024-07-06T05:09:10.1234567Z";
  const newerTime = "2024-07-07T05:09:10Z";
  const source = [{ ...asset("lists/nested/file.txt"), modified_at: newerTime }, { ...asset("nfqws2.conf"), modified_at: newerTime }];
  const directoryModified = { lists: oldTime, "lists/nested": oldTime, "lists/empty": oldTime, configs: oldTime, scripts: oldTime };
  assert.equal(folderEntries(source, "", "", [], directoryModified).find(e => e.path === "lists")?.modifiedAt, oldTime);
  assert.equal(folderEntries(source, "lists", "", [], directoryModified)[0].modifiedAt, oldTime);
  assert.equal(folderEntries(source, "lists/nested", "", [], directoryModified)[0].modifiedAt, newerTime);
  assert.equal(folderEntries(source, "configs", "", [], directoryModified)[0].modifiedAt, newerTime);
  assert.equal(folderEntries([], "lists", "", ["lists/empty"], directoryModified)[0].modifiedAt, oldTime);
  assert.equal(folderEntries(source, "lists")[0].modifiedAt, undefined);
  assert.equal(folderEntries([asset("lists/old.txt")], "lists")[0].modifiedAt, undefined);
});

test("modification dates use the chosen browser zone across midnight and daylight saving", () => {
  const minsk = createModifiedTimeFormatter("Europe/Minsk");
  const date = minsk("2026-10-03T22:05:10.123456789Z");
  assert.equal(date.label, "04.10.2026, 01:05");
  assert.equal(date.dateTime, "2026-10-03T22:05:10.123Z");
  assert.match(date.title, /01:05:10/);
  assert.match(date.title, /Europe\/Minsk/);
  assert.equal(minsk("2026-10-04T01:05:10.123+03:00").label, date.label);
  const berlin = createModifiedTimeFormatter("Europe/Berlin");
  assert.equal(berlin("2026-03-29T00:30:00Z").label, "29.03.2026, 01:30");
  assert.equal(berlin("2026-03-29T01:30:00Z").label, "29.03.2026, 03:30");
});

test("unknown and malformed dates never become now or a misleading normalized date", () => {
  const format = createModifiedTimeFormatter("UTC");
  for (const value of [undefined, "", "n/a", "2026-10-03", "2026-10-03T10:30:00", "0001-01-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z", "2026-01-01T00:60:00Z", "2026-01-01T00:00:60Z"]) {
    assert.deepEqual(format(value), { label: "—", title: "Время изменения неизвестно" }, String(value));
  }
  assert.equal(format("2024-02-29T00:00:00Z").label, "29.02.2024, 00:00");
});

test("navigation exposes immediate folders and the virtual active config without leaking neighbouring roots", () => {
  assert.deepEqual(folderEntries(files, "lists").map(e => [e.type, e.name]), [["folder", "nested"], ["file", "userlist.txt"]]);
  assert.deepEqual(folderEntries(files, "lists/nested").map(e => [e.type, e.name]), [["folder", "deep"], ["file", "b.txt"]]);
  assert.deepEqual(folderEntries(files, "configs").map(e => e.path), ["configs/backup.conf", "nfqws2.conf"]);
  assert.equal(folderEntries(files, "lists", "hidden").length, 0);
});

test("recursive search keeps a result's real download path and displays its relative location", () => {
  assert.deepEqual(folderEntries(files, "lists", "A.TXT").map(e => [e.name, e.path]), [["nested/deep/a.txt", "lists/nested/deep/a.txt"]]);
  assert.equal(folderEntries(files, "blobs", "a.txt").length, 0);
});

test("empty server folders remain browsable and ancestor paths are included", () => {
  const directories = ["lists/empty/deep", "lua/empty", "unrelated/private"];
  assert.ok(knownFolders([], directories).includes("lists/empty"));
  assert.ok(!knownFolders([], directories).includes("unrelated"));
  assert.deepEqual(folderEntries([], "lists", "", directories).map(e => e.path), ["lists/empty"]);
  assert.deepEqual(folderEntries([], "lists/empty/deep", "", directories), []);
});

test("breadcrumbs and platform paths never confuse virtual sections with router directories", () => {
  assert.deepEqual(breadcrumbs("lists/deep/more").map(e => e.path), ["", "lists", "lists/deep", "lists/deep/more"]);
  assert.equal(parentFolder("lists/deep"), "lists");
  assert.equal(parentFolder("lists"), "");
  assert.equal(physicalFolder("lists/deep", { list: "/opt/etc/nfqws2/lists/" }), "/opt/etc/nfqws2/lists/deep");
  assert.equal(physicalFolder("configs", { conf: "/etc/nfqws2" }), "/etc/nfqws2");
  assert.equal(physicalFolder("scripts", { script: "/etc/nfqws2" }), "/etc/nfqws2");
});

test("uploads preserve subfolders, resolve the active config alias and enforce the server namespace", () => {
  assert.equal(uploadPath("lists/existing", "incoming/deep/a.txt"), "lists/existing/incoming/deep/a.txt");
  assert.equal(uploadPath("configs", "nfqws2.conf"), "nfqws2.conf");
  assert.equal(uploadPath("scripts", "custom.sh"), "scripts/custom.sh");
  for (const path of ["../outside", "/absolute", "a//b", "a/./b", "a\\b", "a:b", ".hidden", "trailing.", "x\n.txt", "a/../../x"]) assert.throws(() => uploadPath("lists", path), path);
  assert.throws(() => uploadPath("configs", "folder/a.conf"));
  assert.throws(() => uploadPath("scripts", "folder/a.sh"));
  assert.throws(() => uploadPath("configs", "unknown.txt"));
  assert.throws(() => uploadPath("", "a.txt"));
  assert.throws(() => uploadPath("lists", "a/".repeat(10) + "file.txt"));
});

test("directory drops drain multiple browser batches and keep every relative path", async () => {
  const fileEntry = (name: string) => ({ name, isFile: true, isDirectory: false, file: (resolve: (f: File) => void) => resolve({ name } as File) });
  let reads = 0;
  const firstBatch = Array.from({ length: 100 }, (_, index) => fileEntry(`${index}.txt`));
  const dir = { name: "incoming", isFile: false, isDirectory: true, createReader: () => ({ readEntries: (resolve: (items: unknown[]) => void) => resolve([firstBatch, [fileEntry("second-batch.txt")], []][reads++]) }) };
  const result = await filesFromDrop({ items: [{ kind: "file", webkitGetAsEntry: () => dir, getAsFile: () => null }], files: [] } as unknown as DataTransfer);
  assert.equal(result.length, 101);
  assert.equal(result[0].relativePath, "incoming/0.txt");
  assert.equal(result[100].relativePath, "incoming/second-batch.txt");
  assert.equal(reads, 3);
});

test("mixed and legacy drops do not discard plain files without filesystem handles", async () => {
  const file = { name: "plain.txt", webkitRelativePath: "" } as File;
  assert.deepEqual((await filesFromDrop({ items: [], files: [file] } as unknown as DataTransfer)).map(f => f.relativePath), ["plain.txt"]);
  const entry = { name: "entry.txt", isFile: true, isDirectory: false, file: (resolve: (f: File) => void) => resolve(file) };
  const mixed = { items: [{ kind: "file", webkitGetAsEntry: () => entry, getAsFile: () => null }, { kind: "file", getAsFile: () => file }], files: [file] } as unknown as DataTransfer;
  assert.deepEqual((await filesFromDrop(mixed)).map(f => f.relativePath), ["entry.txt", "plain.txt"]);
});

import test from "node:test";
import assert from "node:assert/strict";
import { lazyCatalog } from "./StoreProvider";

test("optional catalog loads once on first use and shares empty results across tabs", async () => {
  let reads = 0;
  const received: string[][] = [];
  const catalog = lazyCatalog<string>(async () => { reads++; return null; }, items => received.push(items));
  assert.equal(reads, 0);
  const first = catalog.load();
  assert.equal(catalog.load(), first);
  await first;
  await catalog.load();
  assert.equal(reads, 1);
  assert.deepEqual(received, [[]]);
});

test("a mutation refresh supersedes an older in-flight optional catalog read", async () => {
  const finish: ((items: string[]) => void)[] = [];
  const received: string[][] = [];
  const catalog = lazyCatalog<string>(() => new Promise(resolve => finish.push(resolve)), items => received.push(items));
  const old = catalog.load();
  const fresh = catalog.reload();
  finish[1](["new"]);
  await fresh;
  finish[0](["old"]);
  await old;
  assert.deepEqual(received, [["new"]]);
  assert.equal(catalog.load(), fresh);
});

test("a failed optional catalog read is retried on the next visit", async () => {
  let reads = 0;
  const errors: unknown[] = [];
  const received: string[][] = [];
  const catalog = lazyCatalog(async () => {
    if (++reads === 1) throw Error("offline");
    return ["available"];
  }, items => received.push(items), cause => errors.push(cause));
  await catalog.load();
  await catalog.load();
  assert.equal(errors.length, 1);
  assert.deepEqual(received, [["available"]]);
});

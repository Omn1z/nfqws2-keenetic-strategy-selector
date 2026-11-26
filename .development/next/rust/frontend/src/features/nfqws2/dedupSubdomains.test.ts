import assert from "node:assert/strict";
import test from "node:test";
import { dedupSubdomains } from "./dedupSubdomains";

test("subdomain dedup uses existing ancestors regardless of file order", () => {
  const result = dedupSubdomains("cdn.api.example.com\napi.example.com\nexample.com\nother.net\n");
  assert.equal(result.content, "example.com\nother.net\n");
  assert.equal(result.removed, 2);
});

test("siblings alone never create a broader parent or cross label boundaries", () => {
  const source = "one.example.com\ntwo.example.com\nnotexample.com\nexample.com.evil.net\n";
  assert.deepEqual(dedupSubdomains(source), { content: source, removed: 0, examples: [] });
  assert.equal(dedupSubdomains(source + "example.com\n").content, "notexample.com\nexample.com.evil.net\nexample.com\n");
});

test("strict rules never cover children and remain explicit in the result", () => {
  const source = "^example.com\napi.example.com\ncdn.api.example.com\n^exact.api.example.com\n";
  assert.equal(dedupSubdomains(source).content, "^example.com\napi.example.com\n^exact.api.example.com\n");
  assert.equal(dedupSubdomains("example.com\n^api.example.com\n").removed, 0);
});

test("the first duplicate controls strictness just as NFQWS2's hash pool does", () => {
  const strictFirst = "^Example.COM # exact on purpose\nexample.com\napi.example.com\n";
  assert.equal(dedupSubdomains(strictFirst).content, strictFirst);
  const strictWithTail = "^example.com arbitrary text\nexample.com\napi.example.com\n";
  assert.equal(dedupSubdomains(strictWithTail).content, strictWithTail);
  const normalFirst = "Example.COM\n^example.com\napi.example.com\n";
  assert.equal(dedupSubdomains(normalFirst).content, "Example.COM\n^example.com\n");
});

test("whitespace, comments, notes, order and original line endings are preserved", () => {
  const source = "# heading\r\n\tEXAMPLE.com \r\n  api.example.com\r\n\r\n; note\r\n// note\r\n  keep.example.com # explanation\r\nother.net";
  const result = dedupSubdomains(source);
  assert.equal(result.content, "# heading\r\n\tEXAMPLE.com \r\n\r\n; note\r\n// note\r\n  keep.example.com # explanation\r\nother.net");
  assert.equal(result.removed, 1);
  const bareCR = "a.example.com\rexample.com\n";
  assert.equal(dedupSubdomains(bareCR).content, bareCR);
});

test("annotated parent entries cover children, literal hashes are not comments", () => {
  assert.equal(dedupSubdomains("api.example.com\nexample.com # parent\n").content, "example.com # parent\n");
  const source = "example.com#note\napi.example.com\n";
  assert.equal(dedupSubdomains(source).content, source);
});

test("IP addresses, CIDRs, masks, URLs, foreign syntax and Unicode remain unchanged", () => {
  const source = "com\n1\n127.0.0.1\n192.0.2.1\n192.0.2.0/24\n2001:db8::1\n*.example.com\n.example.com\nexample.com.\nhttps://example.com\nfull:api.example.com\nпример.рф\nwww.пример.рф\n\u00a0example.com\nexample.com\n";
  assert.equal(dedupSubdomains(source).content, source.split("\n").filter(line => line !== "example.com").join("\n"));
  const idn = "пример.рф\nwww.xn--e1afmkfd.xn--p1ai\n";
  assert.equal(dedupSubdomains(idn).content, idn);
  assert.equal(dedupSubdomains("xn--e1afmkfd.xn--p1ai\nwww.xn--e1afmkfd.xn--p1ai\n").removed, 1);
});

test("ordinary duplicate removal stays separate from subdomain dedup", () => {
  const source = "example.com\nEXAMPLE.COM\nexample.com\n";
  assert.equal(dedupSubdomains(source).content, source);
});

test("binary terminators leave the entire source unchanged", () => {
  for (const source of ["example.com\0\napi.example.com\n", "^example.com\0ignored\nexample.com\napi.example.com\n"]) {
    assert.deepEqual(dedupSubdomains(source), { content: source, removed: 0, examples: [], skipped: "format" });
  }
});

test("long physical lines cannot hide a strict entry in a later fgets chunk", () => {
  for (const prefix of ["#".repeat(4095), "#" + "я".repeat(2047)]) {
    const source = prefix + "^example.com\nexample.com\na.example.com\n";
    assert.deepEqual(dedupSubdomains(source), { content: source, removed: 0, examples: [], skipped: "format" });
  }
  const safe = "#".repeat(4094) + "\nexample.com\na.example.com\n";
  assert.equal(dedupSubdomains(safe).removed, 1);
});

test("repeated dedup is stable and keeps the effective covering parent", () => {
  const source = "a.b.example.com\nb.example.com\n^example.com\nexample.com\ncom\n";
  const result = dedupSubdomains(source);
  assert.equal(result.content, "^example.com\ncom\n");
  assert.deepEqual(dedupSubdomains(result.content), { content: result.content, removed: 0, examples: [] });
});

test("large sibling lists use bounded previews and retain the late parent and unrelated hosts", () => {
  const source = Array.from({ length: 20_000 }, (_, i) => `cdn${i}.example.com\n`).join("") + "other.net\nexample.com\n";
  const result = dedupSubdomains(source);
  assert.equal(result.removed, 20_000);
  assert.equal(result.content, "other.net\nexample.com\n");
  assert.equal(result.examples.length, 8);
});

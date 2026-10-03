import assert from "node:assert/strict";
import test from "node:test";
import { EditorState } from "@codemirror/state";
import { StringStream, ensureSyntaxTree } from "@codemirror/language";
import { highlightTree, tagHighlighter, tags } from "@lezer/highlight";
import { strategyLanguage, strategyParser } from "./strategyLanguage";

function tokenize(source: string) {
  const state = strategyParser.startState!(2);
  const result: [string, string | null][] = [];
  for (const line of source.split(/\r?\n/)) {
    const stream = new StringStream(line, 2, 2);
    while (!stream.eol()) {
      stream.start = stream.pos;
      const style = strategyParser.token(stream, state);
      assert.ok(stream.pos > stream.start, `Tokenizer must advance at ${stream.start}: ${line}`);
      result.push([stream.current(), style]);
    }
  }
  return result;
}
const significant = (source: string) => tokenize(source).filter(([, style]) => style !== null);

test("complete hyphenated flags, numbers and Lua functions receive distinct tokens", () => {
  assert.deepEqual(significant("--filter-tcp=443 --lua-desync=fake:blob=0x00000000:tcp_ack=-66000:badsum --new"), [
    ["--filter-tcp", "option"], ["=", "operator"], ["443", "number"],
    ["--lua-desync", "option"], ["=", "operator"], ["fake", "function"],
    [":", "punctuation"], ["blob", "parameter"], ["=", "operator"], ["0x00000000", "number"],
    [":", "punctuation"], ["tcp_ack", "parameter"], ["=", "operator"], ["-66000", "number"],
    [":", "punctuation"], ["badsum", "parameter"], ["--new", "option"],
  ]);
});

test("nested Lua parameter lists do not mistake values or new filters for function names", () => {
  const tokens = significant("--lua-desync=fake:tls_mod=rnd,dupsid,sni=www.google.com:repeats=2 --lua-desync=multisplit:pos=1,midsld-2 --filter-l7=tls");
  assert.deepEqual(tokens.filter(([, style]) => style === "function"), [["fake", "function"], ["multisplit", "function"]]);
  assert.deepEqual(tokens.filter(([, style]) => style === "parameter").map(([word]) => word), ["tls_mod", "sni", "repeats", "pos"]);
  assert.ok(tokens.some(([word, style]) => word === "www.google.com" && style === "string"));
  assert.ok(tokens.some(([word, style]) => word === "midsld-2" && style === "string"));
  assert.ok(tokens.some(([word, style]) => word === "tls" && style === "string"));
});

test("paths, variables, escaped spaces and the next flag keep their boundaries", () => {
  const source = String.raw`--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua --hostlist=${"${ROOT}"}/lists/a\ b.list $MODE_AUTO --blob=quic:@/etc/nfqws2/blobs/quic.bin`;
  const tokens = significant(source);
  assert.ok(tokens.some(([word, style]) => word === "@/opt/etc/nfqws2/lua/zapret-lib.lua" && style === "string"));
  assert.ok(tokens.some(([word, style]) => word === "${ROOT}" && style === "variable"));
  assert.ok(tokens.some(([word, style]) => word === "\\ " && style === "escape"));
  assert.ok(tokens.some(([word, style]) => word === "$MODE_AUTO" && style === "variable"));
  assert.ok(tokens.some(([word, style]) => word === "--blob" && style === "option"));
  assert.ok(tokens.some(([word, style]) => word === "@/etc/nfqws2/blobs/quic.bin" && style === "string"));
});

test("comments are only comments at unquoted word boundaries", () => {
  const source = '--hostlist=/tmp/a#b.list --host=example#fragment # actual comment\n--host="literal # value --new" --next';
  const tokens = significant(source);
  assert.deepEqual(tokens.filter(([, style]) => style === "comment"), [["# actual comment", "comment"]]);
  assert.deepEqual(tokens.filter(([, style]) => style === "option").map(([word]) => word), ["--hostlist", "--host", "--host", "--next"]);
});

test("quotes preserve multiline state and distinguish literal from expanded variables", () => {
  const source = '--host="first\n$HOST # literal" --host=\'$LITERAL\' --host="\\$ESCAPED" --lua-desync="fake:blob=tls_clienthello"';
  const tokens = significant(source);
  assert.deepEqual(tokens.filter(([, style]) => style === "variable"), [["$HOST", "variable"]]);
  assert.deepEqual(tokens.filter(([, style]) => style === "comment"), []);
  assert.deepEqual(tokens.filter(([, style]) => style === "function"), [["fake", "function"]]);
});

test("URLs and IPv4/IPv6 including leading compression are not split into Lua keys", () => {
  const values = ["https://example.test:443/file?a=b#fragment", "192.0.2.1/24", "2001:db8::1/64", "[fe80::1%br0]", "::1", "::/0"];
  for (const value of values) {
    assert.ok(significant(`--value=${value}`).some(([text, style]) => text === value && style === "string"), value);
  }
});

test("unknown flags and incomplete edits still advance without false numeric prefixes", () => {
  const source = "--future-feature=123abc --marker=midsld+2 --unicode=пример.рф --host='unfinished\n# still quoted \" ${OPEN";
  const tokens = significant(source);
  assert.ok(tokens.some(([word, style]) => word === "--future-feature" && style === "option"));
  assert.ok(tokens.some(([word, style]) => word === "123abc" && style === "string"));
  assert.equal(tokens.some(([word, style]) => word === "123" && style === "number"), false);
  assert.equal(tokens.some(([, style]) => style === "comment"), false);
  for (const suffix of ["$", "${", "\\", "'", '"', "@", "[", "]", "😀", "::", "#"]) tokenize(source + suffix);
});

test("stream states copied for incremental parsing do not leak edits to following lines", () => {
  const state = strategyParser.startState!(2);
  const stream = new StringStream('--host="unfinished', 2, 2);
  while (!stream.eol()) { stream.start = stream.pos; strategyParser.token(stream, state); }
  const fork = strategyParser.copyState!(state);
  const close = new StringStream('"', 2, 2);
  strategyParser.token(close, fork);
  assert.notDeepEqual(fork, state);
  const comment = new StringStream("# literal", 2, 2);
  assert.notEqual(strategyParser.token(comment, state), "comment");
});

test("CodeMirror exposes semantic tags and reparses after an incremental edit", () => {
  const source = "--filter-tcp=443 --lua-desync=fake:repeats=2";
  const highlighter = tagHighlighter([
    { tag: tags.keyword, class: "option" }, { tag: tags.number, class: "number" },
    { tag: tags.function(tags.variableName), class: "function" }, { tag: tags.propertyName, class: "parameter" },
  ]);
  function styled(state: EditorState) {
    const tree = ensureSyntaxTree(state, state.doc.length, 1000);
    assert.ok(tree);
    const spans: [string, string][] = [];
    highlightTree(tree, highlighter, (from, to, style) => spans.push([state.sliceDoc(from, to), style]));
    return spans;
  }
  const state = EditorState.create({ doc: source, extensions: [strategyLanguage] });
  assert.deepEqual(styled(state), [["--filter-tcp", "option"], ["443", "number"], ["--lua-desync", "option"], ["fake", "function"], ["repeats", "parameter"], ["2", "number"]]);
  const edited = state.update({ changes: { from: source.indexOf("fake"), to: source.indexOf("fake") + 4, insert: "multisplit" } }).state;
  assert.ok(styled(edited).some(([word, style]) => word === "multisplit" && style === "function"));
});

import assert from "node:assert/strict";
import test from "node:test";
import { EditorState } from "@codemirror/state";
import { StringStream, ensureSyntaxTree } from "@codemirror/language";
import { highlightTree, tagHighlighter, tags } from "@lezer/highlight";
import { configLanguage, configParser } from "./configLanguage";

const tcpPorts = "443,80,1984,5222";
const udpPorts = "443,590:600,1400,3478:3481,5349,19294:19344,4192,4193:5348,5350:19293";
const tcpNumbers = ["443", "80", "1984", "5222"];
const udpNumbers = ["443", "590", "600", "1400", "3478", "3481", "5349", "19294", "19344", "4192", "4193", "5348", "5350", "19293"];

function tokenize(source: string) {
  const state = configParser.startState!(2);
  const result: [string, string | null][] = [];
  for (const line of source.split(/\r?\n/)) {
    const stream = new StringStream(line, 2, 2);
    while (!stream.eol()) {
      stream.start = stream.pos;
      const style = configParser.token(stream, state);
      assert.ok(stream.pos > stream.start, `Tokenizer must advance: ${line}`);
      result.push([stream.current(), style]);
    }
  }
  return result;
}

test("quoted and multiline config strategies expose individual NFQWS tokens", () => {
  const source = 'export NFQWS_ARGS="--filter-tcp=443\n  --lua-desync=fake:repeats=2:blob=tls_clienthello" # after\nNFQWS_EXTRA_ARGS="$MODE_AUTO --debug=1"';
  const tokens = tokenize(source);
  assert.deepEqual(tokens.filter(([, style]) => style === "option").map(([text]) => text), ["--filter-tcp", "--lua-desync", "--debug"]);
  assert.ok(tokens.some(([text, style]) => text === "fake" && style === "function"));
  assert.ok(tokens.some(([text, style]) => text === "repeats" && style === "parameter"));
  assert.ok(tokens.some(([text, style]) => text === "$MODE_AUTO" && style === "variable"));
  assert.ok(tokens.some(([text, style]) => text === "# after" && style === "comment"));
});

test("ordinary strings, commented assignments and heredocs keep shell highlighting", () => {
  const source = '# NFQWS_ARGS="--commented"\nPOLICY_NAME="NFQWS_ARGS=--name"\necho "first\nNFQWS_ARGS=--inside-string"\ncat <<EOF\nNFQWS_ARGS="--inside-heredoc"\nEOF\nNFQWS_ARGS_UDP="--filter-udp=443"';
  const tokens = tokenize(source);
  assert.deepEqual(tokens.filter(([, style]) => style === "option"), [["--filter-udp", "option"]]);
});

test("literal hashes and escaped quotes cannot swallow the following assignment", () => {
  const source = String.raw`NFQWS_ARGS="--host=\"example#host\" # literal" # comment` + '\nNFQWS_ARGS_QUIC="--filter-udp=443"';
  const tokens = tokenize(source);
  assert.deepEqual(tokens.filter(([, style]) => style === "option").map(([text]) => text), ["--host", "--filter-udp"]);
  assert.deepEqual(tokens.filter(([, style]) => style === "comment"), [["# comment", "comment"]]);
});

test("single quoted values do not expand variables and unquoted assignments end at shell separators", () => {
  const source = "NFQWS_ARGS='$LITERAL --filter-tcp=80'\nNFQWS_EXTRA_ARGS=$MODE_LIST; echo ok\nNFQWS_ARGS=\nPOLICY_NAME=plain\nNFQWS_BASE_ARGS=--debug=1 # comment";
  const tokens = tokenize(source);
  assert.deepEqual(tokens.filter(([, style]) => style === "variable"), [["$MODE_LIST", "variable"]]);
  assert.deepEqual(tokens.filter(([, style]) => style === "option").map(([text]) => text), ["--filter-tcp", "--debug"]);
  assert.ok(tokens.some(([text, style]) => text === "echo" && style === "builtin"));
});

test("independent incremental states retain multiline strings and strategy arguments", () => {
  const state = configParser.startState!(2);
  const stream = new StringStream('NFQWS_ARGS="--filter-tcp=443', 2, 2);
  while (!stream.eol()) { stream.start = stream.pos; configParser.token(stream, state); }
  const fork = configParser.copyState!(state);
  const close = new StringStream('"', 2, 2);
  configParser.token(close, fork);
  assert.notDeepEqual(state, fork);
  assert.notEqual(state.shell.tokens, fork.shell.tokens);
  assert.notEqual(state.args, fork.args);
});

test("CodeMirror reparses a changed function inside a quoted config strategy", () => {
  const source = 'NFQWS_ARGS="--lua-desync=fake:repeats=2"\nPOLICY_NAME="keep"';
  const highlighter = tagHighlighter([{ tag: tags.keyword, class: "option" }, { tag: tags.function(tags.variableName), class: "function" }]);
  function styled(state: EditorState) {
    const tree = ensureSyntaxTree(state, state.doc.length, 1000);
    assert.ok(tree);
    const result: [string, string][] = [];
    highlightTree(tree, highlighter, (from, to, style) => result.push([state.sliceDoc(from, to), style]));
    return result;
  }
  const state = EditorState.create({ doc: source, extensions: [configLanguage] });
  assert.deepEqual(styled(state), [["--lua-desync", "option"], ["fake", "function"]]);
  const changed = state.update({ changes: { from: source.indexOf("fake"), to: source.indexOf("fake") + 4, insert: "multisplit" } }).state;
  assert.deepEqual(styled(changed), [["--lua-desync", "option"], ["multisplit", "function"]]);
});

test("the reported TCP and UDP port lists highlight every number and range boundary separately", () => {
  for (const [key, value, numbers] of [["TCP_PORTS", tcpPorts, tcpNumbers], ["UDP_PORTS", udpPorts, udpNumbers]] as const) {
    const tokens = tokenize(`${key}=${value}`);
    assert.deepEqual(tokens.filter(([, style]) => style === "number").map(([text]) => text), numbers, key);
    assert.deepEqual(tokens.filter(([text]) => text === "," || text === ":").map(([text]) => text), value.match(/[,:]/g), key);
    assert.equal(tokens.some(([text, style]) => style === "number" && /[,:]/.test(text)), false, key);
  }
});

test("quoted exported port lists retain numbers across whitespace and CRLF without coloring trailing comments", () => {
  const source = `  export\tTCP_PORTS="${tcpPorts.replaceAll(",", ", ")}"  # TCP 9999\r\n\tUDP_PORTS='${udpPorts}'\t# UDP 65535\r\n`;
  const tokens = tokenize(source);
  assert.deepEqual(tokens.filter(([, style]) => style === "number").map(([text]) => text), [...tcpNumbers, ...udpNumbers]);
  assert.deepEqual(tokens.filter(([, style]) => style === "comment").map(([text]) => text), ["# TCP 9999", "# UDP 65535"]);
  assert.ok(tokens.some(([text, style]) => text === "export" && style === "keyword"));
});

test("empty and completed port assignments cannot leak state into the next setting or strategy", () => {
  const source = `TCP_PORTS=\nUDP_PORTS="${udpPorts}"\nPOLICY_NAME="443,80:90"\n# TCP_PORTS=9999\nNFQWS_ARGS="--filter-tcp=8443 --lua-desync=fake:repeats=2"\nTCP_PORTS='${tcpPorts}'\nISP_INTERFACE="eth0,eth1"`;
  const tokens = tokenize(source);
  assert.deepEqual(tokens.filter(([, style]) => style === "number").map(([text]) => text), [...udpNumbers, "8443", "2", ...tcpNumbers]);
  assert.ok(tokens.some(([text, style]) => text === "fake" && style === "function"));
  assert.ok(tokens.some(([text, style]) => text === '"443,80:90"' && style === "string"));
  assert.deepEqual(tokens.filter(([, style]) => style === "comment"), [["# TCP_PORTS=9999", "comment"]]);
});

test("port-looking assignments in comments, ordinary strings, or heredocs stay literal shell text", () => {
  const source = `# TCP_PORTS=${tcpPorts}\nPOLICY_NAME="UDP_PORTS=${udpPorts}"\necho "text\nTCP_PORTS=${tcpPorts}"\ncat <<EOF\nUDP_PORTS=${udpPorts}\nEOF\nTCP_PORTS=${tcpPorts}`;
  const tokens = tokenize(source);
  assert.deepEqual(tokens.filter(([, style]) => style === "number").map(([text]) => text), tcpNumbers);
});

test("CodeMirror incrementally reparses an edited port range without changing later settings", () => {
  const source = `TCP_PORTS=${tcpPorts}\nUDP_PORTS="${udpPorts}"\nPOLICY_NAME="keep 80:90"\nNFQWS_ARGS="--filter-tcp=8443"`;
  const highlighter = tagHighlighter([{ tag: tags.number, class: "number" }, { tag: tags.keyword, class: "option" }]);
  function styled(state: EditorState) {
    const tree = ensureSyntaxTree(state, state.doc.length, 1000);
    assert.ok(tree);
    const spans: [string, string][] = [];
    highlightTree(tree, highlighter, (from, to, style) => spans.push([state.sliceDoc(from, to), style]));
    return spans;
  }
  const state = EditorState.create({ doc: source, extensions: [configLanguage] });
  assert.deepEqual(styled(state).filter(([, style]) => style === "number").map(([text]) => text), [...tcpNumbers, ...udpNumbers, "8443"]);
  const from = source.indexOf("590:600");
  const edited = state.update({ changes: { from, to: from + "590:600".length, insert: "591:601,602" } }).state;
  const result = styled(edited);
  assert.deepEqual(result.filter(([, style]) => style === "number").map(([text]) => text), [...tcpNumbers, "443", "591", "601", "602", ...udpNumbers.slice(3), "8443"]);
  assert.deepEqual(result.filter(([, style]) => style === "option"), [["--filter-tcp", "option"]]);
  assert.equal(edited.sliceDoc(edited.doc.line(3).from), 'POLICY_NAME="keep 80:90"\nNFQWS_ARGS="--filter-tcp=8443"');
});

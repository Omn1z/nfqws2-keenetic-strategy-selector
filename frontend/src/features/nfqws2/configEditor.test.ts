import assert from "node:assert/strict";
import test from "node:test";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { applyPathFix, configMode, parseConfigAssignments, patchConfigMode, patchConfigValue, validPathDiagnostics } from "./configEditor";

test("multiline strategies preserve comments, indentation, other assignments and quoted shell metacharacters", () => {
  const source = '# header\r\n  NFQWS_ARGS="--filter-tcp=443\r\n    # inline strategy note\r\n    --out-range=<n2 --host=example.com"  # keep comment\r\nUNKNOWN="$NFQWS_ARGS --extra"\r\n';
  const parsed = parseConfigAssignments(source);
  assert.equal(parsed.canAppend, true);
  const item = parsed.assignments.get("NFQWS_ARGS")!;
  assert.equal(item.value, "--filter-tcp=443\r\n    # inline strategy note\r\n    --out-range=<n2 --host=example.com");
  assert.equal(patchConfigValue(source, item.key, item.value), source);
  const edited = patchConfigValue(source, item.key, item.value.replace("443", "443,80"));
  assert.equal(edited, source.replace("443", "443,80"));
  assert.equal(parseConfigAssignments(edited).assignments.get("UNKNOWN")?.value, "$NFQWS_ARGS --extra");
});

test("quotes escaped inside double quoted assignments do not end the span", () => {
  const source = String.raw`NFQWS_ARGS="--foo=\"quoted\" --path=C:\\test --literal=\$VAR --ref=$VAR" # tail` + "\nOTHER=keep\n";
  const item = parseConfigAssignments(source).assignments.get("NFQWS_ARGS")!;
  assert.equal(item.editable, true);
  const edited = patchConfigValue(source, item.key, item.value + ' --new="hello"');
  assert.ok(edited.includes(String.raw`--foo=\"quoted\" --path=C:\\test --literal=\$VAR --ref=$VAR`));
  assert.ok(edited.endsWith(' --new=\\"hello\\"" # tail\nOTHER=keep\n'));
  assert.equal(parseConfigAssignments(edited).canAppend, true);
});

test("only the last effective assignment changes, commented keys remain comments", () => {
  const source = '# NFQUEUE_NUM=100\nNFQUEUE_NUM=200\nexport NFQUEUE_NUM=300 # active\n';
  assert.equal(patchConfigValue(source, "NFQUEUE_NUM", "301"), '# NFQUEUE_NUM=100\nNFQUEUE_NUM=200\nexport NFQUEUE_NUM=301 # active\n');
});

test("missing keys append safely preserving CRLF and files without a trailing newline", () => {
  assert.equal(patchConfigValue("OTHER=keep\r\n", "NFQWS_ARGS_CUSTOM", "--foo"), 'OTHER=keep\r\nNFQWS_ARGS_CUSTOM="--foo"\r\n');
  assert.equal(patchConfigValue("OTHER=keep", "NFQWS_ARGS_CUSTOM", ""), 'OTHER=keep\nNFQWS_ARGS_CUSTOM=""\n');
  assert.throws(() => patchConfigValue("", "A; rm", "x"));
});

test("mode changes keep additional flags and variable references", () => {
  const source = 'NFQWS_EXTRA_ARGS="--debug=1 ${MODE_AUTO} --foo=$OTHER"  # keep\n';
  assert.equal(configMode(parseConfigAssignments(source).assignments.get("NFQWS_EXTRA_ARGS")), "auto");
  const changed = patchConfigMode(source, "list");
  assert.equal(changed, 'NFQWS_EXTRA_ARGS="--debug=1 $MODE_LIST --foo=$OTHER"  # keep\n');
  assert.equal(configMode(parseConfigAssignments(changed).assignments.get("NFQWS_EXTRA_ARGS")), "list");
  assert.equal(configMode(parseConfigAssignments('NFQWS_EXTRA_ARGS=${MODE_ALL}\n').assignments.get("NFQWS_EXTRA_ARGS")), "all");
});

test("single-quoted literal flags remain literal when a mode introduces expansion", () => {
  const source = "NFQWS_EXTRA_ARGS='--custom=$SECRET --old=$MODE_ALL --quoted=\"hello\"' # comment\n";
  const result = patchConfigMode(source, "auto");
  assert.equal(result, 'NFQWS_EXTRA_ARGS="$MODE_AUTO --custom=\\$SECRET --old=\\$MODE_ALL --quoted=\\"hello\\"" # comment\n');
  assert.equal(configMode(parseConfigAssignments(result).assignments.get("NFQWS_EXTRA_ARGS")), "auto");
});

test("mode selection refuses ambiguity and does not interpret escaped tokens", () => {
  assert.equal(configMode(parseConfigAssignments('NFQWS_EXTRA_ARGS="\\$MODE_ALL --custom"').assignments.get("NFQWS_EXTRA_ARGS")), "custom");
  assert.throws(() => patchConfigMode('NFQWS_EXTRA_ARGS="$MODE_AUTO $MODE_ALL"', "list"));
});

test("single quote edit and trailing backslash cannot break the outer shell assignment", () => {
  const result = patchConfigValue("POLICY_NAME='nfqws' # comment\n", "POLICY_NAME", "O'Brien $LITERAL");
  assert.equal(result, 'POLICY_NAME="O\'Brien \\$LITERAL" # comment\n');
  assert.equal(parseConfigAssignments(result).canAppend, true);
  const slash = patchConfigValue('POLICY_NAME="old"\n', "POLICY_NAME", "ends\\");
  assert.equal(parseConfigAssignments(slash).canAppend, true);
  assert.equal(slash, 'POLICY_NAME="ends\\\\"\n');
});

test("shell blocks, concatenated words, commands, and incomplete quotes stay raw-only", () => {
  for (const source of [
    'if true; then\nNFQWS_ARGS="a"\nfi\n',
    'f() {\nNFQWS_ARGS="a"\n}\n',
    'NFQWS_ARGS="a"; do_something\n',
    'NFQWS_ARGS="a"\'b\'\n',
    'NFQWS_ARGS="unfinished\nOTHER=keep',
    'NFQWS_ARGS=--out-range=<n2\n',
    'cat <<EOF\nNFQWS_ARGS="a"\nEOF\n',
  ]) {
    assert.equal(parseConfigAssignments(source).canAppend, false, source);
    assert.throws(() => patchConfigValue(source, "NFQWS_ARGS", "--replace"), source);
  }
});

test("generated quoting preserves actual POSIX shell values and literal expansion characters", (t) => {
  const shell = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "/bin/sh";
  if (!existsSync(shell)) { t.skip("POSIX shell unavailable"); return; }
  // Only fixed synthetic fixtures execute here, never the user's config.
  const initial = "NFQWS_EXTRA_ARGS='--literal=$SECRET --old=$MODE_ALL --quoted=\"hello\"'\nPOLICY_NAME='old'\n";
  const changed = patchConfigValue(patchConfigMode(initial, "auto"), "POLICY_NAME", "O'Brien $SECRET `printf nope` \\");
  const input = "MODE_AUTO='--auto'\nMODE_ALL='--all'\nSECRET='must-not-expand'\n" + changed + 'printf "%s\\n%s" "$NFQWS_EXTRA_ARGS" "$POLICY_NAME"\n';
  const result = execFileSync(shell, ["-s"], { input, encoding: "utf8" });
  assert.equal(result, '--auto --literal=$SECRET --old=$MODE_ALL --quoted="hello"\nO\'Brien $SECRET `printf nope` \\');
});

test("path fixes honor UTF-16 offsets and reject stale or invalid spans", () => {
  const source = '😀 /opt/etc/nfqws2/lua/test.lua and other';
  const path = '/opt/etc/nfqws2/lua/test.lua';
  const d = { from: 3, to: 3 + path.length, path, message: "use native root", replacement: "/etc/nfqws2/lua/test.lua" };
  assert.equal(applyPathFix(source, d), '😀 /etc/nfqws2/lua/test.lua and other');
  assert.equal(applyPathFix(source + " changed", { ...d, from: 4 }), source + " changed");
  assert.equal(validPathDiagnostics(source, [d, { ...d, from: -1 }, { ...d, to: Infinity }, { ...d, path: "/wrong" }]).length, 1);
});

const managedServices = '# BEGIN N2S SERVICE STRATEGIES\n' +
  'NFQWS_ARGS_CUSTOM="--filter-tcp=8443 --hostlist-domains=facepunch.com --lua-desync=multisplit${NFQWS_ARGS_CUSTOM:+ --new }${NFQWS_ARGS_CUSTOM}"\n' +
  "TCP_PORTS='80,443,8443'\n" +
  '# END N2S SERVICE STRATEGIES\n';

test("structured edits use base assignments and preserve service overrides verbatim", () => {
  const base = 'NFQWS_ARGS_CUSTOM="--filter-tcp=443 --lua-desync=fake"\nTCP_PORTS=80,443\n';
  const source = base + managedServices;
  const parsed = parseConfigAssignments(source);
  assert.equal(parsed.canAppend, true);
  assert.equal(parsed.assignments.get("TCP_PORTS")?.value, "80,443");
  assert.equal(parsed.assignments.get("NFQWS_ARGS_CUSTOM")?.value, "--filter-tcp=443 --lua-desync=fake");
  assert.equal(patchConfigValue(source, "TCP_PORTS", "443"), base.replace("TCP_PORTS=80,443", "TCP_PORTS=443") + managedServices);
  assert.equal(patchConfigValue(source, "UDP_PORTS", "443"), base + 'UDP_PORTS="443"\n' + managedServices);
  assert.equal(patchConfigValue(managedServices, "NFQWS_ARGS_CUSTOM", "--filter-tcp=80"), 'NFQWS_ARGS_CUSTOM="--filter-tcp=80"\n' + managedServices);
  const crlf = source.replaceAll("\n", "\r\n");
  assert.equal(patchConfigValue(crlf, "UDP_PORTS", "443"), base.replaceAll("\n", "\r\n") + 'UDP_PORTS="443"\r\n' + managedServices.replaceAll("\n", "\r\n"));
  assert.equal(parseConfigAssignments(source.trimEnd()).canAppend, true);
});

test("service marker text inside multiline quotes is ordinary strategy content", () => {
  for (const quote of ["'", '"']) {
    const source = `NFQWS_ARGS=${quote}--filter-tcp=443\n# BEGIN N2S SERVICE STRATEGIES\n# END N2S SERVICE STRATEGIES\n${quote}\nTCP_PORTS=443\n`;
    const parsed = parseConfigAssignments(source);
    assert.equal(parsed.canAppend, true);
    assert.ok(parsed.assignments.get("NFQWS_ARGS")?.value.includes("# BEGIN N2S"));
    assert.equal(patchConfigValue(source, "TCP_PORTS", "80"), source.replace("TCP_PORTS=443", "TCP_PORTS=80"));
  }
});

test("managed service literals accept only safely generated double quote escapes", () => {
  const literal = '--filter-tcp=8443 --lua-desync=fake:arg=C:\\data:quote="literal":dollar=$:tick=`';
  const encoded = literal.replace(/[\\"$`]/g, '\\$&');
  const block = managedServices.replace('--filter-tcp=8443', encoded);
  const source = 'TCP_PORTS=443\n' + block;
  assert.equal(parseConfigAssignments(source).canAppend, true);
  assert.equal(parseConfigAssignments(source).assignments.get('TCP_PORTS')?.value, '443');
  assert.equal(patchConfigValue(source, 'TCP_PORTS', '80'), 'TCP_PORTS=80\n' + block);
  for (const invalid of ['$VALUE', '$(printf unsafe)', '`printf unsafe`', '"unescaped"', '\\q', '\\', '\\\\$VALUE', '\\\\`printf unsafe`']) {
    const source = 'TCP_PORTS=443\n' + managedServices.replace('--filter-tcp=8443', invalid);
    assert.equal(parseConfigAssignments(source).canAppend, false, invalid);
    assert.throws(() => patchConfigValue(source, 'TCP_PORTS', '80'), invalid);
  }
});

test("malformed, duplicate or modified service blocks keep structured editing disabled", () => {
  for (const block of [
    managedServices + managedServices,
    managedServices.replace('# END N2S SERVICE STRATEGIES\n', ''),
    '# END N2S SERVICE STRATEGIES\n',
    managedServices.replace('# BEGIN', ' # BEGIN'),
    managedServices.replace("TCP_PORTS='80,443,8443'", 'ISP_INTERFACE=eth8'),
    managedServices.replace("TCP_PORTS='80,443,8443'", "TCP_PORTS=80\nTCP_PORTS=443"),
    managedServices.replace("TCP_PORTS='80,443,8443'", 'printf unsafe'),
    managedServices.replace('--filter-tcp=8443', '$(printf unsafe)'),
    managedServices + 'TCP_PORTS=999\n',
  ]) {
    const source = 'TCP_PORTS=443\n' + block;
    assert.equal(parseConfigAssignments(source).canAppend, false, block);
    assert.throws(() => patchConfigValue(source, 'TCP_PORTS', '80'), block);
  }
});

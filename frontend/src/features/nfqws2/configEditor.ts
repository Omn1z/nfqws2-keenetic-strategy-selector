/** Lossless shell assignment editing. Values are shell source inside the outer
 * quotes: variable references and escapes are never evaluated in the browser. */
export interface ConfigAssignment {
  key: string;
  value: string;
  from: number;
  to: number;
  quote: "'" | '"' | "";
  editable: boolean;
  reason?: string;
}
export interface ParsedConfig {
  assignments: Map<string, ConfigAssignment>;
  canAppend: boolean;
  warning?: string;
}

function statementEnd(source: string, from: number): number {
  let quote = "";
  for (let i = from; i < source.length; i++) {
    const ch = source[i];
    if (ch === "\\" && quote !== "'") { i++; continue; }
    if (quote) { if (ch === quote) quote = ""; continue; }
    if (ch === "'" || ch === '"' || ch === "`") { quote = ch; continue; }
    if (ch === "#" && (i === from || /[ \t]/.test(source[i - 1]))) {
      const end = source.indexOf("\n", i);
      return end < 0 ? source.length : end;
    }
    if (ch === "\n") return i;
  }
  return source.length;
}

function assignmentValue(source: string, from: number, end: number): Omit<ConfigAssignment, "key"> {
  const first = source[from];
  const quote = first === "'" || first === '"' ? first : "";
  let to = from;
  let complete = true;
  if (quote) {
    to++;
    while (to < end) {
      if (source[to] === "\\" && quote === '"') { to += 2; continue; }
      if (source[to] === quote) break;
      to++;
    }
    complete = source[to] === quote && to < end;
    if (complete) to++;
    else to = end;
  } else {
    while (to < end && !/[ \t\r\n]/.test(source[to])) {
      if (source[to] === "\\") to++;
      to++;
    }
    to = Math.min(to, end);
  }
  const tail = source.slice(to, end).trim();
  const raw = source.slice(from, to);
  const simple = quote !== "" || !/[;|&<>()`'"{}]/.test(raw.replace(/\$\{[A-Za-z_][A-Za-z0-9_]*\}/g, ""));
  const editable = complete && simple && (!tail || tail.startsWith("#"));
  return { from, to, quote, value: quote && complete ? raw.slice(1, -1) : raw, editable,
    reason: editable ? undefined : "Составное или незавершённое shell-выражение: измените его в полном файле." };
}

export function parseConfigAssignments(source: string): ParsedConfig {
  const assignments = new Map<string, ConfigAssignment>();
  let plain = true;
  for (let start = 0; start < source.length;) {
    const end = statementEnd(source, start);
    const statement = source.slice(start, end);
    const trimmed = statement.trim();
    if (trimmed && !trimmed.startsWith("#")) {
      const match = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=/.exec(statement);
      if (match) {
        const item = assignmentValue(source, start + match[0].length, end);
        assignments.set(match[1], { key: match[1], ...item });
        // An assignment followed by a command/conditional can alter the same
        // variable later. Keep every structured field read-only in that case.
        if (!item.editable) plain = false;
      } else plain = false;
    }
    start = end + 1;
  }
  if (!plain) {
    for (const item of assignments.values()) {
      item.editable = false;
      item.reason = "Файл содержит shell-команды или сложные выражения. Для сохранения их порядка используйте полный файл.";
    }
  }
  return { assignments, canAppend: plain, warning: plain ? undefined : "Структурированное редактирование отключено: файл содержит shell-команды, составные или незавершённые выражения. Полный редактор доступен." };
}

function doubleQuoted(value: string): string {
  let result = '"';
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch === "\\") {
      if (i + 1 < value.length) { result += ch + value[++i]; continue; }
      result += "\\\\"; // do not escape the enclosing quote
    } else result += ch === '"' ? '\\"' : ch;
  }
  return result + '"';
}

export function patchConfigValue(source: string, key: string, value: string, forceExpansion = false): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new Error("Некорректное имя параметра.");
  const parsed = parseConfigAssignments(source);
  const item = parsed.assignments.get(key);
  if (!parsed.canAppend || item && !item.editable) throw new Error(item?.reason ?? parsed.warning);
  if (item?.value === value && !forceExpansion) return source;
  let encoded: string;
  if (item?.quote === "'" && !forceExpansion) {
    // A single-quoted value is literal. If a new apostrophe forces double
    // quoting, escape every expansion character to retain that meaning.
    encoded = value.includes("'") ? '"' + value.replace(/[\\"$`]/g, "\\$&") + '"' : "'" + value + "'";
  } else if (item?.quote === "" && /^[A-Za-z0-9_.,:/@%+!=\-]+$/.test(value)) encoded = value;
  else encoded = doubleQuoted(value);
  if (item) return source.slice(0, item.from) + encoded + source.slice(item.to);
  const newline = source.includes("\r\n") ? "\r\n" : "\n";
  return source + (source && !source.endsWith("\n") ? newline : "") + key + "=" + encoded + newline;
}

export type ConfigMode = "list" | "auto" | "all" | "custom";
const modePattern = /\$(?:MODE_(LIST|AUTO|ALL)\b|\{MODE_(LIST|AUTO|ALL)\})/g;
function modeReferences(value: string): { from: number; to: number; mode: ConfigMode }[] {
  const result: { from: number; to: number; mode: ConfigMode }[] = [];
  for (const match of value.matchAll(modePattern)) {
    let escapes = 0;
    for (let i = match.index - 1; i >= 0 && value[i] === "\\"; i--) escapes++;
    if (escapes % 2 === 0) result.push({ from: match.index, to: match.index + match[0].length, mode: (match[1] || match[2]).toLowerCase() as ConfigMode });
  }
  return result;
}
export function configMode(item?: ConfigAssignment): ConfigMode {
  if (!item || item.quote === "'") return "custom";
  const references = modeReferences(item.value);
  return references.length === 1 ? references[0].mode : "custom";
}
export function patchConfigMode(source: string, mode: Exclude<ConfigMode, "custom">): string {
  const item = parseConfigAssignments(source).assignments.get("NFQWS_EXTRA_ARGS");
  const value = item?.quote === "'" ? item.value.replace(/[\\"$`]/g, "\\$&") : item?.value ?? "";
  const refs = item?.quote === "'" ? [] : modeReferences(value);
  if (refs.length > 1) throw new Error("В дополнительных аргументах несколько MODE_*. Выберите режим в полном файле.");
  const token = "$MODE_" + mode.toUpperCase();
  // Keep every unrelated flag and the surrounding spacing, never replace the
  // entire NFQWS_EXTRA_ARGS value with the selected token.
  const next = refs.length ? value.slice(0, refs[0].from) + token + value.slice(refs[0].to) : token + (value ? " " + value : "");
  return patchConfigValue(source, "NFQWS_EXTRA_ARGS", next, true);
}

export interface PathDiagnostic { from: number; to: number; path: string; message: string; replacement?: string }
export interface PathAnalysis { diagnostics: PathDiagnostic[]; content: string; platform: string }
export function validPathDiagnostics(source: string, diagnostics: PathDiagnostic[]): PathDiagnostic[] {
  return diagnostics.filter((d) => Number.isInteger(d.from) && Number.isInteger(d.to) && d.from >= 0 && d.to > d.from && d.to <= source.length && source.slice(d.from, d.to) === d.path);
}
export function applyPathFix(source: string, d: PathDiagnostic): string {
  if (d.replacement === undefined || validPathDiagnostics(source, [d]).length !== 1) return source;
  return source.slice(0, d.from) + d.replacement + source.slice(d.to);
}

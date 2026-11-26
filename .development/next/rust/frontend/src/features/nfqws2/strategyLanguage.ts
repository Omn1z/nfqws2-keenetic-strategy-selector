import { StreamLanguage, type StreamParser, type StringStream } from "@codemirror/language";
import { tags } from "@lezer/highlight";

type Quote = "'" | '"' | null;
interface StrategyState {
  quote: Quote;
  option: string;
  firstValue: boolean;
  parameter: boolean;
  boundary: boolean;
}

const freshState = (): StrategyState => ({ quote: null, option: "", firstValue: false, parameter: false, boundary: true });

/** NFQWS arguments are not shell programs: a hyphenated option is one token,
 * and --lua-desync contains a function followed by colon-delimited parameters.
 * StreamLanguage only reparses changed lines; no decorations scan the document.
 * This is highlighting, not a whitelist/validator, so new engine flags work too. */
export const strategyParser: StreamParser<StrategyState> = {
  name: "nfqws-strategy",
  startState: freshState,
  copyState: (state) => ({ ...state }),
  token(stream: StringStream, state: StrategyState): string | null {
    if (stream.sol() && !state.quote) Object.assign(state, freshState());
    if (stream.eatSpace()) {
      state.boundary = true;
      if (!state.quote && !state.firstValue) { state.option = ""; state.parameter = false; }
      return null;
    }

    const ch = stream.peek();
    if (ch === "#" && !state.quote && state.boundary) { stream.skipToEnd(); return "comment"; }
    if (ch === "\\" && state.quote !== "'") {
      stream.next(); stream.next(); state.boundary = false; return "escape";
    }
    if ((ch === "'" || ch === '"') && (!state.quote || state.quote === ch)) {
      stream.next(); state.quote = state.quote ? null : ch; state.boundary = false; return "string";
    }
    if (ch === "$" && state.quote !== "'" && stream.match(/^\$(?:\{[^}\r\n]*\}?|[A-Za-z_][\w]*|[0-9@*#?$!_-])/)) {
      state.boundary = false; state.firstValue = false; return "variable";
    }
    if (!state.quote && state.boundary && stream.match(/^--?[A-Za-z][\w-]*/)) {
      state.option = stream.current(); state.firstValue = true; state.parameter = false; state.boundary = false;
      return "option";
    }

    state.boundary = false;
    if (ch === "=") { stream.next(); state.parameter = false; return "operator"; }
    if (ch === "," || ch === ";") { stream.next(); return "punctuation"; }

    // Keep URI fragments/query strings and IP addresses intact. Their ':' and
    // '#' characters are data, not Lua separators or shell comments.
    if (stream.match(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s'"\\$]+/) ||
        stream.match(/^(?:\[[\da-f:.]+(?:%[\w.-]+)?\]|(?=[\da-f:]*:[\da-f:]*:)[\da-f:]+)(?:\/\d+)?(?![\w.])/i) ||
        stream.match(/^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d+)?(?![\w.])/)) {
      state.firstValue = false; return "string";
    }
    if (ch === ":") { stream.next(); state.parameter = state.option === "--lua-desync"; return "punctuation"; }
    if (stream.match(/^@?(?:\/|\.\.?\/|~\/)/)) {
      // Outside Lua arguments a colon is a valid part of a filename.
      stream.eatWhile(state.option === "--lua-desync" ? /[^\s'"\\$:,]/ : /[^\s'"\\$]/);
      state.firstValue = false; return "string";
    }
    if (stream.match(/^[+-]?(?:0x[\da-f]+|\d+(?:\.\d+)?)(?![\w.])/i)) {
      state.firstValue = false; return "number";
    }
    if (stream.match(/^[A-Za-z_][\w.-]*/)) {
      const word = stream.current();
      const isFunction = state.firstValue && state.option === "--lua-desync";
      state.firstValue = false;
      if (stream.peek() === "=" || state.parameter) { state.parameter = false; return "parameter"; }
      if (isFunction) return "function";
      if (/^(true|false|yes|no)$/i.test(word)) return "bool";
      return "string";
    }
    if (/[()[\]{}]/.test(ch ?? "")) { stream.next(); return "bracket"; }
    if (/[<>+!|&]/.test(ch ?? "")) { stream.next(); return "operator"; }

    // Includes Unicode names, glob patterns, literal '$' in single quotes and
    // hashes within a word. Always advance, including unfinished input.
    stream.next();
    stream.eatWhile(/[^\s'"\\$=:,;()[\]{}<>+!|&]/);
    state.firstValue = false;
    return "string";
  },
  tokenTable: {
    option: tags.keyword,
    parameter: tags.propertyName,
    function: tags.function(tags.variableName),
    variable: tags.variableName,
    string: tags.string,
    number: tags.number,
    bool: tags.bool,
    operator: tags.operator,
    punctuation: tags.punctuation,
    bracket: tags.bracket,
    escape: tags.escape,
    comment: tags.comment,
  },
  languageData: {
    closeBrackets: { brackets: ["(", "[", "{", "'", '"'] },
    commentTokens: { line: "#" },
  },
};

export const strategyLanguage = StreamLanguage.define(strategyParser);

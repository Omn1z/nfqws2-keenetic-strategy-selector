import { StreamLanguage, type StreamParser, type StringStream } from "@codemirror/language";
import { shell } from "@codemirror/legacy-modes/mode/shell";
import { strategyParser } from "./strategyLanguage";

// The pinned legacy shell parser stores its nested strings/heredocs in tokens.
// Clone that stack when CodeMirror forks a line state for incremental parsing.
type ShellState = { tokens: unknown[] };
type ArgsState = ReturnType<NonNullable<typeof strategyParser.startState>>;
interface ConfigState {
  shell: ShellState;
  phase: "shell" | "equals" | "value" | "args";
  valueKind: "strategy" | "ports";
  quote: "'" | '"' | "";
  args: ArgsState;
  assignmentPrefix: boolean;
}
const argsState = () => strategyParser.startState!(2);

/** Highlight NFQWS arguments and port lists inside shell assignments with
 * semantic tokens, including quoted values. Everything else stays Shell,
 * including commands, ordinary strings, heredocs, and comments. No evaluation,
 * document-wide scans, or rewriting of the user's shell source is involved. */
export const configParser: StreamParser<ConfigState> = {
  name: "nfqws-config",
  startState: () => ({ shell: shell.startState!(2) as ShellState, phase: "shell", valueKind: "strategy", quote: "", args: argsState(), assignmentPrefix: true }),
  copyState: (state) => ({ ...state, shell: { ...state.shell, tokens: [...state.shell.tokens] }, args: strategyParser.copyState!(state.args) }),
  token(stream: StringStream, state: ConfigState): string | null {
    if (stream.sol()) {
      state.assignmentPrefix = state.shell.tokens.length === 0;
      if (state.phase !== "shell" && !state.quote) state.phase = "shell";
    }

    if (state.phase === "shell") {
      // Stop inspecting prefixes after the first ordinary shell word. A long
      // command must not rescan its growing prefix for every later token.
      if (state.assignmentPrefix) {
        const prefix = stream.string.slice(0, stream.pos);
        state.assignmentPrefix = /^[ \t]*(?:export[ \t]*)?$/.test(prefix);
        if (state.assignmentPrefix && /^(?:[ \t]*|[ \t]*export[ \t]+)$/.test(prefix) &&
            stream.match(/^(?:NFQWS_(?:BASE_ARGS|EXTRA_ARGS|ARGS(?:_[A-Z0-9_]+)?)|MODE_(?:AUTO|LIST|ALL)|(?:TCP|UDP)_PORTS)(?==)/)) {
          state.phase = "equals";
          state.valueKind = /^(?:TCP|UDP)_PORTS$/.test(stream.current()) ? "ports" : "strategy";
          state.args = argsState();
          state.assignmentPrefix = false;
          return "def";
        }
      }
      return shell.token(stream, state.shell);
    }
    if (state.phase === "equals") {
      stream.next(); // the '=' required by the assignment match above
      state.phase = "value";
      return "operator";
    }
    if (state.phase === "value") {
      state.phase = "args";
      if (stream.peek() === '"' || stream.peek() === "'") {
        state.quote = stream.next() as "'" | '"';
        return "string";
      }
    }

    const ch = stream.peek();
    if (state.quote && ch === state.quote) {
      stream.next();
      state.quote = "";
      state.phase = "shell";
      return "string";
    }
    if (!state.quote && (stream.match(/^[\s;|&]/, false) || ch === "#")) {
      state.phase = "shell";
      return shell.token(stream, state.shell);
    }
    // These are literal characters in the surrounding shell assignment, not
    // fresh shell quotes/comments. In particular, '#' must not consume its
    // closing quote and corrupt highlighting for the rest of the file.
    if (state.quote && (ch === "#" || ch === '"' || ch === "'" || state.quote === "'" && (ch === "$" || ch === "\\"))) {
      stream.next();
      state.args.boundary = false;
      return "string";
    }
    // The shell lexer consumes ',80' and ':600' as unstyled words. In these
    // two settings each port and each delimiter has its own token. Handle
    // numbers before the strategy parser's IP detection: colons are ranges,
    // not IPv6. Other values (e.g. $PORTS) retain the shared shell handling.
    if (state.valueKind === "ports") {
      if (stream.match(/^\d+(?![\w.])/)) return "number";
      if (stream.match(/^[,:]/)) return "punctuation";
    }
    return strategyParser.token(stream, state.args);
  },
  tokenTable: strategyParser.tokenTable,
  languageData: shell.languageData,
};

export const configLanguage = StreamLanguage.define(configParser);

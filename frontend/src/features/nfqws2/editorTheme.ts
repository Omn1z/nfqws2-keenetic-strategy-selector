import { HighlightStyle } from "@codemirror/language";
import { EditorView } from "@codemirror/view";
import { tags } from "@lezer/highlight";

// CSS variables follow the application theme without recreating the editor,
// changing its selection, or discarding undo history.
export const editorHighlightStyle = HighlightStyle.define([
  { tag: [tags.comment, tags.meta], color: "var(--syntax-comment, var(--c-muted))" },
  { tag: [tags.keyword, tags.modifier, tags.bool, tags.null, tags.atom], color: "var(--syntax-keyword, var(--c-ink))" },
  { tag: [tags.controlKeyword, tags.moduleKeyword], color: "var(--syntax-control, var(--c-ink))" },
  { tag: [tags.string, tags.special(tags.string), tags.regexp], color: "var(--syntax-string, var(--c-ink))" },
  { tag: tags.number, color: "var(--syntax-number, var(--c-ink))" },
  { tag: [tags.function(tags.variableName), tags.function(tags.propertyName), tags.standard(tags.variableName)], color: "var(--syntax-function, var(--c-ink))" },
  { tag: [tags.variableName, tags.attributeName], color: "var(--syntax-variable, var(--c-ink))" },
  { tag: [tags.propertyName, tags.typeName], color: "var(--syntax-type, var(--c-ink))" },
  { tag: tags.definition(tags.variableName), color: "var(--syntax-variable, var(--c-ink))", fontWeight: "500" },
  { tag: [tags.operator, tags.escape], color: "var(--syntax-operator, var(--c-ink-soft))" },
  { tag: [tags.punctuation, tags.bracket], color: "var(--syntax-punctuation, var(--c-ink-soft))" },
  { tag: tags.invalid, color: "var(--syntax-invalid, var(--c-bad))", textDecoration: "underline wavy" },
]);

export const editorTheme = EditorView.theme({
  "&": {
    backgroundColor: "var(--editor-bg, var(--c-input))",
    color: "var(--c-ink)", fontSize: "13px",
  },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": {
    fontFamily: "var(--font-mono, ui-monospace, SFMono-Regular, Consolas, monospace)",
    lineHeight: "1.75", overflow: "auto", maxHeight: "64vh",
    scrollbarColor: "var(--c-track) transparent", overscrollBehavior: "contain",
  },
  ".cm-content": { padding: "14px 0", caretColor: "var(--c-ink)" },
  ".cm-line": { padding: "0 16px" },
  ".cm-gutters": {
    backgroundColor: "var(--editor-gutter, var(--c-input))",
    color: "var(--c-muted)", borderRight: "1px solid var(--c-line-soft)",
    userSelect: "none",
  },
  ".cm-lineNumbers .cm-gutterElement": { padding: "0 10px 0 12px", minWidth: "36px" },
  ".cm-activeLine": { backgroundColor: "var(--editor-active-line, var(--c-line-soft))" },
  ".cm-activeLineGutter": {
    backgroundColor: "var(--editor-active-line, var(--c-line-soft))", color: "var(--c-ink)",
  },
  ".cm-cursor, .cm-dropCursor": { borderLeft: "2px solid var(--c-ink)" },
  // Match CodeMirror's focused selection-layer selector and add the editor
  // class so its built-in light/dark colors cannot win on specificity.
  "&.cm-editor > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, &.cm-editor.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground": {
    backgroundColor: "var(--editor-selection, var(--c-track))",
  },
  "&.cm-editor .cm-content ::selection": { backgroundColor: "var(--editor-selection, var(--c-track))" },
  ".cm-selectionMatch": { backgroundColor: "var(--editor-selection-match, var(--c-line-soft))" },
  "&.cm-editor .cm-searchMatch": {
    backgroundColor: "var(--editor-search-match, var(--c-warn-bg))",
    outline: "1px solid var(--c-track)", borderRadius: "2px",
  },
  "&.cm-editor .cm-searchMatch.cm-searchMatch-selected": {
    backgroundColor: "var(--editor-selection, var(--c-track))", outline: "1px solid var(--c-ink-soft)",
  },
  "&.cm-focused .cm-matchingBracket": {
    backgroundColor: "var(--editor-selection-match, var(--c-line-soft))",
    outline: "1px solid var(--c-track)", color: "var(--c-ink)", borderRadius: "2px",
  },
  "&.cm-focused .cm-nonmatchingBracket": { backgroundColor: "var(--c-bad-bg)", color: "var(--c-bad)" },
  ".cm-tooltip": {
    backgroundColor: "var(--c-panel)", color: "var(--c-ink)",
    border: "1px solid var(--c-line)", borderRadius: "var(--radius-md, 6px)",
    boxShadow: "0 8px 24px rgb(0 0 0 / 12%)", maxWidth: "min(560px, 90vw)",
    fontFamily: "var(--font-sans, system-ui, sans-serif)", fontSize: "12px", lineHeight: "1.6",
  },
  ".cm-tooltip-lint": { padding: "4px", whiteSpace: "pre-wrap", overflowWrap: "anywhere" },
  ".cm-diagnostic": { padding: "7px 10px", marginLeft: "0", borderLeftWidth: "2px" },
  ".cm-diagnostic-warning": { borderLeftColor: "var(--c-warn)" },
  ".cm-diagnostic-error": { borderLeftColor: "var(--c-bad)" },
  ".cm-diagnostic-info, .cm-diagnostic-hint": { borderLeftColor: "var(--c-muted)" },
  ".cm-diagnosticAction": {
    margin: "6px 0 2px 8px", padding: "4px 8px", background: "var(--c-line-soft)",
    color: "var(--c-ink)", border: "1px solid var(--c-line)", borderRadius: "4px", cursor: "pointer",
  },
  ".cm-diagnosticAction:hover": { background: "var(--editor-selection, var(--c-track))" },
  ".cm-diagnosticAction:focus-visible": { outline: "2px solid var(--c-track)", outlineOffset: "2px" },
  ".cm-lintRange-warning": { backgroundImage: "none", textDecoration: "underline wavy var(--c-warn)", textUnderlineOffset: "4px" },
  ".cm-lintRange-error": { backgroundImage: "none", textDecoration: "underline wavy var(--c-bad)", textUnderlineOffset: "4px" },
  ".cm-lint-marker-warning": { content: "none", backgroundColor: "var(--c-warn)", clipPath: "polygon(50% 6%, 100% 92%, 0 92%)" },
  ".cm-lint-marker-error": { content: "none", backgroundColor: "var(--c-bad)", borderRadius: "50%" },
  ".cm-panels": { backgroundColor: "var(--c-panel)", color: "var(--c-ink)" },
  ".cm-panels.cm-panels-top": { borderBottom: "1px solid var(--c-line)" },
  ".cm-panels.cm-panels-bottom": { borderTop: "1px solid var(--c-line)" },
  ".cm-panel.cm-search": {
    padding: "10px 32px 10px 12px", fontFamily: "var(--font-sans, system-ui, sans-serif)", fontSize: "12px",
  },
  ".cm-panel.cm-search label": { display: "inline-flex", alignItems: "center", gap: "4px" },
  ".cm-panel.cm-search input[type=checkbox]": { accentColor: "var(--c-ink)" },
  "&.cm-editor .cm-textfield": {
    minHeight: "30px", padding: "4px 8px", backgroundColor: "var(--c-input)", color: "var(--c-ink)",
    border: "1px solid var(--c-line)", borderRadius: "4px", font: "inherit",
  },
  "&.cm-editor .cm-textfield:focus": { outline: "2px solid var(--c-track)", outlineOffset: "1px" },
  "&.cm-editor .cm-button": {
    minHeight: "30px", padding: "4px 9px", background: "var(--c-panel)", color: "var(--c-ink)",
    border: "1px solid var(--c-line)", borderRadius: "4px", font: "inherit", cursor: "pointer",
  },
  "&.cm-editor .cm-button:hover, &.cm-editor .cm-button:active": { background: "var(--c-line-soft)" },
  "&.cm-editor .cm-button:focus-visible": { outline: "2px solid var(--c-track)", outlineOffset: "1px" },
  ".cm-panel.cm-search [name=close]": { color: "var(--c-muted)", padding: "6px 8px", fontSize: "18px" },
});

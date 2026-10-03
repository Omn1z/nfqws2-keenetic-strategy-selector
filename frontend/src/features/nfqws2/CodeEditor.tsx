import { useEffect, useRef, useState } from "react";
import { Compartment, EditorState } from "@codemirror/state";
import { EditorView, drawSelection, highlightActiveLine, highlightActiveLineGutter, highlightSpecialChars, keymap, lineNumbers } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab, isolateHistory, redo, undo } from "@codemirror/commands";
import { bracketMatching, StreamLanguage, syntaxHighlighting } from "@codemirror/language";
import { closeBrackets, closeBracketsKeymap } from "@codemirror/autocomplete";
import { lua } from "@codemirror/legacy-modes/mode/lua";
import { lintGutter, setDiagnostics, type Diagnostic } from "@codemirror/lint";
import { highlightSelectionMatches, openSearchPanel, searchKeymap } from "@codemirror/search";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { applyPathFix, validPathDiagnostics, type PathAnalysis } from "./configEditor";
import { editorHighlightStyle, editorTheme } from "./editorTheme";
import { strategyLanguage } from "./strategyLanguage";
import { configLanguage } from "./configLanguage";

interface Props {
  value: string;
  onChange: (value: string) => void;
  kind: "conf" | "lua" | "text" | "strategy";
  label?: string;
  minHeight?: number;
  readOnly?: boolean;
  onSave?: () => void;
  checkPaths?: boolean;
}

/** One persistent EditorView per document: incremental highlighting, local undo,
 * and debounced read-only path diagnostics. Saving never waits for validation. */
export function CodeEditor({ value, onChange, kind, label = "Редактор кода", minHeight = 320, readOnly = false, onSave, checkPaths = true }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const callbacks = useRef({ onChange, onSave });
  callbacks.current = { onChange, onSave };
  const initialValue = useRef(value);
  initialValue.current = value;
  const externalChange = useRef(false);
  const editable = useRef(new Compartment());
  const [analysis, setAnalysis] = useState<{ source: string; result: PathAnalysis } | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!host.current) return;
    const editor = new EditorView({ parent: host.current, state: EditorState.create({ doc: initialValue.current, extensions: [
      lineNumbers(), highlightActiveLineGutter(), highlightSpecialChars(), drawSelection(), highlightActiveLine(),
      history(), bracketMatching(), closeBrackets(), lintGutter(), highlightSelectionMatches(), EditorView.lineWrapping, editorTheme,
      EditorState.phrases.of({
        Find: "Найти", Replace: "Заменить", next: "Далее", previous: "Назад", all: "Все",
        "match case": "Регистр", regexp: "Регулярное выражение", "by word": "Целое слово",
        replace: "Заменить", "replace all": "Заменить все", close: "Закрыть",
        "Go to line": "Перейти к строке", go: "Перейти", Diagnostics: "Диагностика", "No diagnostics": "Замечаний нет",
        "current match": "Текущее совпадение", "on line": "в строке",
        "replaced match on line $": "Заменено совпадение в строке $", "replaced $ matches": "Заменено совпадений: $",
      }),
      syntaxHighlighting(editorHighlightStyle),
      ...(kind === "text" ? [] : [kind === "strategy" ? strategyLanguage : kind === "conf" ? configLanguage : StreamLanguage.define(lua)]),
      editable.current.of([EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]),
      EditorView.contentAttributes.of({ "aria-label": label, spellcheck: "false", autocapitalize: "off", autocorrect: "off" }),
      keymap.of([{ key: "Mod-s", run: () => { callbacks.current.onSave?.(); return true; } }, ...closeBracketsKeymap, ...defaultKeymap, ...historyKeymap, ...searchKeymap, indentWithTab]),
      EditorView.updateListener.of((update) => { if (update.docChanged && !externalChange.current) callbacks.current.onChange(update.state.doc.toString()); }),
    ] }) });
    view.current = editor;
    return () => { view.current = null; editor.destroy(); };
  }, [kind]);

  useEffect(() => {
    const editor = view.current;
    if (!editor || editor.state.doc.toString() === value) return;
    const previous = editor.state.doc.toString();
    let from = 0, suffix = 0;
    while (from < Math.min(previous.length, value.length) && previous[from] === value[from]) from++;
    while (suffix < Math.min(previous.length, value.length) - from && previous[previous.length - 1 - suffix] === value[value.length - 1 - suffix]) suffix++;
    externalChange.current = true;
    try { editor.dispatch({ changes: { from, to: previous.length - suffix, insert: value.slice(from, value.length - suffix) }, annotations: isolateHistory.of("full") }); }
    finally { externalChange.current = false; }
  }, [value, kind]);
  useEffect(() => { view.current?.dispatch({ effects: editable.current.reconfigure([EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]) }); }, [readOnly]);

  useEffect(() => {
    const editor = view.current;
    if (editor) editor.dispatch(setDiagnostics(editor.state, []));
    setAnalysis(null); setError(""); setChecking(false);
    if (!checkPaths || kind === "text" || !value.trim()) return;
    if (value.length > 1024 * 1024) { setError("Проверка путей отключена для файлов больше 1 МиБ; редактирование и сохранение доступны."); return; }
    const controller = new AbortController();
    const timer = setTimeout(() => {
      setChecking(true);
      void api<PathAnalysis>("POST", "/api/nfqws2/paths", { content: value, kind: kind === "strategy" ? "conf" : kind }, { signal: controller.signal, timeoutMs: 10000, readOnly: true }).then((result) => {
        const current = view.current;
        if (controller.signal.aborted || !current || current.state.doc.toString() !== value) return;
        result.diagnostics = validPathDiagnostics(value, result.diagnostics ?? []);
        setAnalysis({ source: value, result });
        const diagnostics: Diagnostic[] = result.diagnostics.map((d) => ({ from: d.from, to: d.to, severity: "warning", message: d.message + (d.replacement ? `\nПредлагаемый путь: ${d.replacement}` : ""),
          actions: d.replacement === undefined || readOnly ? undefined : [{ name: "Исправить путь", apply: (target) => {
            if (target.state.doc.toString() !== value) return;
            const fixed = applyPathFix(value, d);
            if (fixed !== value) target.dispatch({ changes: { from: d.from, to: d.to, insert: d.replacement! } });
          } }],
        }));
        current.dispatch(setDiagnostics(current.state, diagnostics));
      }).catch((e) => { if (!controller.signal.aborted) setError("Проверка путей: " + (e as Error).message); })
        .finally(() => { if (!controller.signal.aborted) setChecking(false); });
    }, 500);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [value, kind, readOnly, checkPaths]);

  const fixes = analysis?.source === value ? analysis.result.diagnostics.filter((d) => d.replacement !== undefined).length : 0;
  return <div className="overflow-hidden rounded-md border border-line bg-input transition-[border-color,box-shadow] focus-within:border-ring focus-within:ring-[3px] focus-within:ring-ring/25" data-slot="code-editor">
    <div className="flex flex-wrap items-center gap-1 border-b border-line bg-panel px-2 py-2 text-xs">
      <span className="mr-2 inline-flex items-center gap-2 rounded-sm border border-line bg-line-soft px-2 py-1 font-medium text-ink-soft">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m8 8-4 4 4 4m8-8 4 4-4 4m-3-11-2 22" /></svg>
        {kind === "lua" ? "Lua" : kind === "conf" ? "Shell" : kind === "strategy" ? "NFQWS" : "Текст"}
      </span>
      <Button mini variant="ghost" disabled={readOnly} onClick={() => { if (view.current) undo(view.current); }} title="Отменить · Ctrl+Z">Отменить</Button>
      <Button mini variant="ghost" disabled={readOnly} onClick={() => { if (view.current) redo(view.current); }} title="Повторить · Ctrl+Shift+Z">Повторить</Button>
      <span className="mx-1 h-4 w-px bg-line" aria-hidden="true" />
      <Button mini variant="ghost" onClick={() => { if (view.current) openSearchPanel(view.current); }} title="Найти · Ctrl+F">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5" /><path d="m16 16 4 4" /></svg>
        Найти
      </Button>
      <span className="ml-auto px-2 text-[11px] text-muted">{readOnly ? "Только чтение" : onSave ? <><kbd className="rounded-sm border border-line bg-input px-1.5 py-0.5 font-sans text-[10px]">Ctrl+S</kbd><span className="ml-1.5 hidden sm:inline">Сохранить</span></> : "Изменения в черновике"}</span>
    </div>
    <div ref={host} style={{ minHeight }} className="[&_.cm-content]:min-h-[inherit] [&_.cm-editor]:min-h-[inherit]" />
    {kind !== "text" && checkPaths && <div className="flex flex-wrap items-center gap-2 border-t border-line bg-panel px-3 py-2.5 text-[11px] text-muted">
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${checking ? "animate-pulse bg-muted motion-reduce:animate-none" : error || analysis?.result.diagnostics.length ? "bg-warn" : analysis ? "bg-ok" : "bg-track"}`} aria-hidden="true" />
      <span className="min-w-0 flex-1">{checking ? "Проверяем пути…" : error || (analysis ? analysis.result.diagnostics.length ? `Замечания к путям: ${analysis.result.diagnostics.length}. Наведите курсор на подчёркнутый путь.` : `Пути проверены · ${analysis.result.platform}` : "Проверка путей после изменения текста")}</span>
      {fixes > 0 && !readOnly && <Button mini onClick={() => {
        if (!analysis || analysis.source !== view.current?.state.doc.toString()) return;
        callbacks.current.onChange(analysis.result.content);
      }}>Исправить пути ({fixes})</Button>}
    </div>}
  </div>;
}

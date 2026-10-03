import { useEffect, useId, useMemo, useRef, useState } from "react";
import { RadioGroup } from "@base-ui/react/radio-group";
import { Radio } from "@base-ui/react/radio";
import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { Field, Input } from "@/components/ui/form";
import { CodeEditor } from "./CodeEditor";
import { configMode, parseConfigAssignments, patchConfigMode, patchConfigValue, type ConfigMode } from "./configEditor";

const CONF = "nfqws2.conf";
const modeDescriptions: Record<ConfigMode, string> = {
  auto: "Домены из user.list и автоматическое пополнение auto.list.",
  list: "Только домены из user.list.",
  all: "Все домены, кроме exclude.list.",
  custom: "Пользовательский режим. Дополнительные аргументы сохраняются при выборе режима; сложные выражения изменяются в полном файле.",
};
const strategies = [
  ["NFQWS_BASE_ARGS", "Параметры запуска", "Загрузка Lua, blob-файлы и общие параметры движка."],
  ["NFQWS_ARGS", "Базовая стратегия HTTP(S)", "Основная стратегия для TCP: HTTP, TLS и другие протоколы."],
  ["NFQWS_ARGS_QUIC", "Стратегия QUIC", "Правила для QUIC / HTTP/3."],
  ["NFQWS_ARGS_UDP", "Стратегия UDP", "Другой UDP-трафик; NFQWS_EXTRA_ARGS к этой стратегии не применяется."],
  ["NFQWS_ARGS_IPSET", "IPSET", "Списки IP-адресов и исключений."],
  ["NFQWS_ARGS_CUSTOM", "Пользовательские стратегии", "Дополнительные фильтры и стратегии с разделителем --new."],
  ["NFQWS_EXTRA_ARGS", "Дополнительные аргументы и режим", "Ссылки $MODE_* сохраняются вместе с вашими дополнительными флагами."],
] as const;

/** Raw file is the sole source of truth; each form edits one assignment span. */
export function ConfigPane({ restart }: { restart: () => Promise<void> }) {
  const modeHintId = useId();
  const [content, setContent] = useState<string | null>(null);
  const [saved, setSaved] = useState("");
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [remoteChanged, setRemoteChanged] = useState(false);
  const [editorError, setEditorError] = useState("");
  const sequence = useRef(0);
  const dirty = content !== null && content !== saved;
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  const parsed = useMemo(() => parseConfigAssignments(content ?? ""), [content]);

  const load = async () => {
    const request = ++sequence.current;
    setBusy(true);
    try {
      const d = await api<{ content: string }>("GET", `/api/nfqws2/file?kind=conf&name=${CONF}`);
      if (sequence.current !== request) return;
      setContent(d.content ?? ""); setSaved(d.content ?? ""); setLoadError(""); setRemoteChanged(false); setEditorError("");
    } catch (e) { if (sequence.current === request) setLoadError((e as Error).message); }
    finally { if (sequence.current === request) setBusy(false); }
  };
  useEffect(() => {
    void load();
    const changed = (event: Event) => { if ((event as CustomEvent).detail?.source === "config") return; if (dirtyRef.current) setRemoteChanged(true); else void load(); };
    window.addEventListener("nfqws2-files-changed", changed);
    return () => { sequence.current++; window.removeEventListener("nfqws2-files-changed", changed); };
  }, []);

  const patch = (key: string, value: string) => {
    try { setContent(patchConfigValue(content ?? "", key, value)); setEditorError(""); }
    catch (e) { setEditorError((e as Error).message); }
  };
  const save = async () => {
    if (content === null || busy || !dirty) return;
    if (remoteChanged && !(await confirmDialog({ title: "Конфиг на роутере мог измениться", body: "Заменить файл nfqws2.conf вашим несохранённым черновиком?", confirmLabel: "Заменить", danger: true }))) return;
    setBusy(true);
    try {
      await api("POST", "/api/nfqws2/file", { kind: "conf", name: CONF, content });
      setSaved(content); setRemoteChanged(false);
      window.dispatchEvent(new CustomEvent("nfqws2-files-changed", { detail: { source: "config" } }));
      toast("nfqws2.conf сохранён", "ok");
      if (await confirmDialog({ title: "Применить настройки?", body: "Перезапустить nfqws2 (~2 с обхода DPI прервётся). Роутер не перезагружается.", confirmLabel: "Перезапустить", cancelLabel: "Позже" })) await restart();
    } catch (e) { toast((e as Error).message, "err"); }
    finally { setBusy(false); }
  };
  const reset = async () => {
    if (dirty && !(await confirmDialog({ title: "Сбросить несохранённые правки?", body: "Загрузить текущий файл с роутера. Черновик будет заменён.", confirmLabel: "Загрузить", danger: true }))) return;
    await load();
  };
  if (content === null) return <Card><p className="text-xs text-muted">{loadError || "Загрузка nfqws2.conf…"}</p>{loadError && <Button className="mt-2" disabled={busy} onClick={load}>Повторить</Button>}</Card>;
  const val = (key: string) => parsed.assignments.get(key)?.value ?? "";
  const readonly = busy || !parsed.canAppend;
  const mode = configMode(parsed.assignments.get("NFQWS_EXTRA_ARGS"));

  return <>
    {(remoteChanged || loadError || editorError || parsed.warning) && <Card><div className="space-y-2 text-xs text-warn" role="status">
      {remoteChanged && <p>Файлы на роутере изменились. Ваш черновик сохранён; перед записью проверьте изменения или загрузите файл заново.</p>}
      {loadError && <p>{loadError}</p>}{editorError && <p>{editorError}</p>}{parsed.warning && <p>{parsed.warning}</p>}
    </div></Card>}
    <Card title="Настройки запуска" sub="форма и полный файл редактируют один черновик">
      <div className="grid grid-cols-1 gap-x-4 gap-y-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="WAN-интерфейсы" hint="через пробел"><Input disabled={readonly} value={val("ISP_INTERFACE")} onChange={(e) => patch("ISP_INTERFACE", e.target.value)} /></Field>
        <fieldset className="min-w-0">
          <legend className="mb-1.5 text-sm font-medium leading-5">Режим работы{mode === "custom" && <span className="ml-2 rounded-sm border border-line px-1.5 py-0.5 text-[10px] font-normal text-muted">Пользовательский</span>}</legend>
          <RadioGroup disabled={readonly} value={mode === "custom" ? null : mode} aria-label="Режим работы" aria-describedby={modeHintId} className="grid min-h-8 grid-cols-3 gap-0.5 rounded-md bg-rhea-input/50 p-0.5" onValueChange={(next) => {
            if (next !== "auto" && next !== "list" && next !== "all") return;
            try { setContent(patchConfigMode(content, next)); setEditorError(""); }
            catch (error) { setEditorError((error as Error).message); }
          }}>
            {(["auto", "list", "all"] as const).map((value) => <Radio.Root key={value} value={value} title={modeDescriptions[value]} className="flex min-h-7 cursor-pointer select-none items-center justify-center rounded-sm px-2 text-xs font-medium text-muted outline-none transition-[color,background-color,box-shadow] hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring data-[checked]:bg-panel data-[checked]:text-foreground data-[checked]:shadow-sm data-[disabled]:pointer-events-none data-[disabled]:opacity-50">{value === "auto" ? "Auto" : value === "list" ? "List" : "All"}</Radio.Root>)}
          </RadioGroup>
          <p id={modeHintId} className="mt-1.5 text-[11px] leading-4 text-muted">{modeDescriptions[mode]}</p>
        </fieldset>
        <Field label="Политика Keenetic"><Input disabled={readonly} value={val("POLICY_NAME")} onChange={(e) => patch("POLICY_NAME", e.target.value)} /></Field>
        <Field label="TCP-порты"><Input disabled={readonly} value={val("TCP_PORTS")} onChange={(e) => patch("TCP_PORTS", e.target.value)} /></Field>
        <Field label="UDP-порты"><Input disabled={readonly} value={val("UDP_PORTS")} onChange={(e) => patch("UDP_PORTS", e.target.value)} /></Field>
        <Field label="Номер NFQUEUE"><Input disabled={readonly} value={val("NFQUEUE_NUM")} onChange={(e) => patch("NFQUEUE_NUM", e.target.value)} /></Field>
      </div>
      <div className="mt-4 flex flex-wrap gap-x-6 gap-y-3">
        {[["IPV6_ENABLED", "IPv6"], ["POLICY_EXCLUDE", "Исключать политику"], ["LOG_LEVEL", "Отладочный лог"]].map(([key, label]) => <Switch key={key} disabled={readonly} checked={/^(1|true|yes)$/i.test(val(key).trim())} onChange={(on) => patch(key, on ? "1" : "0")} label={label} />)}
      </div>
    </Card>
    <Card title="Стратегии и аргументы" sub="значения без внешних кавычек; shell-переменные и экранирование остаются в файле">
      <div className="space-y-3">{strategies.map(([key, title, hint]) => <details key={key} className="rounded-lg border border-line" open={key === "NFQWS_ARGS" ? true : undefined}>
        <summary className="cursor-pointer px-3 py-2 text-[13px] font-medium">{title}<span className="ml-2 font-mono text-[11px] text-muted">{key}</span></summary>
        <div className="space-y-2 border-t border-line p-3"><p className="text-xs text-muted">{hint}</p><CodeEditor value={val(key)} onChange={(value) => patch(key, value)} kind="strategy" checkPaths={false} minHeight={100} label={title} readOnly={readonly} onSave={() => void save()} /></div>
      </details>)}</div>
    </Card>
    <Card title={<span className="font-mono text-sm">nfqws2.conf{dirty && <span className="ml-1.5 text-warn">●</span>}</span>} sub="полный файл с подсветкой, поиском и проверкой путей">
      <CodeEditor value={content} onChange={(text) => { setContent(text); setEditorError(""); }} kind="conf" label="Полный файл nfqws2.conf" readOnly={busy} onSave={() => void save()} />
      <div className="mt-3 flex flex-wrap items-center gap-2"><Button variant="primary" onClick={save} disabled={busy || !dirty}>{busy ? "Сохранение…" : "Сохранить"}</Button><Button variant="ghost" onClick={reset} disabled={busy}>Загрузить с роутера</Button><span className="text-xs text-muted">{dirty ? "Есть несохранённые изменения" : "сохранено"}</span></div>
    </Card>
  </>;
}

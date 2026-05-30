import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { Field, Input, Select, Textarea } from "@/components/ui/form";

const CONF = "nfqws2.conf";

// Read a KEY=value (quoted or bare) from the shell-config text.
function getVal(src: string, key: string): string {
  const q = src.match(new RegExp(`^[ \\t]*${key}="([^"]*)"[ \\t]*$`, "m"));
  if (q) return q[1];
  const u = src.match(new RegExp(`^[ \\t]*${key}=([^\\n#]*)$`, "m"));
  if (u) return u[1].trim();
  return "";
}

// Line-patch a single key, preserving its quoting style and indentation. A
// function replacement is used so a value containing "$" (e.g. "$MODE_AUTO") is
// never interpreted as a regex backreference. Absent keys are left untouched.
function setVal(src: string, key: string, value: string): string {
  const reQ = new RegExp(`^([ \\t]*${key}=)"[^"]*"([ \\t]*)$`, "m");
  if (reQ.test(src)) return src.replace(reQ, (_m, p1, p2) => `${p1}"${value}"${p2}`);
  const reU = new RegExp(`^([ \\t]*${key}=)[^\\n#]*$`, "m");
  if (reU.test(src)) return src.replace(reU, (_m, p1) => `${p1}${value}`);
  return src;
}

type Mode = "list" | "auto" | "all";
const MODE_TOKEN: Record<Mode, string> = { list: "$MODE_LIST", auto: "$MODE_AUTO", all: "$MODE_ALL" };
function getMode(src: string): Mode {
  const e = getVal(src, "NFQWS_EXTRA_ARGS");
  if (e.includes("MODE_AUTO")) return "auto";
  if (e.includes("MODE_ALL")) return "all";
  if (e.includes("MODE_LIST")) return "list";
  return "auto";
}

/** Конфиг sub-tab: structured quick-settings that live-patch the raw text, plus
 *  the full raw nfqws2.conf editor (the single source of truth). */
export function ConfigPane({ restart }: { restart: () => Promise<void> }) {
  const [content, setContent] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const d = await api<{ content: string }>("GET", `/api/nfqws2/file?kind=conf&name=${CONF}`);
      setContent(d.content ?? "");
      setDirty(false);
    } catch (e) {
      toast((e as Error).message, "err");
      setContent("");
    }
  };
  useEffect(() => { void load(); }, []);

  const patch = (key: string, val: string) => { setContent((c) => (c == null ? c : setVal(c, key, val))); setDirty(true); };

  const save = async () => {
    if (content == null) return;
    setBusy(true);
    try {
      await api("POST", "/api/nfqws2/file", { kind: "conf", name: CONF, content });
      setDirty(false);
      toast("nfqws2.conf сохранён", "ok");
      if (await confirmDialog({ title: "Применить настройки?", body: "Перезапустить nfqws2 (~2 с обхода DPI прервётся). Роутер не перезагружается.", confirmLabel: "Перезапустить", cancelLabel: "Позже" })) await restart();
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  if (content == null) return <Card><span className="text-xs text-muted">Загрузка nfqws2.conf…</span></Card>;
  const src = content;

  return (
    <>
      <Card title="Быстрые настройки" sub="правят соответствующие строки nfqws2.conf">
        <div className="grid grid-cols-1 gap-x-4 gap-y-3 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="WAN-интерфейс(ы)" hint="через пробел"><Input value={getVal(src, "ISP_INTERFACE")} onChange={(e) => patch("ISP_INTERFACE", e.target.value)} /></Field>
          <Field label="Режим списков">
            <Select value={getMode(src)} onChange={(e) => patch("NFQWS_EXTRA_ARGS", MODE_TOKEN[e.target.value as Mode])}>
              <option value="list">Только user.list</option>
              <option value="auto">Авто (user + auto.list)</option>
              <option value="all">Все, кроме exclude.list</option>
            </Select>
          </Field>
          <Field label="Политика Keenetic"><Input value={getVal(src, "POLICY_NAME")} onChange={(e) => patch("POLICY_NAME", e.target.value)} /></Field>
          <Field label="TCP-порты" className="sm:col-span-2"><Input value={getVal(src, "TCP_PORTS")} onChange={(e) => patch("TCP_PORTS", e.target.value)} /></Field>
          <Field label="NFQUEUE"><Input value={getVal(src, "NFQUEUE_NUM")} onChange={(e) => patch("NFQUEUE_NUM", e.target.value)} /></Field>
          <Field label="UDP-порты" className="sm:col-span-3"><Input value={getVal(src, "UDP_PORTS")} onChange={(e) => patch("UDP_PORTS", e.target.value)} /></Field>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-x-6 gap-y-1">
          <div className="flex h-[38px] items-center"><Switch checked={getVal(src, "IPV6_ENABLED") === "1"} onChange={(on) => patch("IPV6_ENABLED", on ? "1" : "0")} label="IPv6" /></div>
          <div className="flex h-[38px] items-center"><Switch checked={getVal(src, "POLICY_EXCLUDE") === "1"} onChange={(on) => patch("POLICY_EXCLUDE", on ? "1" : "0")} label="Исключать политику" /></div>
          <div className="flex h-[38px] items-center"><Switch checked={getVal(src, "LOG_LEVEL") === "1"} onChange={(on) => patch("LOG_LEVEL", on ? "1" : "0")} label="Отладочный лог" /></div>
        </div>
      </Card>

      <Card title={<span className="font-mono text-sm">nfqws2.conf{dirty && <span className="ml-1.5 text-warn">●</span>}</span>} sub="полный файл — стратегии (NFQWS_ARGS…) правьте здесь">
        <Textarea rows={26} value={src} spellCheck={false} onChange={(e) => { setContent(e.target.value); setDirty(true); }} />
        <div className="mt-2.5 flex flex-wrap items-center gap-2">
          <Button variant="primary" onClick={save} disabled={busy || !dirty}>{busy ? "Сохранение…" : "Сохранить"}</Button>
          <Button variant="ghost" onClick={load} disabled={busy}>Сбросить правки</Button>
          {!dirty && <span className="text-xs text-muted">сохранено</span>}
        </div>
      </Card>
    </>
  );
}

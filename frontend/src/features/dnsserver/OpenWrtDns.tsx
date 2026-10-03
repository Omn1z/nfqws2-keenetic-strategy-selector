import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field, Select } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";
import type { OpenWrtDnsState } from "@/types/api";
import { initialOpenWrtDnsSelection, openWrtDnsApplyBlock, openWrtDnsEndpoint, openWrtDnsRestoreAllowed, type OpenWrtDnsSelection } from "./openWrtDnsState";

type Props = {
  dirty: boolean;
  running: boolean;
  busy: boolean;
  endpoint: string;
  configurationKey: string;
  onSupportedChange: (supported: boolean) => void;
  /** Acquires the parent's synchronous mutation lock; false rejects a race. */
  onBusyChange: (busy: boolean) => boolean;
};

export function OpenWrtDns({ dirty, running, busy, endpoint, configurationKey, onSupportedChange, onBusyChange }: Props) {
  const [state, setState] = useState<OpenWrtDnsState | null>(null);
  const [selection, setSelection] = useState<OpenWrtDnsSelection>({ interface: "", instance: "" });
  const [loading, setLoading] = useState(true);
  const [pending, setPending] = useState<"apply" | "restore" | null>(null);
  const [error, setError] = useState("");
  const [writeError, setWriteError] = useState("");
  const mounted = useRef(false);
  const working = useRef(false);
  const read = useRef<AbortController | null>(null);
  const callbacks = useRef({ onSupportedChange, onBusyChange });
  callbacks.current = { onSupportedChange, onBusyChange };

  const receive = (value: OpenWrtDnsState) => {
    setState(value);
    setSelection((current) => initialOpenWrtDnsSelection(value, current));
    callbacks.current.onSupportedChange(value.supported);
  };
  const refresh = async () => {
    read.current?.abort();
    const controller = new AbortController();
    read.current = controller;
    setLoading(true);
    try {
      const result = await api<OpenWrtDnsState>("GET", "/api/dnsserver/openwrt", undefined, { signal: controller.signal });
      if (!mounted.current || controller.signal.aborted || read.current !== controller) return;
      receive(result); setError("");
    } catch (e) {
      if (mounted.current && !controller.signal.aborted && read.current === controller) setError((e as Error).message);
    } finally {
      if (mounted.current && read.current === controller) setLoading(false);
    }
  };
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; read.current?.abort(); };
  }, []);
  useEffect(() => {
    if (!working.current) void refresh();
    return () => { read.current?.abort(); };
  }, [configurationKey]);

  const change = async (operation: "apply" | "restore") => {
    if (working.current || loading || error || !state) return;
    const blocked = operation === "apply"
      ? !!openWrtDnsApplyBlock(state, selection, { dirty, running, busy })
      : !openWrtDnsRestoreAllowed(state, busy);
    if (blocked || !callbacks.current.onBusyChange(true)) return;
    working.current = true; setPending(operation); setWriteError("");
    read.current?.abort();
    try {
      const body = operation === "apply" ? { ...selection, revision: state.revision } : { revision: state.revision };
      const result = await api<OpenWrtDnsState>("POST", `/api/dnsserver/openwrt/${operation}`, body, { timeoutMs: 60_000 });
      if (mounted.current) {
        receive(result);
        toast(operation === "apply" ? "DNS OpenWrt подключён к DNS Server" : "Прежние настройки DNS OpenWrt восстановлены", "ok");
      }
    } catch (e) {
      if (mounted.current) setWriteError(`${(e as Error).message} Проверьте состояние ниже перед повторной попыткой.`);
    } finally {
      // The response can be lost after UCI was committed. Read once to display
      // actual ownership/revision before allowing another apply or restore.
      if (mounted.current) await refresh();
      working.current = false;
      if (mounted.current) setPending(null);
      callbacks.current.onBusyChange(false);
    }
  };

  if (state?.supported === false && !error) return null;
  const blocked = openWrtDnsApplyBlock(state, selection, { dirty, running, busy });
  const unavailable = busy || !!pending || loading || !!error;
  return <Card title="DNS OpenWrt" sub="автоматическое подключение роутера" head={<div className="flex flex-wrap items-center gap-2">
    {state?.managed && <Badge kind={state.conflict || state.pending ? "warn" : "ok"}>{state.conflict ? "Настройки изменены" : state.pending ? "Требуется восстановление" : "Подключён"}</Badge>}
    <Button mini disabled={busy || !!pending || loading} onClick={() => { setWriteError(""); void refresh(); }}>{loading ? "Обновление…" : "Обновить"}</Button>
  </div>}>
    {!state && !error && <p role="status" className="text-xs text-muted">Проверка интерфейсов и DNS OpenWrt…</p>}
    {error && <p role="alert" className="text-xs text-bad [overflow-wrap:anywhere]">Не удалось прочитать настройки OpenWrt: {error}</p>}
    {state?.supported && <>
      <p className="mb-3 text-xs text-muted">OpenWrt и устройства продолжат использовать DNS роутера на порту 53. dnsmasq будет пересылать запросы в сохранённый адрес DNS Server: <code>{endpoint || "адрес пока недоступен"}</code>. Это позволяет использовать локальный DNS-сервер с отдельным портом.</p>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Интерфейс OpenWrt"><Select value={selection.interface} disabled={unavailable} onChange={(e) => setSelection((value) => ({ ...value, interface: e.target.value }))}>
          {!selection.interface && <option value="">Выберите интерфейс</option>}
          {(state.interfaces ?? []).map((entry) => <option key={entry.id} value={entry.id}>{entry.label || entry.id}</option>)}
        </Select></Field>
        <Field label="Экземпляр dnsmasq"><Select value={selection.instance} disabled={unavailable} onChange={(e) => setSelection((value) => ({ ...value, instance: e.target.value }))}>
          {!selection.instance && <option value="">Выберите экземпляр</option>}
          {(state.instances ?? []).map((entry) => <option key={entry.id} value={entry.id}>{entry.label || entry.id}</option>)}
        </Select></Field>
      </div>
      <p className="mt-2 text-xs text-muted">На выбранном интерфейсе будет включён пользовательский DNS с IP этого роутера. Пересылка dnsmasq применяется ко всем сетям, которые обслуживает выбранный экземпляр. Отдельные DNS-правила для доменов сохраняются.</p>
      {state.binding && <p className="mt-3 text-xs text-muted">Текущее подключение: <b>{state.binding.interface}</b> · {state.binding.instance} → <code>{openWrtDnsEndpoint(state.binding.endpoint)}</code></p>}
      <p className="mt-2 text-xs text-muted">Перед применением сохраняется резервная копия изменяемых настроек. Кнопка восстановления вернёт их прежние значения.</p>
      {state.managed && <p className="mt-2 text-xs text-muted">При отключении DNS Server или смене его IP/порта прежние настройки OpenWrt восстанавливаются автоматически. После смены адреса включите DNS Server и повторно примените подключение здесь.</p>}
      {state.conflict && <p role="alert" className="mt-3 text-xs text-warn [overflow-wrap:anywhere]">{state.conflict}</p>}
      {(state.warnings ?? []).map((warning, index) => <p key={index} className="mt-2 text-xs text-warn [overflow-wrap:anywhere]">{warning}</p>)}
      {blocked && !busy && !state.conflict && <p className="mt-3 text-xs text-muted">{blocked}</p>}
      <div className="mt-4 flex flex-wrap gap-2">
        <Button variant="primary" disabled={unavailable || !!blocked} onClick={() => { void change("apply"); }}>{pending === "apply" ? "Подключение…" : state.managed ? "Применить подключение" : "Подключить DNS Server"}</Button>
        {state.managed && <Button disabled={unavailable || !openWrtDnsRestoreAllowed(state, busy)} onClick={() => { void change("restore"); }}>{pending === "restore" ? "Восстановление…" : "Восстановить прежний DNS"}</Button>}
      </div>
    </>}
    {writeError && <p role="alert" className="mt-3 text-xs text-bad [overflow-wrap:anywhere]">{writeError}</p>}
  </Card>;
}

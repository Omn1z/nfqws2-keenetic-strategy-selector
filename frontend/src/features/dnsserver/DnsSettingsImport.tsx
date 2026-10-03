import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { Field, Select } from "@/components/ui/form";
import type { DnsSettingsImportPlan, DnsSettingsImportRequest } from "@/types/api";
import { buildDnsImportRequest, DNS_SETTINGS_FILE_LIMIT, initialDnsImportMapping, parseDnsSettingsDocument } from "./importDnsSettings";

type Props = {
  dirty: boolean;
  saving: boolean;
  onClose: () => void;
  onImport: (request: DnsSettingsImportRequest) => Promise<boolean>;
};

export function DnsSettingsImport({ dirty, saving, onClose, onImport }: Props) {
  const [document, setDocument] = useState("");
  const [filename, setFilename] = useState("");
  const [plan, setPlan] = useState<DnsSettingsImportPlan | null>(null);
  const [mapping, setMapping] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const mounted = useRef(true);
  const working = useRef(false);
  const controller = useRef<AbortController | null>(null);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; controller.current?.abort(); };
  }, []);
  const preview = async (text: string, selection?: DnsSettingsImportRequest) => {
    const aborter = new AbortController();
    controller.current = aborter;
    const result = await api<DnsSettingsImportPlan>("POST", "/api/dnsserver/import/preview", selection ?? { document: text }, { signal: aborter.signal, readOnly: true });
    if (!mounted.current || aborter.signal.aborted) return;
    setPlan(result);
    setMapping(initialDnsImportMapping(result));
  };
  const choose = async (file?: File) => {
    if (!file || working.current || saving) return;
    working.current = true; setBusy(true); setError(""); setPlan(null); setDocument(""); setMapping(""); setFilename(file.name);
    try {
      if (file.size > DNS_SETTINGS_FILE_LIMIT) throw new Error("Файл настроек DNS превышает 16 МиБ.");
      const text = (await file.text()).replace(/^\uFEFF/, "");
      parseDnsSettingsDocument(text);
      if (!mounted.current) return;
      setDocument(text);
      await preview(text);
    } catch (e) { if (mounted.current) setError((e as Error).message); }
    finally { working.current = false; if (mounted.current) setBusy(false); }
  };
  const refresh = async () => {
    if (!document || working.current || saving) return;
    working.current = true; setBusy(true); setError(""); setPlan(null);
    try { await preview(document); }
    catch (e) { if (mounted.current) setError((e as Error).message); }
    finally { working.current = false; if (mounted.current) setBusy(false); }
  };
  const selectMapping = async (value: string) => {
    if (!plan || working.current || saving) return;
    let request: DnsSettingsImportRequest;
    try { request = buildDnsImportRequest(document, plan, value); }
    catch (e) { setError((e as Error).message); return; }
    working.current = true; setBusy(true); setError(""); setMapping(value);
    try { await preview(document, request); }
    catch (e) { if (mounted.current) { setError((e as Error).message); setPlan(null); } }
    finally { working.current = false; if (mounted.current) setBusy(false); }
  };
  const apply = async () => {
    if (!plan || working.current || saving) return;
    let request: DnsSettingsImportRequest;
    try { request = buildDnsImportRequest(document, plan, mapping); }
    catch (e) { setError((e as Error).message); return; }
    working.current = true; setBusy(true); setError("");
    try {
      if (await onImport(request)) onClose();
      else setError("Импорт не подтверждён. Обновите предварительный просмотр: настройки могли измениться или сохраниться после потери ответа.");
    } finally { working.current = false; if (mounted.current) setBusy(false); }
  };
  return <Modal title="Импорт настроек DNS Server" size="lg" onClose={() => { if (!saving && !working.current) onClose(); }} actions={<>
    <Button disabled={busy || saving} onClick={onClose}>Отмена</Button>
    {document && <Button disabled={busy || saving} onClick={refresh}>Обновить просмотр</Button>}
    <Button variant="primary" disabled={!plan || busy || saving || !mapping} onClick={apply}>{saving ? "Импорт…" : "Применить импорт"}</Button>
  </>}>
    <p className="mb-3 text-xs text-muted">Выберите JSON экспорта DNS Server. Сначала будет показана конфигурация; она заменит все сохранённые настройки DNS только после «Применить импорт».</p>
    {dirty && <p className="mb-3 text-xs text-warn">На странице есть несохранённые изменения. Применение импорта заменит и этот черновик.</p>}
    <Field label="Файл настроек DNS"><input type="file" accept="application/json,.json" disabled={busy || saving} onChange={(e) => { void choose(e.target.files?.[0]); e.target.value = ""; }} className="block w-full rounded-lg border border-line bg-input p-2 text-xs" /></Field>
    {filename && <p className="mt-2 text-xs text-muted">{filename}</p>}
    {busy && !saving && <p role="status" className="mt-3 text-xs text-muted">Проверка настроек и подключения…</p>}
    {error && <p role="alert" className="mt-3 text-xs text-bad">{error}</p>}
    {plan && <>
      <div className="mt-4 grid gap-2 rounded-lg border border-line p-3 text-xs sm:grid-cols-2">
        <p>Сервис: <b>{plan.listener.enabled ? "включён" : "выключен"}</b></p><p>Адрес: <code>{plan.listener.address}</code></p>
        <p>Режим: <b>{plan.config.route_mode === "vpn_only" ? "только VPN" : "NFQWS и VPN"}</b></p><p>Кэш: {plan.config.cache_size} записей, до {plan.config.cache_ttl_seconds} сек.</p>
        <p>Группы доменов: {plan.config.rules.length}</p><p>Провайдеров в основном пуле: {1 + (plan.config.default_pool?.length ?? 0)}</p>
        <p>Блокировка: {plan.config.filtering?.enabled ? "включена" : "выключена"}</p><p>Планировщик: {plan.config.scheduler_enabled === false ? "выключен" : "включён"}</p>
        <p>Shadow DNS: {plan.config.shadow_dns?.enabled ? "включён" : "выключен"} · {plan.config.shadow_dns?.domains.length ?? 0} правил</p><p>DNS провайдера определяется автоматически на этом роутере.</p>
      </div>
      <div className="mt-3">
        <Field label="VPN-подключение для DNS"><Select value={mapping} disabled={busy || saving} onChange={(e) => { void selectMapping(e.target.value); }}>
          <option value="auto">Автоматически — подключения этого роутера</option>
          {plan.config.route_mode !== "vpn_only" && <option value="off">Без VPN — только NFQWS</option>}
          {plan.vpn.candidates.map((v) => <option key={v.ref} value={v.ref}>{[v.label || v.ref, v.endpoint, v.client_iface].filter(Boolean).join(" · ")}</option>)}
        </Select></Field>
        <p className="mt-2 text-xs text-muted">{mapping === "auto" ? "Автоматический режим использует включённые VPN-подключения этого роутера. Можно выбрать конкретное подключение из списка." : mapping === "off" ? "VPN для DNS отключён. Можно выбрать подключение этого роутера или автоматику." : "Выбрано подключение этого роутера. Можно выбрать другое или автоматику."}</p>
        {mapping === "auto" && plan.vpn.candidates.length === 0 && <p className="mt-2 text-xs text-warn">{plan.config.route_mode === "vpn_only" ? "VPN-подключений пока нет. Настройки можно импортировать; запросы через VPN заработают после добавления и включения подключения." : "VPN-подключений пока нет. Настройки можно импортировать; новые подключения будут подхвачены автоматически."}</p>}
        {plan.config.route_mode === "vpn_only" && <p className="mt-2 text-xs text-muted">Режим «Только VPN» сохраняется и при автоматическом выборе подключения.</p>}
      </div>
      {plan.warnings.map((warning, index) => <p key={index} className="mt-2 text-xs text-warn">{warning}</p>)}
      <p className="mt-3 text-xs text-warn">Импорт включает адрес, порт и состояние DNS-сервиса. При изменении рабочих настроек сервис перезапустится. Проверьте адрес и VPN перед применением.</p>
      <details className="mt-3 rounded-lg border border-line p-3 text-xs"><summary className="cursor-pointer font-semibold">Настройки после импорта</summary><pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap [overflow-wrap:anywhere]">{JSON.stringify(plan.config, null, 2)}</pre></details>
    </>}
  </Modal>;
}

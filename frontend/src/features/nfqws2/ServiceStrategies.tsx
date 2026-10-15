import { useEffect, useMemo, useRef, useState } from "react";
import { api, ApiHTTPError } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { confirmDialog } from "@/components/ui/Confirm";
import { Field, Input, Textarea } from "@/components/ui/form";
import { Switch } from "@/components/ui/Switch";
import { toast } from "@/components/ui/Toast";
import { CodeEditor } from "./CodeEditor";
import { newServiceGroup, newServiceID, serviceCheckDomains, serviceEntries, servicesPayload, servicesSignature } from "./serviceStrategiesModel";
import type { DomainCheckResult, ServiceGroup, ServiceGroupKind, ServicePreview, ServiceState, ServiceStrategy } from "./serviceStrategiesModel";

const endpoint = "/api/nfqws2/service-strategies";

function moveItem<T>(items: T[], index: number, direction: -1 | 1): T[] {
  const target = index + direction;
  if (target < 0 || target >= items.length) return items;
  const result = [...items];
  [result[index], result[target]] = [result[target], result[index]];
  return result;
}

/** One retained draft for all services; only Save mutates the router. */
export function ServiceStrategies({ restart, canRestart = true }: { restart: () => Promise<boolean>; canRestart?: boolean }) {
  const [services, setServices] = useState<ServiceStrategy[] | null>(null);
  const [savedSignature, setSavedSignature] = useState("");
  const [revision, setRevision] = useState("");
  const [selectedID, setSelectedID] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [saveError, setSaveError] = useState("");
  const [stale, setStale] = useState(false);
  const [needsRestart, setNeedsRestart] = useState(false);
  const [preview, setPreview] = useState<ServicePreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [previewError, setPreviewError] = useState("");
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState("");
  const [checks, setChecks] = useState<{ source: string; serviceID: string; results: DomainCheckResult[] } | null>(null);
  const signature = useMemo(() => servicesSignature(services ?? []), [services]);
  const dirty = services !== null && signature !== savedSignature;
  const dirtyRef = useRef(dirty); dirtyRef.current = dirty;
  const revisionRef = useRef(revision); revisionRef.current = revision;
  const loadSequence = useRef(0);
  const checkSequence = useRef(0);
  const mutation = useRef(false);
  const editingDisabled = busy || loading;

  const invalidateChecks = () => {
    checkSequence.current++; setChecking(false); setChecks(null); setCheckError("");
  };

  const load = async (replace = false) => {
    const request = ++loadSequence.current;
    setLoading(true);
    try {
      const data = await api<ServiceState>("GET", endpoint);
      if (request !== loadSequence.current) return;
      if (!replace && dirtyRef.current) {
        setStale(data.revision !== revisionRef.current);
      } else {
        setServices(data.services ?? []);
        setSavedSignature(servicesSignature(data.services ?? []));
        setRevision(data.revision);
        revisionRef.current = data.revision;
        setSelectedID(current => data.services?.some(service => service.id === current) ? current : data.services?.[0]?.id ?? "");
        setStale(false); setSaveError("");
      }
      setNeedsRestart(data.restart_required);
      setLoadError("");
    } catch (error) {
      if (request === loadSequence.current) setLoadError((error as Error).message);
    } finally {
      if (request === loadSequence.current) setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    const changed = (event: Event) => {
      if ((event as CustomEvent).detail?.source === "service-strategies" || mutation.current) return;
      invalidateChecks();
      void load();
    };
    window.addEventListener("nfqws2-files-changed", changed);
    return () => { loadSequence.current++; checkSequence.current++; window.removeEventListener("nfqws2-files-changed", changed); };
  }, []);

  useEffect(() => {
    setPreview(null); setPreviewError("");
    if (services === null) return;
    const controller = new AbortController();
    setPreviewing(true);
    const timer = setTimeout(() => {
      void api<ServicePreview>("POST", `${endpoint}/preview`, { services: JSON.parse(signature) }, { signal: controller.signal, readOnly: true }).then(data => {
        if (!controller.signal.aborted) setPreview(data);
      }).catch(error => {
        if (!controller.signal.aborted) setPreviewError((error as Error).message);
      }).finally(() => {
        if (!controller.signal.aborted) setPreviewing(false);
      });
    }, 500);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [signature, services === null]);

  const selected = services?.find(service => service.id === selectedID);
  const selectedIndex = services?.findIndex(service => service.id === selectedID) ?? -1;
  const domains = serviceCheckDomains(selected);
  const selectedSource = selected ? servicesSignature([selected]) : "";
  const currentChecks = checks?.serviceID === selectedID ? checks : null;
  const checksStale = currentChecks && currentChecks.source !== selectedSource;

  const patchService = (patch: Partial<ServiceStrategy>) => {
    setServices(current => current?.map(service => service.id === selectedID ? { ...service, ...patch } : service) ?? null);
    setSaveError("");
  };
  const patchGroup = (id: string, patch: Partial<ServiceGroup>) => {
    if (selected) patchService({ groups: selected.groups.map(group => group.id === id ? { ...group, ...patch } : group) });
  };
  const addService = () => {
    const service: ServiceStrategy = { id: newServiceID(), name: "Новый сервис", enabled: false, groups: [newServiceGroup("domains", newServiceID()), newServiceGroup("ips", newServiceID())] };
    setServices(current => [...(current ?? []), service]); setSelectedID(service.id); setSaveError("");
  };
  const addGroup = (kind: ServiceGroupKind) => {
    if (!selected) return;
    patchService({ groups: [...selected.groups, newServiceGroup(kind, newServiceID(), selected.groups.filter(group => group.kind === kind).length + 1)] });
  };
  const removeService = async () => {
    if (!selected || !(await confirmDialog({ title: `Удалить сервис «${selected.name || "Без имени"}»?`, body: "Сервис и его группы будут удалены из черновика. Изменение вступит в силу после сохранения и перезапуска NFQWS2.", confirmLabel: "Удалить", danger: true }))) return;
    setServices(current => current?.filter(service => service.id !== selected.id) ?? null);
    setSelectedID(services?.find(service => service.id !== selected.id)?.id ?? "");
  };
  const removeGroup = async (group: ServiceGroup) => {
    if (!selected) return;
    if ((serviceEntries(group.entries).length || group.strategy.trim()) && !(await confirmDialog({ title: `Удалить группу «${group.name || "Без имени"}»?`, body: "Домены или IP и стратегия группы будут удалены из черновика.", confirmLabel: "Удалить", danger: true }))) return;
    patchService({ groups: selected.groups.filter(item => item.id !== group.id) });
  };
  const reset = async () => {
    if (dirty && !(await confirmDialog({ title: "Загрузить сервисы с роутера?", body: "Несохранённые изменения всех сервисов будут заменены текущими настройками роутера.", confirmLabel: "Загрузить", danger: true }))) return;
    await load(true);
  };
  const apply = async () => {
    if (mutation.current || !canRestart) return;
    mutation.current = true; setBusy(true);
    try {
      if (await restart()) { invalidateChecks(); setNeedsRestart(false); await load(true); }
    } catch (error) { toast((error as Error).message, "err"); }
    finally { mutation.current = false; setBusy(false); }
  };
  const save = async (andRestart = false) => {
    if (services === null || loading || mutation.current || stale || !dirty) return;
    mutation.current = true; setBusy(true); setSaveError("");
    loadSequence.current++;
    try {
      const data = await api<ServiceState>("POST", endpoint, { services: servicesPayload(services), revision });
      setServices(data.services ?? []); setSavedSignature(servicesSignature(data.services ?? []));
      setRevision(data.revision); revisionRef.current = data.revision;
      setNeedsRestart(data.restart_required); setStale(false);
      invalidateChecks();
      window.dispatchEvent(new CustomEvent("nfqws2-files-changed", { detail: { source: "service-strategies" } }));
      toast("Стратегии сервисов сохранены", "ok");
      if (andRestart && canRestart && await restart()) { setNeedsRestart(false); await load(true); }
    } catch (error) {
      if (error instanceof ApiHTTPError && error.status === 409) setStale(true);
      setSaveError((error as Error).message);
      toast((error as Error).message, "err");
    } finally { mutation.current = false; setBusy(false); setLoading(false); }
  };
  const check = async () => {
    if (checking || !selected || !domains.length || domains.length > 64) return;
    const request = ++checkSequence.current;
    const source = selectedSource;
    const serviceID = selected.id;
    setChecking(true); setCheckError("");
    try {
      const data = await api<{ results: DomainCheckResult[] }>("POST", `${endpoint}/check`, { domains }, { readOnly: true, timeoutMs: 180000 });
      if (request === checkSequence.current) setChecks({ source, serviceID, results: data.results ?? [] });
    } catch (error) { if (request === checkSequence.current) setCheckError((error as Error).message); }
    finally { if (request === checkSequence.current) setChecking(false); }
  };

  if (services === null) return <Card title="Стратегии сервисов"><p className="text-sm text-muted" role="status">{loadError || "Загрузка сервисов…"}</p>{loadError && <Button className="mt-3" onClick={() => void load()} disabled={loading}>Повторить</Button>}</Card>;

  return <>
    <Card title="Стратегии сервисов" sub="отдельные правила для сайтов, игр и приложений" head={<Button variant="primary" onClick={addService} disabled={busy || loading}>Создать сервис</Button>}>
      <p className="text-sm leading-6 text-muted">Объедините домены и IP-зоны сервиса в группы и задайте каждой свою стратегию. Включённые группы создают профили с <code className="font-mono text-xs">--new</code>. Выключенный сервис использует глобальные стратегии NFQWS2.</p>
      <p className="mt-2 text-xs text-muted">TCP- и UDP-порты определяются из фильтров стратегии автоматически. Пересекающиеся доменные зоны или IP-сети включённых групп нужно разделить; проверка покажет конфликт.</p>
      {(stale || loadError || saveError) && <div className="mt-3 space-y-2 rounded-md border border-warn/30 bg-warn-bg p-3 text-sm text-warn" role="alert">
        {stale && <p>Настройки на роутере изменились. Черновик сохранён на экране; загрузите актуальные сервисы перед следующей записью.</p>}
        {loadError && <p>{loadError}</p>}{saveError && <p>{saveError}</p>}
      </div>}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Button variant="primary" disabled={busy || loading || !dirty || stale} onClick={() => void save()}>{busy ? "Выполняется…" : "Сохранить"}</Button>
        <Button disabled={busy || loading || !dirty || stale || !canRestart} onClick={() => void save(true)}>Сохранить и перезапустить</Button>
        {needsRestart && !dirty && <Button variant="primary" disabled={busy || loading || !canRestart} onClick={() => void apply()}>Перезапуск службы</Button>}
        <Button variant="ghost" disabled={busy || loading} onClick={() => void reset()}>Загрузить с роутера</Button>
        <span className="text-xs text-muted">{dirty ? "Есть несохранённые изменения" : needsRestart ? "Сохранено · нужен перезапуск" : "Сохранено"}</span>
      </div>
      <p className="mt-2 text-xs text-muted">Сохранение готовит настройки; перезапуск применяет стратегии и порты ко всем сервисам.</p>
      {!canRestart && <p className="mt-2 text-xs text-muted">Для применения сохранённых правок включите службу NFQWS2 и дождитесь подтверждения её состояния.</p>}
    </Card>

    <div className="grid min-w-0 gap-4 lg:grid-cols-[15rem_minmax(0,1fr)]">
      <Card title="Сервисы" sub={`${services.length}`} className="self-start">
        {services.length === 0 ? <div className="space-y-3"><p className="text-sm text-muted">Создайте первый сервис, например FacePunch, и добавьте его домены или IP-сети.</p><Button onClick={addService} disabled={editingDisabled}>Создать сервис</Button></div> : <div className="space-y-1" aria-label="Выбор сервиса">{services.map((service, index) => <button key={service.id} type="button" onClick={() => setSelectedID(service.id)} aria-pressed={selectedID === service.id} className={cn("flex w-full items-start gap-2 rounded-md border px-3 py-2 text-left outline-none transition focus-visible:ring-2 focus-visible:ring-ring", selectedID === service.id ? "border-primary/40 bg-primary/10" : "border-transparent hover:bg-line-soft")}>
          <span className="mt-0.5 text-xs text-muted">{index + 1}.</span><span className="min-w-0 flex-1"><span className="block break-words font-medium">{service.name.trim() || "Без имени"}</span><span className="mt-0.5 block text-xs text-muted">{service.enabled ? "Своя стратегия" : "Глобальная стратегия"} · групп: {service.groups.length}</span></span><span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", service.enabled ? "bg-ok" : "bg-track")} aria-hidden="true" />
        </button>)}</div>}
      </Card>

      <div className="min-w-0">
        {selected && <>
          <Card title={selected.name.trim() || "Новый сервис"} head={<Badge kind={selected.enabled ? "ok" : "neutral"}>{selected.enabled ? "Своя стратегия" : "Глобальная стратегия"}</Badge>}>
            <div className="grid items-end gap-4 sm:grid-cols-[minmax(0,1fr)_auto]"><Field label="Имя сервиса"><Input value={selected.name} maxLength={100} disabled={editingDisabled} placeholder="FacePunch" onChange={event => patchService({ name: event.target.value })} /></Field><div className="pb-1"><Switch checked={selected.enabled} disabled={editingDisabled} onChange={enabled => patchService({ enabled })} label="Включить стратегию" /></div></div>
            <p className="mt-3 text-xs text-muted">{selected.enabled ? "После сохранения и перезапуска к зонам этого сервиса применятся стратегии его групп." : "Собственные профили этого сервиса отключены. Трафик обрабатывают глобальные стратегии; группы можно подготовить заранее."}</p>
            <div className="mt-4 flex flex-wrap gap-2"><Button mini disabled={editingDisabled || selectedIndex <= 0} onClick={() => setServices(moveItem(services, selectedIndex, -1))} title="Поднять приоритет сервиса">Выше</Button><Button mini disabled={editingDisabled || selectedIndex >= services.length - 1} onClick={() => setServices(moveItem(services, selectedIndex, 1))} title="Опустить приоритет сервиса">Ниже</Button><Button mini variant="danger" disabled={editingDisabled} onClick={() => void removeService()}>Удалить сервис</Button></div>
          </Card>

          {selected.groups.map((group, index) => <Card key={group.id} title={group.kind === "domains" ? "Доменные зоны" : "IP-зоны"} sub={`группа ${index + 1}`} head={<div className="flex gap-1"><Button mini disabled={editingDisabled || index === 0} onClick={() => patchService({ groups: moveItem(selected.groups, index, -1) })} aria-label={`Поднять группу ${group.name}`}>↑</Button><Button mini disabled={editingDisabled || index === selected.groups.length - 1} onClick={() => patchService({ groups: moveItem(selected.groups, index, 1) })} aria-label={`Опустить группу ${group.name}`}>↓</Button><Button mini variant="danger" disabled={editingDisabled} onClick={() => void removeGroup(group)}>Удалить</Button></div>}>
            <Field label="Имя группы"><Input value={group.name} maxLength={100} disabled={editingDisabled} onChange={event => patchGroup(group.id, { name: event.target.value })} placeholder={group.kind === "domains" ? "Основные домены" : "Игровые серверы"} /></Field>
            <Field className="mt-3" label={group.kind === "domains" ? "Домены" : "IP-адреса и сети"} hint="По одному на строку"><Textarea value={group.entries.join("\n")} rows={4} disabled={editingDisabled} spellCheck={false} placeholder={group.kind === "domains" ? "facepunch.com\nexample.com" : "192.0.2.0/24\n2001:db8::/32"} onChange={event => patchGroup(group.id, { entries: event.target.value.split("\n") })} /></Field>
            <p className="mt-1.5 text-xs text-muted">{group.kind === "domains" ? "Доменная зона включает её поддомены. Пустые строки и строки с # пропускаются." : "Поддерживаются отдельные IPv4/IPv6-адреса и сети в формате CIDR. Пустые строки и строки с # пропускаются."}</p>
            <p className="mb-2 mt-4 text-sm font-medium">Стратегия группы</p>
            <CodeEditor value={group.strategy} onChange={strategy => patchGroup(group.id, { strategy })} kind="strategy" checkPaths={false} minHeight={110} readOnly={editingDisabled} label={`Стратегия группы ${group.name || index + 1}`} onSave={() => void save()} />
            <p className="mt-2 text-xs leading-5 text-muted">Укажите <code>--filter-tcp=443</code> или <code>--filter-udp=27015-27050</code> и параметры обхода. Несколько профилей разделяйте <code>--new</code>; список зон подключается автоматически.</p>
          </Card>)}
          <div className="mb-4 flex flex-wrap gap-2"><Button disabled={editingDisabled} onClick={() => addGroup("domains")}>Добавить группу доменов</Button><Button disabled={editingDisabled} onClick={() => addGroup("ips")}>Добавить группу IP</Button></div>

          <Card title="Проверка доменов" sub="HTTPS с роутера" head={<Button disabled={checking || editingDisabled || !domains.length || domains.length > 64} onClick={() => void check()}>{checking ? "Проверяем…" : `Проверить домены (${domains.length})`}</Button>}>
            <p className="text-xs leading-5 text-muted">Проверяются домены выбранного сервиса, включая несохранённый список. Запросы используют текущую работающую конфигурацию NFQWS2. Чтобы проверить новую стратегию, сначала сохраните её и перезапустите движок. Проверка HTTPS не проверяет игровые UDP-порты.</p>
            {domains.length > 64 && <p className="mt-3 text-xs text-warn">За одну проверку поддерживается до 64 доменов; в этом сервисе {domains.length}. Сократите список для проверки.</p>}
            {checkError && <p className="mt-3 text-sm text-bad" role="alert">{checkError}</p>}
            {checksStale && <p className="mt-3 text-xs text-warn">Настройки сервиса изменились после проверки. Повторите проверку после применения стратегии.</p>}
            {currentChecks && <div className="mt-3 divide-y divide-line" aria-live="polite">{currentChecks.results.map(result => <div key={result.domain} className="flex flex-wrap items-center gap-2 py-2"><span className="min-w-0 flex-1 break-all font-mono text-xs">{result.domain}</span><Badge kind={result.ok ? "ok" : "bad"}>{result.ok ? "Доступен" : "Ошибка"}</Badge><span className="text-xs text-muted">{result.ms} мс</span><p className="w-full break-words text-xs text-muted">{result.detail}</p></div>)}</div>}
            {!domains.length && <p className="mt-3 text-xs text-muted">Добавьте домены в группу, чтобы проверить доступность.</p>}
          </Card>
        </>}
      </div>
    </div>

    <Card title="Параметры всех сервисов" sub="предпросмотр текущего черновика">
      {previewing && <p className="text-xs text-muted" role="status">Определяем профили и порты…</p>}
      {previewError && <p className="text-sm text-bad" role="alert">{previewError}</p>}
      {preview && <>
        <div className="flex flex-wrap items-start gap-2"><Badge kind="neutral">Профилей: {preview.profiles}</Badge><span className="min-w-0 rounded-md bg-secondary px-2 py-0.5 font-mono text-xs text-secondary-foreground [overflow-wrap:anywhere]">TCP: {preview.tcp_ports || "—"}</span><span className="min-w-0 rounded-md bg-secondary px-2 py-0.5 font-mono text-xs text-secondary-foreground [overflow-wrap:anywhere]">UDP: {preview.udp_ports || "—"}</span></div>
        <p className="mt-2 text-xs text-muted">Порты включённых сервисов добавляются к глобальным портам NFQWS2 автоматически. Выключенные сервисы не добавляют профили или порты.</p>
        {!!preview.warnings?.length && <ul className="mt-3 list-inside list-disc space-y-1 text-xs text-warn">{preview.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul>}
        {preview.args && <details className="mt-3"><summary className="cursor-pointer text-xs text-ink-soft">Сформированные профили NFQWS2</summary><pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md bg-input p-3 font-mono text-xs">{preview.args}</pre></details>}
      </>}
    </Card>
  </>;
}

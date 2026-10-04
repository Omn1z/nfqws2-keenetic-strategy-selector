import { useRef, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { navigate } from "@/lib/router";
import { toast } from "@/components/ui/Toast";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field, Input, Select } from "@/components/ui/form";
import { Switch } from "@/components/ui/Switch";
import { UpstreamPool, collectUpstream, upstreamForm, type UpstreamForm } from "./UpstreamPool";
import { DnsDiagnostics } from "./DnsDiagnostics";
import { DnsStatistics } from "./DnsStatistics";
import { DnsLastRequest, DnsTestAnswer } from "./DnsAnswerPresentation";
import { DnsSettingsExportButton, DnsSettingsExportNote } from "./DnsSettingsExport";
import { DnsSettingsImport } from "./DnsSettingsImport";
import { OpenWrtDns } from "./OpenWrtDns";
import { Blocking, blockingForm, collectBlocking, type BlockingForm } from "./Blocking";
import { DomainGroups } from "./DomainGroups";
import { collectRuleGroups, groupRules, type RuleGroupForm } from "./ruleGroups";
import { ShadowDns } from "./ShadowDns";
import { collectShadow, dnsRouteLabel, shadowForm, type ShadowForm } from "./shadowDnsForm";
import type { DnsServerConfig, DnsServerStatus, DnsServerTestResult } from "@/types/api";

type RouteMode = "auto" | "vpn_only";
type Form = Omit<DnsServerConfig, "dns_port" | "logging_enabled" | "timeout_seconds" | "cache_size" | "cache_ttl_seconds" | "default_upstream" | "default_pool" | "rules" | "route_mode" | "filtering" | "shadow_dns"> & {
  timeout_seconds: string; cache_size: string; cache_ttl_seconds: string;
  default_pool: UpstreamForm[]; groups: RuleGroupForm[]; route_mode: RouteMode; filtering: BlockingForm;
  shadow_dns: ShadowForm;
};
const toForm = (c: DnsServerConfig): Form => ({
  enabled: c.enabled, listen_host: c.listen_host,
  route_mode: c.route_mode === "vpn_only" ? "vpn_only" : "auto",
  awg_fallback: c.route_mode === "vpn_only" && c.awg_fallback === "off" ? "auto" : c.awg_fallback,
  fast_dns: c.fast_dns ?? true,
  scheduler_enabled: c.scheduler_enabled ?? true,
  timeout_seconds: String(c.timeout_seconds), cache_size: String(c.cache_size),
  cache_ttl_seconds: String(c.cache_ttl_seconds ?? 3600),
  default_pool: [c.default_upstream, ...(c.default_pool ?? [])].map(upstreamForm),
  groups: groupRules(c.rules ?? []),
  filtering: blockingForm(c.filtering),
  shadow_dns: shadowForm(c.shadow_dns),
});
const integer = (value: string, name: string, min: number, max: number) => {
  if (!/^\d+$/.test(value) || Number(value) < min || Number(value) > max) throw new Error(`${name}: укажите целое число от ${min} до ${max}`);
  return Number(value);
};
const timeLabel = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString("ru-RU", { hour12: false });
};
const collect = (f: Form): Omit<DnsServerConfig, "dns_port" | "logging_enabled"> => {
  const { groups, filtering, shadow_dns, ...config } = f;
  return {
    ...config, listen_host: f.listen_host.trim() || "auto",
    awg_fallback: f.route_mode === "vpn_only" && f.awg_fallback === "off" ? "auto" : f.awg_fallback,
    timeout_seconds: integer(f.timeout_seconds, "Таймаут", 1, 10), cache_size: integer(f.cache_size, "Размер кэша", 0, 4096),
    cache_ttl_seconds: integer(f.cache_ttl_seconds, "Время хранения кэша", 1, 86400),
    default_upstream: collectUpstream(f.default_pool[0]), default_pool: f.default_pool.slice(1).map(collectUpstream),
    rules: collectRuleGroups(groups),
    filtering: collectBlocking(filtering),
    shadow_dns: collectShadow(shadow_dns),
  };
};

function Endpoint({ label, value }: { label: string; value: string }) {
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); toast("Адрес скопирован", "ok"); }
    catch { toast("Выделите и скопируйте адрес вручную", "err"); }
  };
  return (
    <div className="min-w-0 rounded-lg border border-line p-3">
      <div className="mb-2 flex items-center justify-between gap-2"><span className="text-xs font-semibold text-ink-soft">{label}</span>{value && <Button mini onClick={copy}>Копировать</Button>}</div>
      <code className="block select-all text-xs [overflow-wrap:anywhere]">{value || "Адрес пока недоступен"}</code>
    </div>
  );
}

export default function DnsServer() {
  const [live, setLive] = useState<DnsServerStatus | null>(null);
  const [form, setForm] = useState<Form | null>(null);
  const [busy, setBusy] = useState(false);
  const [openWrtBusy, setOpenWrtBusy] = useState(false);
  const [openWrtSupported, setOpenWrtSupported] = useState<boolean | null>(null);
  const [openWrtRefresh, setOpenWrtRefresh] = useState(0);
  const [clearing, setClearing] = useState(false);
  const [filterUpdating, setFilterUpdating] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [domain, setDomain] = useState("claude.ai");
  const [queryType, setQueryType] = useState<"A" | "AAAA" | "CNAME" | "HTTPS" | "SVCB">("A");
  const [testing, setTesting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [test, setTest] = useState<DnsServerTestResult | null>(null);
  const loaded = useRef(false);
  const polling = useRef(false);
  const mutation = useRef(0);
  const acting = useRef(false);

  const apply = (v: DnsServerStatus) => { setLive(v); setForm(toForm(v.config)); loaded.current = true; setLoadError(""); };
  const refresh = async () => {
    if (polling.current || acting.current) return;
    polling.current = true;
    const revision = mutation.current;
    try {
      const v = await api<DnsServerStatus>("GET", "/api/dnsserver");
      if (revision !== mutation.current) return;
      setLive(v); setLoadError("");
      if (!loaded.current) { setForm(toForm(v.config)); loaded.current = true; }
    } catch (e) { if (revision === mutation.current) setLoadError((e as Error).message); }
    finally { polling.current = false; }
  };
  usePoll(refresh, 3000);

  const action = async (path: string, body: unknown, message: string) => {
    if (acting.current) return;
    acting.current = true; mutation.current++; setBusy(true);
    try { apply(await api<DnsServerStatus>("POST", `/api/dnsserver/${path}`, body)); setTest(null); toast(message, "ok"); return true; }
    catch (e) { toast((e as Error).message, "err"); return false; }
    finally { acting.current = false; setBusy(false); setOpenWrtRefresh((value) => value + 1); }
  };
  const save = async () => {
    if (!form) return;
    try { await action("config", collect(form), "Настройки DNS сохранены"); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const clearCache = async () => {
    if (acting.current) return;
    acting.current = true;
    const revision = ++mutation.current;
    setBusy(true); setClearing(true);
    try {
      const v = await api<DnsServerStatus>("POST", "/api/dnsserver/cache/clear", {});
      // An older poll cannot restore cleared cache data; unsaved form fields stay intact.
      if (revision === mutation.current) { setLive(v); setLoadError(""); }
      toast("Кэш DNS очищен", "ok");
    } catch (e) { toast((e as Error).message, "err"); }
    finally { acting.current = false; setBusy(false); setClearing(false); }
  };
  const updateFiltering = async () => {
    if (acting.current) return;
    acting.current = true;
    const revision = ++mutation.current;
    setFilterUpdating(true);
    try {
      const v = await api<DnsServerStatus>("POST", "/api/dnsserver/filtering/update", {});
      // Refresh live status only: the user may have unsaved changes in the form.
      if (revision === mutation.current) { setLive(v); setLoadError(""); }
      toast("Обновление списков запущено", "ok");
    } catch (e) { toast((e as Error).message, "err"); }
    finally { acting.current = false; setFilterUpdating(false); }
  };
  const set = <K extends keyof Form>(key: K, value: Form[K]) => setForm((f) => f ? { ...f, [key]: value } : f);
  const setRouteMode = (mode: RouteMode) => setForm((f) => f ? {
    ...f, route_mode: mode, awg_fallback: mode === "vpn_only" && f.awg_fallback === "off" ? "auto" : f.awg_fallback,
  } : f);
  const lookup = async () => {
    if (acting.current) return;
    setTesting(true); setTest(null);
    try { setTest(await api<DnsServerTestResult>("POST", "/api/dnsserver/test", { domain: domain.trim(), type: queryType })); }
    catch (e) { toast((e as Error).message, "err"); }
    finally { setTesting(false); }
  };

  if (!live || !form) return <Card title="DNS Server"><p className="text-xs text-muted">{loadError || "Загрузка…"}</p>{loadError && <Button className="mt-3" onClick={refresh}>Повторить</Button>}</Card>;

  const dirty = JSON.stringify(form) !== JSON.stringify(toForm(live.config));
  const tunnels = (live.routes ?? []).filter((r) => r.id.startsWith("awg:"));
  const selectedTunnelExists = tunnels.some((r) => r.id.slice(4) === form.awg_fallback);
  const selectedTunnelAvailable = form.awg_fallback === "auto"
    ? tunnels.some((r) => r.available)
    : tunnels.some((r) => r.id.slice(4) === form.awg_fallback && r.available);
  const routeName = (id?: string) => dnsRouteLabel(id, live.routes);

  return (
    <>
      <Card title="DNS Server" sub="локальный DNS с группами доменов" head={<div className="flex flex-wrap items-center gap-2"><Button mini disabled={busy || testing || filterUpdating} onClick={() => setImporting(true)}>Импорт настроек</Button><DnsSettingsExportButton disabled={busy || testing || filterUpdating} /><Badge kind={live.running ? "ok" : live.config.enabled ? "bad" : "neutral"}>{live.running ? "работает" : live.config.enabled ? "ошибка запуска" : "выключен"}</Badge></div>}>
        <p className="mb-3 text-xs text-muted">Устройства отправляют обычные DNS-запросы на роутер по UDP или TCP. Выберите специальный DoH или пул серверов и назначьте ему группу доменов. Сервис по умолчанию выключен.</p>
        <div className="flex flex-wrap items-center gap-4">
          <Switch checked={live.config.enabled} disabled={busy || dirty || testing} onChange={(on) => action(on ? "start" : "stop", {}, on ? "DNS-сервер включён" : "DNS-сервер выключен")} label="DNS-сервер включён" />
          {dirty && <><Button mini variant="primary" disabled={busy || testing} onClick={save}>Сохранить изменения</Button><Button mini disabled={busy || testing} onClick={() => setForm(toForm(live.config))}>Отменить</Button></>}
          {!dirty && live.running && <span className="text-xs text-muted">Адрес в локальной сети: {live.listen_host}</span>}
        </div>
        <DnsSettingsExportNote dirty={dirty} />
        {live.last_error && <p role="alert" className="mt-3 text-xs text-bad [overflow-wrap:anywhere]">{live.last_error}</p>}
        {loadError && <p role="alert" className="mt-3 text-xs text-warn">Не удалось обновить состояние: {loadError}</p>}
      </Card>

      <Card title="Статистика" sub="с запуска DNS-сервера" head={<Button mini disabled={busy || testing || !live.cache.entries} onClick={clearCache}>{clearing ? "Очистка…" : "Очистить кэш"}</Button>}>
        <DnsStatistics stats={live.stats} cache={live.cache} />
        <p className="mt-3 text-xs text-muted">Очистка кэша сохраняет статистику и настройки. Новые запросы снова заполняют кэш.</p>
        <DnsLastRequest stats={live.stats} routeName={routeName} />
        {live.stats.last_error && <p className="mt-2 text-xs text-bad [overflow-wrap:anywhere]">Последняя ошибка: {live.stats.last_error}</p>}
      </Card>

      <Card title="Подключение роутера и устройств" sub="адрес из сохранённых настроек" head={<Button mini disabled={busy} onClick={() => navigate("system")}>Настроить порты</Button>}>
        <Endpoint label="Обычный DNS · UDP и TCP, без TLS" value={live.endpoints.dns} />
        <p className="mt-3 text-xs text-warn">Этот адрес принимает обычный DNS. Не добавляйте его в список DoT/DoH: там ожидается TLS или HTTPS, а локальный порт обслуживает DNS по UDP/TCP.</p>
        {openWrtSupported === false && <><p className="mt-2 text-xs text-muted">Чтобы встроенный DNS Keenetic на порту 53 пересылал запросы сюда, откройте штатную CLI KeeneticOS (не оболочку Entware root) и выполните:</p>
        {live.endpoints.dns && <pre className="mt-2 overflow-x-auto rounded-lg border border-line bg-panel-soft p-3 font-mono text-xs">{`ip name-server ${live.endpoints.dns}\nsystem configuration save\nshow ip name-server`}</pre>}
        <p className="mt-2 text-xs text-warn">Keenetic может одновременно использовать другие DNS: от провайдера, добавленные вручную, DoT/DoH и профили интернет-фильтрации. Для исключительного использования этого сервиса проверьте и отключите конкурирующие источники в настройках Keenetic вручную.</p></>}
        <p className="mt-2 text-xs text-muted">Устройства, которым можно задать порт DNS, могут обращаться напрямую к адресу выше. Устройства с полем только для IP используют порт 53 — оставьте им IP роутера. Пока сервис выключен, порт выше не отвечает.</p>
      </Card>

      <OpenWrtDns dirty={dirty} running={live.running} busy={busy || testing || filterUpdating || importing} endpoint={live.endpoints.dns}
        configurationKey={JSON.stringify([live.config, live.listen_host, live.running, live.endpoints.dns, openWrtRefresh])}
        onSupportedChange={setOpenWrtSupported} onBusyChange={(pending) => {
          if (pending) {
            if (acting.current) return false;
            acting.current = true; mutation.current++;
          } else acting.current = false;
          setOpenWrtBusy(pending); setBusy(pending);
          return true;
        }} />

      <fieldset disabled={busy || testing} inert={openWrtBusy} className="min-w-0">
        <ShadowDns value={form.shadow_dns} status={live.shadow_dns} onChange={(value) => set("shadow_dns", value)} busy={busy || testing || filterUpdating || importing}
          onDiagnosticsStatus={(value) => { setLive(value); setLoadError(""); }}
          onRefresh={refresh} onRenewResult={(result) => {
            // A successful renewal supersedes the previous cached failure
            // immediately, even while an older status poll is still finishing.
            if (result.status === "resolved") setLive((current) => current?.shadow_dns ? { ...current, shadow_dns: { ...current.shadow_dns, servers: result.servers ?? [], error: undefined } } : current);
          }} onRenewBusyChange={(pending) => {
            if (pending) {
              if (acting.current) return false;
              acting.current = true; mutation.current++;
            } else acting.current = false;
            setBusy(pending);
            return true;
          }} />

        <Card title="Пул DoH по умолчанию" sub="для доменов вне Shadow DNS и специальных групп">
          <p className="mb-3 text-xs text-muted">Серверы пула участвуют в параллельных запросах через доступные маршруты. Первый корректный ответ возвращается устройству.</p>
          <UpstreamPool value={form.default_pool} onChange={(v) => set("default_pool", v)} />
          <p className="mt-2 text-xs text-muted">IP для подключения помогает, когда провайдер блокирует разрешение имени самого DNS-сервера. Имя и проверка сертификата берутся из HTTPS-адреса.</p>
        </Card>

        <DomainGroups value={form.groups} onChange={(groups) => set("groups", groups)} disabled={busy || testing} />

        <Blocking value={form.filtering} onChange={(filtering) => set("filtering", filtering)} status={live.filtering} savedEnabled={live.config.filtering?.enabled ?? false} running={live.running} disabled={busy || testing} updateBusy={filterUpdating} unsaved={dirty} onUpdate={updateFiltering} />

        <Card title="Ускорение и обход блокировок DNS">
          <p className="mb-3 text-xs text-muted">Если ответа нет в кэше, DoH из подходящего пула запрашиваются через маршруты выбранного режима. Попытки запускаются параллельно; первый корректный ответ возвращается сразу, остальные отменяются.</p>
          <div className="mb-3 rounded-lg border border-line p-3">
            <Switch checked={form.scheduler_enabled ?? true} onChange={(enabled) => set("scheduler_enabled", enabled)} label="Планировщик DNS" />
            <p className="mt-2 text-xs text-muted">Ставит быстрые и надёжные сочетания «маршрут + DoH» первыми и измеряет альтернативы в фоне. При единственном доступном сочетании фоновые замеры не нужны и автоматически пропускаются. После выключения запросы идут в порядке настройки пула, без обучения и фоновых замеров; кэш и fast-dns продолжают работать. Выбор применяется кнопкой «Сохранить настройки».</p>
          </div>
          <div className="mb-3 rounded-lg border border-line p-3">
            <Switch checked={form.fast_dns} onChange={(enabled) => set("fast_dns", enabled)} label="fast-dns" />
            <p className="mt-2 text-xs text-muted">Кэширует IP-адреса DoH-серверов и обновляет их в фоне каждый час. Указанные вручную IP имеют приоритет. Этот кэш не зависит от кэша DNS-ответов и его времени хранения.</p>
            {live.running && (live.config.fast_dns ?? true) && live.fast_dns?.enabled && <>
              <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
                <span>По сохранённым настройкам</span>
                <span title={`Пары DoH × маршрут${live.fast_dns.last_refresh_at ? `. Последнее успешное обновление: ${timeLabel(live.fast_dns.last_refresh_at)}` : ""}`}>Готовых записей: {live.fast_dns.ready} / {live.fast_dns.entries}</span>
                {live.fast_dns.refreshing > 0 ? <span className="text-accent" title="Записи в очереди и на обновлении">Обновление: {live.fast_dns.refreshing}</span> : live.fast_dns.next_refresh_at ? <span>Обновление после {timeLabel(live.fast_dns.next_refresh_at)}</span> : null}
              </div>
              {live.fast_dns.last_error && <p className="mt-1 text-xs text-warn [overflow-wrap:anywhere]">Обновление IP: {live.fast_dns.last_error}</p>}
            </>}
          </div>
          <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_180px]">
            <Field label="Маршруты исходящих DNS-запросов"><Select value={form.route_mode} onChange={(e) => setRouteMode(e.target.value as RouteMode)}>
              <option value="auto">NFQWS и VPN</option>
              <option value="vpn_only">Только VPN (AWG/WARP)</option>
            </Select></Field>
            <Field label="VPN-подключение для DNS"><Select value={form.awg_fallback} onChange={(e) => set("awg_fallback", e.target.value)}>
              <option value="auto">Авто — все доступные AWG, включая WARP</option>
              {form.route_mode !== "vpn_only" && <option value="off">Выключено — только NFQWS</option>}
              {!selectedTunnelExists && !["auto", "off"].includes(form.awg_fallback) && <option value={form.awg_fallback}>Сохранённое подключение недоступно</option>}
              {tunnels.map((r) => <option key={r.id} value={r.id.slice(4)}>{r.name}{r.available ? " — доступен" : " — недоступен"}</option>)}
            </Select></Field>
            <Field label="Таймаут маршрута, сек."><Input type="number" min={1} max={10} value={form.timeout_seconds} onChange={(e) => set("timeout_seconds", e.target.value)} /></Field>
          </div>
          {form.route_mode === "vpn_only" && <p className="mt-2 text-xs text-warn">Режим «Только VPN» не отправляет новые запросы к DoH через NFQWS или напрямую. Если выбранный AWG/WARP недоступен, запросы без ответа в кэше завершатся ошибкой DNS до восстановления туннеля. Включённый Shadow DNS — отдельное исключение: его домены идут к DNS провайдера.</p>}
          <div className="mt-3 flex flex-wrap gap-2">{live.routes?.map((r) => {
            const dnsDisabled = r.id === "nfqws" && !live.config.enabled;
            const excluded = r.id === "nfqws" && live.config.route_mode === "vpn_only";
            return <span key={r.id} title={dnsDisabled ? "Маршрут запускается при включении DNS-сервера" : excluded ? "Исключён режимом «Только VPN»" : r.error || r.interface}><Badge kind={dnsDisabled || excluded ? "neutral" : r.available ? "ok" : "warn"}>{r.name}: {dnsDisabled ? "DNS-сервер выключен" : excluded ? "исключён режимом" : r.available ? "доступен" : "недоступен"}</Badge></span>;
          })}</div>
          {form.awg_fallback !== "off" && !selectedTunnelAvailable && <p className="mt-2 text-xs text-warn">Выбранное VPN-подключение сейчас недоступно. {form.route_mode === "vpn_only" ? "Новые DoH-запросы без кэша будут завершаться ошибкой." : "VPN сможет участвовать в запросах после подключения."}</p>}
          <p className="mt-2 text-xs text-muted">Таймаут ограничивает каждый маршрут отдельно: быстрый ответ не ждёт медленных маршрутов. NFQWS доступен только в режиме «NFQWS и VPN» и обрабатывает DoH на порту 443; для другого HTTPS-порта используются выбранные AWG-подключения.</p>
        </Card>

        <Card title="Параметры сервера">
          <div className="grid gap-3 md:grid-cols-3">
            <Field label="Локальный IP для прослушивания" hint="auto = адрес LAN"><Input value={form.listen_host} placeholder="auto" onChange={(e) => set("listen_host", e.target.value)} autoCapitalize="none" spellCheck={false} /></Field>
            <Field label="Размер кэша, записей"><Input type="number" min={0} max={4096} value={form.cache_size} onChange={(e) => set("cache_size", e.target.value)} /></Field>
            <Field label="Время хранения кэша, сек."><Input type="number" min={1} max={86400} value={form.cache_ttl_seconds} onChange={(e) => set("cache_ttl_seconds", e.target.value)} /></Field>
          </div>
          <p className="mt-2 text-xs text-muted">Размер кэша 0 отключает кэш. Порт DNS-сервера меняется в разделе «Система».</p>
          <p className="mt-2 text-xs text-muted">Время хранения — верхний предел от 1 до 86400 секунд. Если TTL ответа DNS-провайдера истекает раньше, запись удаляется раньше.</p>
          <p className="mt-1 text-xs text-muted">A, AAAA и HTTPS хранятся как отдельные записи. Параметры DNS-запроса также могут различать записи кэша, даже для одного домена.</p>
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Button variant="primary" disabled={busy || testing || !dirty} onClick={save}>{busy && !clearing ? "Сохранение…" : "Сохранить настройки"}</Button>
            {dirty && <Button disabled={busy || testing} onClick={() => setForm(toForm(live.config))}>Отменить изменения</Button>}
            <span className="text-xs text-muted">{dirty ? "Есть несохранённые изменения." : "Все настройки сохранены."} {live.running ? "Сохранение перезапустит DNS-сервер." : "Сохранение не включает сервис."}</span>
          </div>
        </Card>
      </fieldset>

      <div inert={openWrtBusy}><DnsDiagnostics loggingEnabled={live.config.logging_enabled} running={live.running} routes={live.routes} onLoggingChange={(enabled) => { mutation.current++; setLive((v) => v ? { ...v, config: { ...v.config, logging_enabled: enabled } } : v); }} /></div>

      {importing && <DnsSettingsImport dirty={dirty} saving={busy} onClose={() => setImporting(false)} onImport={async (request) => (await action("import", request, "Настройки DNS импортированы")) ?? false} />}

      <Card title="Проверка DNS" sub="использует сохранённые настройки">
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Домен" className="min-w-[180px] flex-1"><Input value={domain} disabled={testing} onChange={(e) => setDomain(e.target.value)} placeholder="claude.ai" autoCapitalize="none" spellCheck={false} /></Field>
          <Field label="Тип записи" className="w-36"><Select value={queryType} disabled={testing} onChange={(e) => setQueryType(e.target.value as typeof queryType)}><option value="A">A · IPv4</option><option value="AAAA">AAAA · IPv6</option><option value="CNAME">CNAME · псевдоним</option><option value="HTTPS">HTTPS</option><option value="SVCB">SVCB</option></Select></Field>
          <Button disabled={busy || testing || dirty || !live.running || !domain.trim()} onClick={lookup}>{testing ? "Проверка…" : "Проверить"}</Button>
        </div>
        {!live.running && <p className="mt-2 text-xs text-muted">Для проверки включите DNS-сервер.</p>}
        {dirty && <p className="mt-2 text-xs text-muted">Для проверки сначала сохраните изменения.</p>}
        {test && <DnsTestAnswer result={test} routeName={routeName} />}
      </Card>

    </>
  );
}

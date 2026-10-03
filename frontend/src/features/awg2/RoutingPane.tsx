import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { Field, Select } from "@/components/ui/form";
import type { Awg2Status, AwgRoutingConfig, AwgRulesImportResult, AwgZone } from "@/types/api";
import RulesTable from "./RulesTable";
import type { ImportRoutingRules, RoutingReadTask } from "./RulesTransferModal";
import { prepareRuleConnection } from "./routingRules";


// One combined list per rule: domains/masks AND IPv4/IPv6/CIDR in the same box.
// During editing everything lives in z.domains; on save we split IP/CIDR lines into
// z.ips and keep the rest in z.domains (the backend routes ips via ipset and
// domains/masks via the DNS proxy).
const zoneLines = (z: AwgZone) => [...(z.domains || []), ...(z.ips || [])];
const cleanArr = (a: string[]) => (a || []).map((x) => x.trim()).filter(Boolean);
const isIPish = (s: string) =>
  /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(s) || // IPv4 / CIDR
  (s.includes(":") && /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(s)); // IPv6 / CIDR
const cleanRouting = (rc: AwgRoutingConfig, tunnelIDs: ReadonlySet<string>): AwgRoutingConfig => ({
  ...rc,
  zones: (rc.zones || []).map((z) => {
    const all = cleanArr(zoneLines(z));
    return { ...prepareRuleConnection(z, tunnelIDs), domains: all.filter((x) => !isIPish(x)), ips: all.filter(isIPish) };
  }),
});
const routingFromStatus = (st: Awg2Status): AwgRoutingConfig => {
  const routing = st.routing_config ?? st.config.routing;
  return { ...routing, mode: routing?.mode || "zones", zones: st.routing_config?.zones ?? st.routing_rules ?? st.config.routing?.zones ?? [] };
};

export default function RoutingPane({ st, reload, visible, onBusyChange, externalBusy, acceptRouting }: { st: Awg2Status; reload: () => Promise<void>; visible: boolean; onBusyChange: (busy: boolean) => void; externalBusy: boolean; acceptRouting: (routing: AwgRoutingConfig) => void }) {
  const [r, setRState] = useState<AwgRoutingConfig>(() => routingFromStatus(st));
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState("");
  const saveInFlight = useRef(false);
  const routingKey = JSON.stringify(routingFromStatus(st));
  const observedRoutingKey = useRef(routingKey);
  const pendingRouting = useRef<AwgRoutingConfig | null>(null);
  const blocked = busy || externalBusy;
  const tunnelIDs = new Set(st.servers.map((server) => server.id));
  // Polls often change handshake counters without changing configuration.
  // Only a genuinely new routing snapshot can replace a clean local form.
  useEffect(() => {
    if (routingKey !== observedRoutingKey.current) {
      observedRoutingKey.current = routingKey;
      pendingRouting.current = routingFromStatus(st);
    }
    if (dirty || busy || !pendingRouting.current) return;
    setRState(pendingRouting.current);
    pendingRouting.current = null;
  }, [routingKey, dirty, busy, st]);
  const setR = (next: AwgRoutingConfig | ((prev: AwgRoutingConfig) => AwgRoutingConfig)) => {
    setDirty(true);
    setRState(next);
  };
  const markSaved = (next: AwgRoutingConfig) => {
    setRState(next);
    setDirty(false);
  };
  const runRead: RoutingReadTask = async (work) => {
    if (saveInFlight.current || externalBusy) throw new Error("Дождитесь завершения текущей настройки.");
    saveInFlight.current = true;
    setBusy(true);
    onBusyChange(true);
    try { return await work(); }
    finally { saveInFlight.current = false; setBusy(false); onBusyChange(false); }
  };
  const importRules: ImportRoutingRules = async (request) => {
    if (saveInFlight.current || externalBusy) return false;
    saveInFlight.current = true;
    setBusy(true);
    onBusyChange(true);
    setSaveError("");
    try {
      const result = await api<AwgRulesImportResult>("POST", "/api/awg2/routing/rules/import", request);
      // Import is atomic: preserve the visible draft until the backend confirms
      // success, then accept its canonical result before a fallible status read.
      pendingRouting.current = null;
      acceptRouting(result.routing);
      markSaved(result.routing);
      toast(`Импорт завершён · всего правил: ${result.rule_count}${result.waiting_rule_count ? ` · ожидают подключения: ${result.waiting_rule_count}` : ""}`, "ok");
      await reload();
      return true;
    } catch (e) {
      const message = (e as Error).message;
      setSaveError(message);
      toast(message, "err");
      // Validation or uncertain network failures cannot discard the local form.
      return false;
    } finally { saveInFlight.current = false; setBusy(false); onBusyChange(false); }
  };

  const eng = st.engine;
  // Use the backend's applied state, not the selected profile or unsaved draft.
  const active = st.routing_config?.active ?? st.config.routing?.active ?? false;

  const saveRules = async (nextRouting: AwgRoutingConfig, ok?: string): Promise<boolean> => {
    if (saveInFlight.current || externalBusy) return false;
    saveInFlight.current = true;
    setBusy(true);
    onBusyChange(true);
    setSaveError("");
    setRState(nextRouting);
    setDirty(true);
    try {
      await api("POST", "/api/awg2/routing/rules", nextRouting);
      // The acknowledged write supersedes snapshots received while editing.
      // A failed follow-up GET must not replay one of those over the saved form.
      pendingRouting.current = null;
      markSaved(nextRouting);
      if (ok) toast(ok, "ok");
      await reload();
      return true;
    } catch (e) {
      const message = (e as Error).message;
      setSaveError(message);
      toast(message, "err");
      // Keep the draft: a timeout does not prove the server rolled it back.
      return false;
    } finally {
      saveInFlight.current = false;
      setBusy(false);
      onBusyChange(false);
    }
  };

  const install = async () => {
    if (!(await confirmDialog({
      title: eng.installed ? "Обновить движок AmneziaWG?" : "Установить движок AmneziaWG?",
      body: `Установит ${eng.target_version || "актуальную сборку"} на роутер. Действующие VPN-туннели будут перезапущены с сохранением профилей.`,
      confirmLabel: eng.installed ? "Обновить" : "Установить",
    }))) return;
    if (blocked || saveInFlight.current) return;
    saveInFlight.current = true;
    setBusy(true);
    onBusyChange(true);
    try {
      const d = await api<{ ok: boolean; detail?: string; error?: string }>("POST", "/api/awg2/install", {});
      toast(d.ok ? "Движок AmneziaWG готов" : "Ошибка: " + (d.error || "?"), d.ok ? "ok" : "err");
      await reload();
    } catch (e) { toast((e as Error).message, "err"); } finally { saveInFlight.current = false; setBusy(false); onBusyChange(false); }
  };

  const applyRouting = async () => {
    if (r.mode === "off") return teardown();
    if (!(await confirmDialog({
      title: "Применить маршрутизацию?",
      body: `Режим «${r.mode}». Правила будут сохранены и применены на роутере. Локальная сеть, приватные адреса и сам сервер VPN всегда в обход туннеля.`,
      confirmLabel: "Применить",
    }))) return;
    await saveRules(cleanRouting(r, tunnelIDs), "Правила применены");
  };

  const teardown = () => {
    const nextRouting = cleanRouting({ ...r, mode: "off" }, tunnelIDs);
    void saveRules(nextRouting, "Маршрутизация снята");
  };

  return (
    <>
      {(!eng.installed || eng.update_available || !eng.awg3_supported || !eng.tun_ok) && (
      <Card title="Движок AmneziaWG" sub={eng.installed ? `Установлен: ${eng.awg_version || "версия неизвестна"}` : "нужен для запуска VPN на роутере"}>
        {!eng.supported ? (
          <p className="text-xs text-bad">Для архитектуры {eng.arch} готовой сборки движка нет.</p>
        ) : (
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="primary" onClick={install} disabled={blocked}>{busy ? "Установка…" : `${eng.installed ? "Обновить движок" : "Установить движок"}${eng.target_version ? ` · ${eng.target_version}` : ""}`}</Button>
            {!eng.tun_ok && <span className="text-xs text-warn">⚠ /dev/net/tun не найден — при установке будет попытка загрузить модуль</span>}
          </div>
        )}
        {eng.update_available && <p className="mt-2 text-xs text-muted">Обновление добавляет поддержку AWG 3.1. Существующие профили AWG 2.0, WireGuard и WARP сохраняются.</p>}
      </Card>
      )}

      <Card title="Сплит-маршрутизация" sub="локальные правила на роутере, независимо от настроек подключений">
        <div className="flex flex-wrap gap-4">
          <Field label="Режим" className="min-w-[280px] flex-1">
            <Select disabled={blocked} value={r.mode === "include" || r.mode === "exclude" ? "zones" : r.mode} onChange={(e) => setR({ ...r, mode: e.target.value })}>
              <option value="off">Выключено</option>
              <option value="zones">По зонам (Включить/Исключить на каждой зоне)</option>
              <option value="full">Весь трафик — через VPN</option>
            </Select>
          </Field>
        </div>
        <div className="mt-1 flex items-center gap-4"><Switch disabled={blocked} checked={!!r.killswitch} onChange={(v) => setR({ ...r, killswitch: v })} label="Эксклюзивный маршрут (kill-switch): если туннель недоступен — сайты из зон НЕ открываются" /></div>
        <p className="mt-0.5 text-[11px] text-muted">Включено — трафик зон идёт только через туннель; упал туннель → соединения нет (без утечки в обычный канал). Выключено — при недоступном туннеле сайты зон открываются обычным прямым соединением.</p>
        <div className="mt-1 flex items-center gap-4"><Switch disabled={blocked} checked={r.domain_source === "dnsproxy"} onChange={(v) => setR({ ...r, domain_source: v ? "dnsproxy" : "resolve" })} label="Перехват DNS и для обычных доменов (смена IP)" /></div>
        <p className="mt-0.5 text-[11px] text-muted">Маски (<b>*.com</b>, <b>*ip*</b>, <b>[re]…</b>) включают перехват DNS <b>автоматически</b>. Тумблер дополнительно обрабатывает новые IP обычных доменов; учёт их поддоменов задаётся переключателем «Учитывать все поддомены автоматически» в поле «Что матчит» редактора правила. Перехват ловит только нешифрованный DNS через роутер; DoH/DoT на устройстве его обходит — для всего трафика ставьте <b>*</b> или режим «Весь трафик». Общие CDN-IP вроде Cloudflare автоматически не кэшируются, чтобы не зацепить соседние сайты.</p>
        <div className="mt-1 flex items-center gap-4"><Switch disabled={blocked} checked={!!r.sni_routing} onChange={(v) => setR({ ...r, sni_routing: v })} label="SNI-маршрутизация (DoH; без общих CDN-IP) — дополнительный слой" /></div>
        <p className="mt-0.5 text-[11px] text-muted">Читает имя сайта прямо из TLS-рукопожатия — <b>не зависит от DNS</b> (работает при DoH/DoT). Домены из зон «Включить» заводятся в туннель по факту обращения и держатся ~1 ч. Первый коннект к новому адресу ещё уходит напрямую (по нему учимся), дальше — через VPN. Если адрес принадлежит общему CDN-edge Cloudflare, он пропускается; для такого случая нужен режим «Весь трафик» или явный IP/CIDR с пониманием, что это правило шире одного домена.</p>
        {r.domain_source === "dnsproxy" && (
          <p className="mt-1 text-[11px] text-muted">Перехватывает DNS локальной сети и заводит в туннель IP по совпадению имени. Форматы строки: <b>youtube.com</b> — домен, поддомены учитываются по переключателю правила; <b>ip*</b> — всё, что начинается на «ip» (ipinfo.io, iphone.com) — точка НЕ нужна; <b>*ip*</b> — всё, что содержит «ip» (2ip.ru, ipinfo.io); <b>server*</b>, <b>test##.com</b> (<b>#</b> — один символ); регэксп <b>[re]^.*\.cdn\.net$</b>. ⚠️ <b>ip.*</b> (с точкой) совпадает только с «ip.что-то», НЕ с ipinfo.io — для «ipinfo» пишите <b>ip*</b> или <b>*ip*</b>. Маски действуют, только пока маршрутизация активна; шифрованный DNS (DoH/DoT) на устройстве это обходит.</p>
        )}
        <div className="mt-2 flex flex-wrap items-center gap-2.5">
          {r.mode === "off" ? (
            <Button variant="primary" onClick={teardown} disabled={blocked}>Снять маршрутизацию</Button>
          ) : active ? (
            <Button variant="primary" onClick={() => { const nextRouting = cleanRouting(r, tunnelIDs); void saveRules(nextRouting, "Сохранено и применено"); }} disabled={blocked}>Сохранить и применить</Button>
          ) : (
            <>
              <Button onClick={() => { const nextRouting = cleanRouting(r, tunnelIDs); void saveRules(nextRouting, "Маршрутизация сохранена"); }} disabled={blocked}>Сохранить</Button>
              <Button variant="primary" onClick={applyRouting} disabled={blocked}>Применить</Button>
            </>
          )}
          {busy && <span className="text-xs text-muted" role="status">Обрабатываем запрос…</span>}
          {!busy && dirty && <span className="text-xs text-warn">Есть несохранённые изменения</span>}
        </div>
        {saveError && <p className="mt-2 text-xs text-bad" role="alert">Изменения не подтверждены: {saveError}</p>}
        {active
          ? <p className="mt-2 text-[11px] font-medium text-ok">● Маршрутизация активна — правки режима, зон, масок и kill-switch применяются к туннелю сразу при сохранении.</p>
          : <p className="mt-2 text-[11px] text-muted">Локальная сеть, приватные адреса и адрес сервера VPN всегда идут в обход туннеля.</p>}
      </Card>

      <Card title="Правила" sub="приоритет сверху вниз — первое совпадение определяет маршрут · применяются автоматически">
        <RulesTable r={r} saveRouting={saveRules} saving={blocked} visible={visible} st={st} reload={reload} runRead={runRead} importRules={importRules} hasDraft={dirty} />
      </Card>
    </>
  );
}

import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { Field, Select } from "@/components/ui/form";
import type { Awg2Status, AwgRoutingConfig, AwgZone } from "@/types/api";
import RulesTable from "./RulesTable";


// One combined list per rule: domains/masks AND IPv4/IPv6/CIDR in the same box.
// During editing everything lives in z.domains; on save we split IP/CIDR lines into
// z.ips and keep the rest in z.domains (the backend routes ips via ipset and
// domains/masks via the DNS proxy).
const zoneLines = (z: AwgZone) => [...(z.domains || []), ...(z.ips || [])];
const cleanArr = (a: string[]) => (a || []).map((x) => x.trim()).filter(Boolean);
const isIPish = (s: string) =>
  /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(s) || // IPv4 / CIDR
  (s.includes(":") && /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(s)); // IPv6 / CIDR
const cleanRouting = (rc: AwgRoutingConfig): AwgRoutingConfig => ({
  ...rc,
  zones: (rc.zones || []).map((z) => {
    const all = cleanArr(zoneLines(z));
    return { ...z, domains: all.filter((x) => !isIPish(x)), ips: all.filter(isIPish) };
  }),
});
const routingFromStatus = (st: Awg2Status): AwgRoutingConfig => ({
  ...st.config.routing,
  mode: st.config.routing?.mode || "zones",
  zones: st.routing_rules || st.config.routing?.zones || [],
});

export default function RoutingPane({ st, reload }: { st: Awg2Status; reload: () => void }) {
  const [r, setRState] = useState<AwgRoutingConfig>(() => routingFromStatus(st));
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const timer = useRef<number | null>(null);
  const autoTimer = useRef<number | null>(null);
  const routingKey = JSON.stringify({ routing: st.config.routing || {}, rules: st.routing_rules || [] });
  // Suppress poll-driven resync for a brief window after a save. Otherwise the
  // parent's 2.5s usePoll can race with our local markSaved: a poll fetched at
  // the same time as POST may have captured pre-save state, and its setSt then
  // overrides our just-applied edits via the resync useEffect. 3s covers at
  // least one full poll cycle so the next refetch sees the saved values.
  const savedAtRef = useRef(0);
  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current); if (autoTimer.current) window.clearTimeout(autoTimer.current); }, []);
  useEffect(() => {
    if (dirty) return;
    if (Date.now() - savedAtRef.current < 3000) return;
    setRState(routingFromStatus(st));
  }, [routingKey, dirty, st]);
  const setR = (next: AwgRoutingConfig | ((prev: AwgRoutingConfig) => AwgRoutingConfig)) => {
    setDirty(true);
    setRState(next);
  };
  const markSaved = (next: AwgRoutingConfig) => {
    setRState(next);
    setDirty(false);
    savedAtRef.current = Date.now();
  };

  const eng = st.engine;
  // Routing is "active" once committed; while active, saving zones/masks/killswitch
  // applies to the live tunnel immediately (the backend refreshes membership without
  // a dead-man's switch — it can't cut panel access).
  const active = r.mode !== "off" && (r.zones || []).some((z) => z.enabled);

  const post = async (path: string, body: unknown, ok: string, after?: () => void, savedRouting?: AwgRoutingConfig) => {
    setBusy(true);
    try { await api("POST", path, body); if (savedRouting) markSaved(savedRouting); toast(ok, "ok"); after?.(); await reload(); }
    catch (e) { toast((e as Error).message, "err"); }
    finally { setBusy(false); }
  };
  const saveRules = (nextRouting: AwgRoutingConfig, ok: string, after?: () => void) =>
    post("/api/awg2/routing/rules", nextRouting, ok, after, nextRouting);

  const install = async () => {
    if (!(await confirmDialog({
      title: eng.installed ? "Обновить движок AmneziaWG?" : "Установить движок AmneziaWG?",
      body: `Установит ${eng.target_version || "актуальную сборку"} на роутер. Действующие VPN-туннели будут перезапущены с сохранением профилей.`,
      confirmLabel: eng.installed ? "Обновить" : "Установить",
    }))) return;
    setBusy(true);
    try {
      const d = await api<{ ok: boolean; detail?: string; error?: string }>("POST", "/api/awg2/install", {});
      toast(d.ok ? "Движок AmneziaWG готов" : "Ошибка: " + (d.error || "?"), d.ok ? "ok" : "err");
      await reload();
    } catch (e) { toast((e as Error).message, "err"); } finally { setBusy(false); }
  };

  const stopCountdown = () => { setCountdown(0); if (timer.current) window.clearInterval(timer.current); if (autoTimer.current) { window.clearTimeout(autoTimer.current); autoTimer.current = null; } };

  const applyRouting = async () => {
    if (r.mode === "off") return teardown();
    if (!(await confirmDialog({
      title: "Применить маршрутизацию?",
      body: `Режим «${r.mode}». Часть трафика пойдёт через VPN. Подтверждение произойдёт автоматически через несколько секунд; если применение оборвёт связь с панелью — будет авто-откат. Локальная сеть, приватные адреса и сам сервер VPN всегда в обход туннеля.`,
      confirmLabel: "Применить",
    }))) return;
    setBusy(true);
    try {
      const nextRouting = cleanRouting(r);
      await api("POST", "/api/awg2/routing/rules", nextRouting);
      markSaved(nextRouting);
      toast("Правила применены", "ok");
      await reload();
    } catch (e) { toast((e as Error).message, "err"); } finally { setBusy(false); }
  };
  const commit = () => stopCountdown();

  const teardown = () => {
    const nextRouting = cleanRouting({ ...r, mode: "off" });
    void saveRules(nextRouting, "Маршрутизация снята", stopCountdown);
  };

  const setZone = (i: number, patch: Partial<AwgZone>) => setR((p) => ({ ...p, zones: p.zones.map((z, j) => (j === i ? { ...z, ...patch } : z)) }));
  // Per-zone editor lives in RulesTable now — the legacy zone-form +
  // include/exclude segment was replaced by a pi-hole-style table. setZone is
  // kept for any in-place tweaks (the table calls it from row controls).
  void setZone;

  return (
    <>
      {(!eng.installed || eng.update_available || !eng.awg3_supported || !eng.tun_ok) && (
      <Card title="Движок AmneziaWG" sub={eng.installed ? `Установлен: ${eng.awg_version || "версия неизвестна"}` : "нужен для запуска VPN на роутере"}>
        {!eng.supported ? (
          <p className="text-xs text-bad">Для архитектуры {eng.arch} готовой сборки движка нет.</p>
        ) : (
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="primary" onClick={install} disabled={busy}>{busy ? "Установка…" : `${eng.installed ? "Обновить движок" : "Установить движок"}${eng.target_version ? ` · ${eng.target_version}` : ""}`}</Button>
            {!eng.tun_ok && <span className="text-xs text-warn">⚠ /dev/net/tun не найден — при установке будет попытка загрузить модуль</span>}
          </div>
        )}
        {eng.update_available && <p className="mt-2 text-xs text-muted">Обновление добавляет поддержку AWG 3.1. Существующие профили AWG 2.0, WireGuard и WARP сохраняются.</p>}
      </Card>
      )}

      <Card title="Сплит-маршрутизация" sub="локальные правила на роутере, независимо от настроек подключений">
        <div className="flex flex-wrap gap-4">
          <Field label="Режим" className="min-w-[280px] flex-1">
            <Select value={r.mode === "include" || r.mode === "exclude" ? "zones" : r.mode} onChange={(e) => setR({ ...r, mode: e.target.value })}>
              <option value="off">Выключено</option>
              <option value="zones">По зонам (Включить/Исключить на каждой зоне)</option>
              <option value="full">Весь трафик — через VPN</option>
            </Select>
          </Field>
        </div>
        <div className="mt-1 flex items-center gap-4"><Switch checked={!!r.killswitch} onChange={(v) => setR({ ...r, killswitch: v })} label="Эксклюзивный маршрут (kill-switch): если туннель недоступен — сайты из зон НЕ открываются" /></div>
        <p className="mt-0.5 text-[11px] text-muted">Включено — трафик зон идёт только через туннель; упал туннель → соединения нет (без утечки в обычный канал). Выключено — при недоступном туннеле сайты зон открываются обычным прямым соединением.</p>
        <div className="mt-1 flex items-center gap-4"><Switch checked={r.domain_source === "dnsproxy"} onChange={(v) => setR({ ...r, domain_source: v ? "dnsproxy" : "resolve" })} label="Перехват DNS и для обычных доменов (поддомены + смена IP)" /></div>
        <p className="mt-0.5 text-[11px] text-muted">Маски (<b>*.com</b>, <b>*ip*</b>, <b>[re]…</b>) включают перехват DNS <b>автоматически</b> — отдельно тумблер для них не нужен. Тумблер дополнительно заводит в туннель <b>обычные</b> домены со всеми поддоменами и новыми IP. Перехват ловит только нешифрованный DNS через роутер; DoH/DoT на устройстве его обходит — для «всё и всегда» ставьте <b>*</b> или режим «Весь трафик». Общие CDN-IP вроде Cloudflare автоматически не кэшируются, чтобы не зацепить соседние сайты.</p>
        <div className="mt-1 flex items-center gap-4"><Switch checked={!!r.sni_routing} onChange={(v) => setR({ ...r, sni_routing: v })} label="SNI-маршрутизация (DoH; без общих CDN-IP) — дополнительный слой" /></div>
        <p className="mt-0.5 text-[11px] text-muted">Читает имя сайта прямо из TLS-рукопожатия — <b>не зависит от DNS</b> (работает при DoH/DoT). Домены из зон «Включить» заводятся в туннель по факту обращения и держатся ~1 ч. Первый коннект к новому адресу ещё уходит напрямую (по нему учимся), дальше — через VPN. Если адрес принадлежит общему CDN-edge Cloudflare, он пропускается; для такого случая нужен режим «Весь трафик» или явный IP/CIDR с пониманием, что это правило шире одного домена.</p>
        {r.domain_source === "dnsproxy" && (
          <p className="mt-1 text-[11px] text-muted">Перехватывает DNS локальной сети и заводит в туннель IP по совпадению имени. Форматы строки: <b>youtube.com</b> — домен и все поддомены; <b>ip*</b> — всё, что начинается на «ip» (ipinfo.io, iphone.com) — точка НЕ нужна; <b>*ip*</b> — всё, что содержит «ip» (2ip.ru, ipinfo.io); <b>server*</b>, <b>test##.com</b> (<b>#</b> — один символ); регэксп <b>[re]^.*\.cdn\.net$</b>. ⚠️ <b>ip.*</b> (с точкой) совпадает только с «ip.что-то», НЕ с ipinfo.io — для «ipinfo» пишите <b>ip*</b> или <b>*ip*</b>. Маски действуют, только пока маршрутизация активна; шифрованный DNS (DoH/DoT) на устройстве это обходит.</p>
        )}
        <div className="mt-2 flex flex-wrap items-center gap-2.5">
          {r.mode === "off" ? (
            <Button variant="primary" onClick={teardown} disabled={busy}>Снять маршрутизацию</Button>
          ) : active ? (
            <Button variant="primary" onClick={() => { const nextRouting = cleanRouting(r); void saveRules(nextRouting, "Сохранено и применено"); }} disabled={busy}>Сохранить и применить</Button>
          ) : (
            <>
              <Button onClick={() => { const nextRouting = cleanRouting(r); void saveRules(nextRouting, "Маршрутизация сохранена"); }} disabled={busy}>Сохранить</Button>
              <Button variant="primary" onClick={applyRouting} disabled={busy}>Применить</Button>
            </>
          )}
          {countdown > 0 && <Button variant="primary" onClick={commit} disabled={busy}>✓ Подтвердить ({countdown}с)</Button>}
          {countdown > 0 && <span className="text-xs font-medium text-warn">← нажмите, иначе авто-откат</span>}
        </div>
        {active
          ? <p className="mt-2 text-[11px] font-medium text-ok">● Маршрутизация активна — правки режима, зон, масок и kill-switch применяются к туннелю сразу при сохранении.</p>
          : <p className="mt-2 text-[11px] text-muted">Локальная сеть, приватные адреса и адрес сервера VPN всегда идут в обход туннеля. Первое применение защищено авто-откатом: если панель станет недоступна — маршрутизация откатится сама.</p>}
      </Card>

      <Card title="Правила" sub="приоритет сверху вниз — первое совпадение определяет маршрут · применяются автоматически">
        <RulesTable r={r} setR={setRState} st={st} reload={reload} />
      </Card>
    </>
  );
}

import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Switch } from "@/components/ui/Switch";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import type { Awg2Status, AwgRoutingConfig, AwgZone, Device } from "@/types/api";

// DevicePicker fetches the live device list (DHCP leases + ARP cache, same data
// the Devices tab shows) so the user can click a hostname instead of typing the
// IP. Picking a device appends its LAN IP to the zone's source_ips; the v6 path
// auto-derives from the MAC at apply time (see firewall_linux.go), so one click
// covers both families.
function DevicePicker({ onPick }: { onPick: (ip: string) => void }) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open) return;
    void (async () => {
      try {
        const v = await api<{ devices: Device[] }>("GET", "/api/devices");
        setDevices((v.devices ?? []).filter((d) => d.ip));
      } catch (e) { toast((e as Error).message, "err"); }
    })();
  }, [open]);
  return (
    <span className="relative inline-block">
      <Button mini onClick={() => setOpen((v) => !v)}>+ из списка</Button>
      {open && (
        <div className="absolute left-0 top-full z-10 mt-1 max-h-72 w-72 overflow-y-auto rounded-lg border border-line bg-panel p-1 text-xs shadow-lg">
          {devices.length === 0 ? (
            <div className="px-2 py-1 text-muted">Загрузка...</div>
          ) : devices.map((d) => (
            <button key={d.mac + d.ip} type="button" onClick={() => { onPick(d.ip); setOpen(false); }} className="block w-full rounded px-2 py-1 text-left hover:bg-line-soft">
              {d.hostname && <b className="text-ink">{d.hostname} </b>}
              <span className="font-mono">{d.ip}</span>
              {!d.hostname && <span className="ml-2 text-muted">{d.mac}</span>}
            </button>
          ))}
        </div>
      )}
    </span>
  );
}

// One combined list per zone: domains/masks AND IPv4/IPv6/CIDR in the same box.
// During editing everything lives in z.domains; on save we split IP/CIDR lines into
// z.ips and keep the rest in z.domains (the backend routes ips via ipset and
// domains/masks via the DNS proxy).
const zoneLines = (z: AwgZone) => [...(z.domains || []), ...(z.ips || [])];
const toLines = (a: string[]) => (a || []).join("\n");
// Keep raw lines while editing (don't trim/drop blanks — that fights the cursor
// and blocks pressing Enter). Clean (trim + drop empties) only when saving.
const splitRaw = (s: string) => s.split("\n");
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
const human = (n: number) => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
};
const ago = (t: number) => {
  if (!t) return "—";
  const s = Math.max(0, Math.floor(Date.now() / 1000) - t);
  return s < 60 ? `${s} с назад` : s < 3600 ? `${Math.floor(s / 60)} мин назад` : `${Math.floor(s / 3600)} ч назад`;
};

export default function RoutingPane({ st, reload }: { st: Awg2Status; reload: () => void }) {
  const [r, setRState] = useState<AwgRoutingConfig>(() => st.config.routing);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const timer = useRef<number | null>(null);
  const autoTimer = useRef<number | null>(null);
  const serverID = st.active_server_id || "";
  const routingKey = JSON.stringify(st.config.routing || {});
  const lastServerIDRef = useRef(serverID);
  // Suppress poll-driven resync for a brief window after a save. Otherwise the
  // parent's 2.5s usePoll can race with our local markSaved: a poll fetched at
  // the same time as POST may have captured pre-save state, and its setSt then
  // overrides our just-applied edits via the resync useEffect. 3s covers at
  // least one full poll cycle so the next refetch sees the saved values.
  const savedAtRef = useRef(0);
  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current); if (autoTimer.current) window.clearTimeout(autoTimer.current); }, []);
  useEffect(() => {
    if (lastServerIDRef.current !== serverID) {
      // User switched to a different AWG server — its routing config is wholly
      // different, force-reset whatever was in flight.
      lastServerIDRef.current = serverID;
      setRState(st.config.routing);
      setDirty(false);
      return;
    }
    if (dirty) return;
    if (Date.now() - savedAtRef.current < 3000) return;
    setRState(st.config.routing);
  }, [routingKey, serverID, dirty, st.config.routing]);
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
  const cl = st.client;
  // Routing is "active" once committed; while active, saving zones/masks/killswitch
  // applies to the live tunnel immediately (the backend refreshes membership without
  // a dead-man's switch — it can't cut panel access).
  const active = !!st.config.routing.active && r.mode !== "off";

  const post = async (path: string, body: unknown, ok: string, after?: () => void, savedRouting?: AwgRoutingConfig) => {
    setBusy(true);
    try { await api("POST", path, body); if (savedRouting) markSaved(savedRouting); toast(ok, "ok"); after?.(); await reload(); }
    catch (e) { toast((e as Error).message, "err"); }
    finally { setBusy(false); }
  };

  const install = async () => {
    if (!(await confirmDialog({ title: "Установить движок AmneziaWG?", body: "Скачает нашу сборку amneziawg-go + awg и установит на роутер (нужен интернет).", confirmLabel: "Установить" }))) return;
    setBusy(true);
    try {
      const d = await api<{ ok: boolean; detail?: string; error?: string }>("POST", "/api/awg2/install", {});
      toast(d.ok ? "Движок установлен" : "Ошибка: " + (d.error || "?"), d.ok ? "ok" : "err");
      await reload();
    } catch (e) { toast((e as Error).message, "err"); } finally { setBusy(false); }
  };

  const startCountdown = () => {
    setCountdown(90);
    if (timer.current) window.clearInterval(timer.current);
    timer.current = window.setInterval(() => setCountdown((c) => {
      if (c <= 1) { if (timer.current) window.clearInterval(timer.current); return 0; }
      return c - 1;
    }), 1000);
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
      await api("POST", "/api/awg2/routing/config", nextRouting);
      markSaved(nextRouting);
      await api("POST", "/api/awg2/routing/apply", {});
      toast("Применено — подтверждаю автоматически…", "ok");
      startCountdown();
      await reload();
      // Auto-confirm shortly after: the panel is reached by LAN IP regardless of
      // routing (LAN/private/self are always excluded from the tunnel), so a config
      // change can't cut panel access. If it somehow did, this commit POST fails and
      // the 90s dead-man's switch still rolls everything back.
      if (autoTimer.current) window.clearTimeout(autoTimer.current);
      autoTimer.current = window.setTimeout(() => {
        void api("POST", "/api/awg2/routing/commit", {})
          .then(() => { stopCountdown(); toast("Подтверждено", "ok"); void reload(); })
          .catch(() => { /* unreachable → dead-man's switch rolls back */ });
      }, 5000);
    } catch (e) { toast((e as Error).message, "err"); } finally { setBusy(false); }
  };
  const commit = () => post("/api/awg2/routing/commit", {}, "Подтверждено — авто-откат отменён", stopCountdown);

  // Save + apply + commit when the tunnel is ALREADY active. No confirm dialog
  // and no 90s dead-man's countdown — the panel can't lose itself because
  // LAN/private/self are always excluded from the tunnel, so re-applying live
  // zones can't cut access. The previous behaviour (POST only /routing/config)
  // was wrong: the backend persists the new config but doesn't rebuild ipsets
  // until /apply, so zone edits silently never took effect.
  const applyRoutingLive = async () => {
    setBusy(true);
    try {
      const nextRouting = cleanRouting(r);
      await api("POST", "/api/awg2/routing/config", nextRouting);
      markSaved(nextRouting);
      await api("POST", "/api/awg2/routing/apply", {});
      // Commit immediately — there's no need for the dead-man's switch because
      // the tunnel is already up; this is a refresh, not a cut-over.
      await api("POST", "/api/awg2/routing/commit", {});
      toast("Зоны применены к туннелю", "ok");
      await reload();
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };
  const teardown = () => {
    const nextRouting = cleanRouting({ ...r, mode: "off" });
    void post("/api/awg2/routing/config", nextRouting, "Маршрутизация снята", stopCountdown, nextRouting);
  };

  const setZone = (i: number, patch: Partial<AwgZone>) => setR((p) => ({ ...p, zones: p.zones.map((z, j) => (j === i ? { ...z, ...patch } : z)) }));
  const addZone = () => setR((p) => ({ ...p, zones: [...(p.zones || []), { name: "новая зона", mode: "include", domains: [], ips: [], source_ips: [], enabled: true }] }));
  const delZone = (i: number) => setR((p) => ({ ...p, zones: p.zones.filter((_, j) => j !== i) }));

  // Per-zone Include/Exclude picker: each zone routes its own members THROUGH the
  // tunnel (include) or DIRECT/bypass (exclude). The base for everything else is
  // derived on the backend: any include-zone → whitelist (only includes via VPN,
  // excludes carve out); only exclude-zones → blacklist (everything via VPN except).
  const zoneSeg = (i: number, z: AwgZone, m: "include" | "exclude", label: string, hint: string) => (
    <button
      type="button"
      title={hint}
      onClick={() => setZone(i, { mode: m })}
      className={cn(
        "border-r border-line px-2.5 py-1 text-xs outline-none transition last:border-r-0 focus-visible:relative focus-visible:ring-2 focus-visible:ring-ring/40",
        (z.mode || "include") === m ? "bg-accent text-white" : "bg-panel text-ink-soft hover:bg-line-soft",
      )}
    >
      {label}
    </button>
  );

  return (
    <>
      <Card
        title="Движок и туннель на роутере"
        sub="userspace amneziawg-go (наша сборка)"
        head={
          <div className="flex flex-wrap items-center gap-2">
            <Badge kind={eng.installed ? "ok" : "neutral"}>{eng.installed ? "движок установлен" : "движок не установлен"}</Badge>
            {cl?.running && <Badge kind={cl.connected ? "ok" : "warn"}>{cl.connected ? "туннель подключён" : "туннель поднят"}</Badge>}
          </div>
        }
      >
        {!eng.supported ? (
          <p className="text-xs text-bad">Для архитектуры {eng.arch} готовой сборки движка нет.</p>
        ) : !eng.installed ? (
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="primary" onClick={install} disabled={busy}>Установить движок</Button>
            {!eng.tun_ok && <span className="text-xs text-warn">⚠ /dev/net/tun не найден — при установке будет попытка загрузить модуль</span>}
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-3">
              {cl?.running
                ? <Button onClick={() => post("/api/awg2/client/down", {}, "Туннель опущен")} disabled={busy}>Опустить туннель</Button>
                : <Button variant="primary" onClick={() => post("/api/awg2/client/up", {}, "Туннель поднят")} disabled={busy}>Поднять туннель</Button>}
              <span className="text-xs text-muted">движок {eng.awg_version || "ok"}{cl?.running ? ` · ${cl.endpoint || ""}` : ""}</span>
            </div>
            {cl?.running && (
              <p className="mt-2 text-xs text-muted">Хендшейк: {ago(cl.last_handshake)} · ↑ {human(cl.tx_bytes)} / ↓ {human(cl.rx_bytes)} · MTU {cl.mtu || "—"}</p>
            )}
            {!st.deployed && <p className="mt-1 text-[11px] text-warn">Сервер ещё не развёрнут — разверните его и добавьте этот роутер как пир (вкладка «Клиенты»).</p>}
          </>
        )}
      </Card>

      <Card title="Сплит-маршрутизация" sub="как делить трафик между туннелем и прямым выходом">
        <div className="flex flex-wrap gap-4">
          <Field label="Режим" className="min-w-[280px] flex-1">
            <Select value={r.mode === "include" || r.mode === "exclude" ? "zones" : r.mode} onChange={(e) => setR({ ...r, mode: e.target.value })}>
              <option value="off">Выключено</option>
              <option value="zones">По зонам (Включить/Исключить на каждой зоне)</option>
              <option value="full">Весь трафик — через VPN</option>
            </Select>
          </Field>
          <Field label="MTU туннеля" className="w-28 shrink-0"><Input type="number" min={1280} max={1420} value={String(r.mtu || 1376)} onChange={(e) => setR({ ...r, mtu: parseInt(e.target.value, 10) || 1376 })} /></Field>
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
            <Button variant="primary" onClick={() => { const nextRouting = cleanRouting(r); void post("/api/awg2/routing/config", nextRouting, "Сохранено и применено к туннелю", undefined, nextRouting); }} disabled={busy}>Сохранить и применить</Button>
          ) : (
            <>
              <Button onClick={() => { const nextRouting = cleanRouting(r); void post("/api/awg2/routing/config", nextRouting, "Маршрутизация сохранена", undefined, nextRouting); }} disabled={busy}>Сохранить</Button>
              <Button variant="primary" onClick={applyRouting} disabled={busy || !cl?.running}>Применить</Button>
            </>
          )}
          {countdown > 0 && <Button variant="primary" onClick={commit} disabled={busy}>✓ Подтвердить ({countdown}с)</Button>}
          {countdown > 0 && <span className="text-xs font-medium text-warn">← нажмите, иначе авто-откат</span>}
          {!cl?.running && r.mode !== "off" && !active && <span className="text-xs text-muted">сначала поднимите туннель</span>}
        </div>
        {active
          ? <p className="mt-2 text-[11px] font-medium text-ok">● Маршрутизация активна — правки режима, зон, масок и kill-switch применяются к туннелю сразу при сохранении.</p>
          : <p className="mt-2 text-[11px] text-muted">Локальная сеть, приватные адреса и адрес сервера VPN всегда идут в обход туннеля. Первое применение защищено авто-откатом: если панель станет недоступна — маршрутизация откатится сама.</p>}
      </Card>

      <Card title="Зоны" sub="что заводить в туннель — домены, маски и IP в одном списке" head={<Button mini onClick={addZone}>Добавить зону</Button>}>
        <p className="mb-2 text-[11px] text-muted"><b>Включить</b> — зона идёт через VPN; <b>Исключить</b> — мимо VPN (напрямую). Есть хоть одна «Включить» → через туннель идут только include-зоны (exclude вырезаются); только «Исключить» → через туннель идёт всё, кроме них. <b>Звёздочка <code>*</code> отдельной строкой во «Включить»-зоне = весь трафик через VPN</b> — надёжно, на уровне файрвола (работает для всех сайтов, не зависит от DNS); вместе с «Исключить»-зоной = всё, кроме неё. В список можно вписывать вперемешку: домены/маски, IPv4 и подсети (напр. <b>104.18.0.0/16</b>); IPv6 принимается, но в туннель пока не маршрутизируется.</p>
        {(r.zones || []).length === 0 ? (
          <p className="text-xs text-muted">Зон нет. Добавьте зону и впишите домены (напр. youtube.com), маски (ip*) и/или IP/подсети — всё в одном списке.</p>
        ) : (
          (r.zones || []).map((z, i) => (
            <div key={i} className="mb-3 rounded-lg border border-line p-2.5">
              <div className="mb-2 flex flex-wrap items-center gap-3">
                <Input className="w-44" value={z.name} onChange={(e) => setZone(i, { name: e.target.value })} />
                <div className="inline-flex overflow-hidden rounded-md border border-line" role="group" aria-label="Режим зоны">
                  {zoneSeg(i, z, "include", "Включить", "Зона идёт через VPN (туннель)")}
                  {zoneSeg(i, z, "exclude", "Исключить", "Зона идёт мимо VPN (напрямую)")}
                </div>
                <Switch checked={z.enabled} onChange={(v) => setZone(i, { enabled: v })} label="вкл" />
                <Button mini onClick={() => delZone(i)}>Удалить</Button>
              </div>
              <Field label="Домены, маски и IP — всё в одном списке (по строке)" hint={"Префиксы xray-стиля: domain:vk.com (суффикс), full:exact.com (точный), geosite:cn / geoip:cn (категория из загруженного geosite.dat/geoip.dat), regexp:^.*\\.foo$ (Go regex), keyword:foo (substring), list:user (читает /opt/etc/nfqws2/lists/user.list). Без префикса работает по-старому."}>
                <Textarea rows={6} value={toLines(zoneLines(z))} placeholder={"youtube.com\n*ip*\ndomain:vk.com\ngeosite:cn\nregexp:^.*\\.googlevideo\\.com$\nlist:user\n104.18.0.0/16"} onChange={(e) => setZone(i, { domains: splitRaw(e.target.value), ips: [] })} />
              </Field>
              <Field label="Источники (LAN IP/CIDR — пусто = вся сеть)" hint={"Если задано, зона применяется ТОЛЬКО к пакетам от этих устройств (IPv4 — по адресу, IPv6 — по MAC из ARP-кэша). Семантика для source-зоны: include + пустые домены = ВЕСЬ трафик источников в туннель; include + домены = только эти домены в туннель для этих источников; exclude + домены = эти домены идут direct ДЛЯ ЭТИХ источников (carve-out поверх include). Order: exclude перебивает include. Source-зоны не влияют на других пользователей сети."}>
                <div className="flex items-start gap-2">
                  <Textarea rows={2} className="flex-1" value={toLines(z.source_ips || [])} placeholder={"192.168.31.243\n192.168.31.100"} onChange={(e) => setZone(i, { source_ips: splitRaw(e.target.value) })} />
                  <DevicePicker onPick={(ip) => {
                    const cur = (z.source_ips || []).map((s) => s.trim()).filter(Boolean);
                    if (cur.includes(ip)) return;
                    setZone(i, { source_ips: [...cur, ip] });
                  }} />
                </div>
              </Field>
            </div>
          ))
        )}
        {(r.zones || []).length > 0 && <Button variant="primary" onClick={() => { if (!active) { void applyRouting(); } else { void applyRoutingLive(); } }} disabled={busy}>Сохранить и применить зоны</Button>}
      </Card>
    </>
  );
}

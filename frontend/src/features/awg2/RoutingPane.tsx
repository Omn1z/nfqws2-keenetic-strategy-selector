import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Switch } from "@/components/ui/Switch";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import type { Awg2Status, AwgRoutingConfig, AwgZone } from "@/types/api";

const toLines = (a: string[]) => (a || []).join("\n");
// Keep raw lines while editing (don't trim/drop blanks — that fights the cursor
// and blocks pressing Enter). Clean (trim + drop empties) only when saving.
const splitRaw = (s: string) => s.split("\n");
const cleanArr = (a: string[]) => (a || []).map((x) => x.trim()).filter(Boolean);
const cleanRouting = (rc: AwgRoutingConfig): AwgRoutingConfig => ({
  ...rc,
  zones: (rc.zones || []).map((z) => ({ ...z, domains: cleanArr(z.domains), ips: cleanArr(z.ips) })),
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
  const [r, setR] = useState<AwgRoutingConfig>(() => st.config.routing);
  const [busy, setBusy] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const timer = useRef<number | null>(null);
  const autoTimer = useRef<number | null>(null);
  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current); if (autoTimer.current) window.clearTimeout(autoTimer.current); }, []);

  const eng = st.engine;
  const cl = st.client;

  const post = async (path: string, body: unknown, ok: string, after?: () => void) => {
    setBusy(true);
    try { await api("POST", path, body); toast(ok, "ok"); after?.(); await reload(); }
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
      await api("POST", "/api/awg2/routing/config", cleanRouting(r));
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
  const teardown = () => post("/api/awg2/routing/teardown", {}, "Маршрутизация снята", stopCountdown);

  const setZone = (i: number, patch: Partial<AwgZone>) => setR((p) => ({ ...p, zones: p.zones.map((z, j) => (j === i ? { ...z, ...patch } : z)) }));
  const addZone = () => setR((p) => ({ ...p, zones: [...(p.zones || []), { name: "новая зона", domains: [], ips: [], enabled: true }] }));
  const delZone = (i: number) => setR((p) => ({ ...p, zones: p.zones.filter((_, j) => j !== i) }));

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
            <Select value={r.mode} onChange={(e) => setR({ ...r, mode: e.target.value })}>
              <option value="off">Выключено</option>
              <option value="exclude">Всё через VPN, кроме зон (напр. .ru — мимо)</option>
              <option value="include">Только зоны — через VPN</option>
              <option value="full">Весь трафик — через VPN</option>
            </Select>
          </Field>
          <Field label="MTU туннеля" className="w-28 shrink-0"><Input type="number" min={1280} max={1420} value={String(r.mtu || 1376)} onChange={(e) => setR({ ...r, mtu: parseInt(e.target.value, 10) || 1376 })} /></Field>
        </div>
        <div className="mt-1 flex items-center gap-4"><Switch checked={!!r.killswitch} onChange={(v) => setR({ ...r, killswitch: v })} label="Killswitch (резать туннельный трафик, если awg0 упал)" /></div>
        <div className="mt-1 flex items-center gap-4"><Switch checked={r.domain_source === "dnsproxy"} onChange={(v) => setR({ ...r, domain_source: v ? "dnsproxy" : "resolve" })} label="Маски и поддомены доменов (перехват DNS)" /></div>
        {r.domain_source === "dnsproxy" && (
          <p className="mt-1 text-[11px] text-muted">Панель прозрачно перехватывает DNS локальной сети и заводит в туннель IP по совпадению имени. Форматы записи домена: <b>domain.com</b> — домен и все поддомены; маски <b>*main.com</b>, <b>server*</b>, <b>test##.com</b> (<b>#</b> — один символ); регэксп <b>[re]^.*\.cdn\.net$</b>. Действует только пока маршрутизация активна; шифрованный DNS (DoH/DoT) на устройстве это обходит.</p>
        )}
        <div className="mt-2 flex flex-wrap items-center gap-2.5">
          <Button onClick={() => post("/api/awg2/routing/config", cleanRouting(r), "Маршрутизация сохранена")} disabled={busy}>Сохранить</Button>
          {r.mode === "off"
            ? <Button variant="primary" onClick={teardown} disabled={busy}>Снять маршрутизацию</Button>
            : <Button variant="primary" onClick={applyRouting} disabled={busy || !cl?.running}>Применить</Button>}
          {countdown > 0 && <Button variant="primary" onClick={commit} disabled={busy}>✓ Подтвердить ({countdown}с)</Button>}
          {countdown > 0 && <span className="text-xs font-medium text-warn">← нажмите, иначе авто-откат</span>}
          {!cl?.running && r.mode !== "off" && <span className="text-xs text-muted">сначала поднимите туннель</span>}
        </div>
        <p className="mt-2 text-[11px] text-muted">Локальная сеть, приватные адреса и адрес сервера VPN всегда идут в обход туннеля. Применение защищено авто-откатом: если панель станет недоступна — маршрутизация откатится сама.</p>
      </Card>

      <Card title="Зоны (домены / IP)" sub="наполнение для include/exclude" head={<Button mini onClick={addZone}>Добавить зону</Button>}>
        {(r.zones || []).length === 0 ? (
          <p className="text-xs text-muted">Зон нет. Добавьте зону с доменами (напр. youtube.com) и/или IP/подсетями — они попадут в ipset выбранного режима.</p>
        ) : (
          (r.zones || []).map((z, i) => (
            <div key={i} className="mb-3 rounded-lg border border-line p-2.5">
              <div className="mb-2 flex flex-wrap items-center gap-3">
                <Input className="w-48" value={z.name} onChange={(e) => setZone(i, { name: e.target.value })} />
                <Switch checked={z.enabled} onChange={(v) => setZone(i, { enabled: v })} label="вкл" />
                <Button mini onClick={() => delZone(i)}>Удалить</Button>
              </div>
              <div className="flex flex-wrap gap-3">
                <Field label="Домены (по строке)" className="min-w-[200px] flex-1"><Textarea rows={4} value={toLines(z.domains)} placeholder={"youtube.com\ngoogleapis.com"} onChange={(e) => setZone(i, { domains: splitRaw(e.target.value) })} /></Field>
                <Field label="IP / подсети (по строке)" className="min-w-[160px] flex-1"><Textarea rows={4} value={toLines(z.ips)} placeholder={"1.2.3.4\n10.0.0.0/24"} onChange={(e) => setZone(i, { ips: splitRaw(e.target.value) })} /></Field>
              </div>
            </div>
          ))
        )}
        {(r.zones || []).length > 0 && <Button onClick={() => post("/api/awg2/routing/config", cleanRouting(r), "Сохранить зоны")} disabled={busy}>Сохранить зоны</Button>}
      </Card>
    </>
  );
}

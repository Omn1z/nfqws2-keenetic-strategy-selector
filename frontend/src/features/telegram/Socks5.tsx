import { useRef, useState } from "react";
import type { ReactNode } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Switch } from "@/components/ui/Switch";
import { Field, Input } from "@/components/ui/form";
import { tableCls, tdCls } from "@/components/ui/Table";
import AwgFallback from "./AwgFallback";
import type { Socks5Config, Socks5Status } from "@/types/api";

interface Form {
  port: string;
  user: string;
  pass: string;
  link_host: string;
}

const toForm = (c: Socks5Config): Form => ({
  port: String(c.port || 1080), user: c.user || "", pass: c.pass || "", link_host: c.link_host || "",
});

const StatRow = ({ l, v }: { l: string; v: ReactNode }) => (
  <tr><td className={cn(tdCls, "text-ink-soft")}>{l}</td><td className={cn(tdCls, "tabular-nums")}>{v}</td></tr>
);

export default function Socks5() {
  const [form, setForm] = useState<Form | null>(null);
  const [live, setLive] = useState<Socks5Status | null>(null);
  const loaded = useRef(false);

  const apply = (st: Socks5Status) => { setLive(st); setForm(toForm(st.config)); };
  usePoll(async () => {
    try {
      const st = await api<Socks5Status>("GET", "/api/socks5");
      setLive(st);
      if (!loaded.current) { setForm(toForm(st.config)); loaded.current = true; }
    } catch { /* keep last */ }
  }, 2000);

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const toggle = async (on: boolean) => { try { apply(await api<Socks5Status>("POST", on ? "/api/socks5/start" : "/api/socks5/stop", {})); toast(on ? "SOCKS5 запущен" : "SOCKS5 остановлен", "ok"); } catch (e) { toast((e as Error).message, "err"); } };
  const save = async () => {
    if (!form || !live) return;
    const body: Socks5Config = { ...live.config, port: parseInt(form.port, 10) || 1080, user: form.user.trim(), pass: form.pass, link_host: form.link_host.trim() };
    try { apply(await api<Socks5Status>("POST", "/api/socks5/config", body)); toast("Настройки сохранены", "ok"); } catch (e) { toast((e as Error).message, "err"); }
  };
  const copy = async () => { const v = live?.link; if (!v) return; try { await navigator.clipboard.writeText(v); toast("Ссылка скопирована", "ok"); } catch { toast("Скопируйте вручную", "err"); } };

  if (!form || !live) return <Card><span className="text-xs text-muted">Загрузка…</span></Card>;
  const { connections: cc, traffic: t } = live.stats;
  const noAuth = !form.user.trim();

  return (
    <>
      <Card title="Telegram SOCKS5 прокси" head={<Badge kind={live.running ? "ok" : "bad"}>{live.running ? "работает" : "остановлен"}</Badge>}>
        <p className="mb-3 text-xs text-muted">SOCKS5 для Telegram: трафик к дата-центрам Telegram туннелируется по WSS к <code>web.telegram.org</code> (обходит блокировку по IP), остальные адреса проксируются напрямую. Подключается в Telegram → Настройки → Данные и память → Прокси → SOCKS5.</p>
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex h-[38px] items-center"><Switch checked={live.config.enabled} onChange={toggle} label="Прокси включён" /></div>
          <span className="text-xs text-muted">{live.running ? `слушает порт ${form.port}` : live.config.enabled ? "не удалось запустить" : ""}</span>
        </div>
      </Card>

      <AwgFallback />

      <Card title="Подключение Telegram" sub="ссылка добавляет прокси автоматически">
        <Field label="tg:// ссылка"><div className="flex gap-2"><Input readOnly value={live.link} className="font-mono text-xs" /><Button onClick={copy}>Копировать</Button></div></Field>
        <p className="text-xs text-muted">Откройте ссылку на устройстве с Telegram — SOCKS5-прокси добавится автоматически.</p>
      </Card>

      <Card title="Настройки">
        {noAuth && (
          <p className="mb-3 rounded-lg bg-warn-bg px-3 py-2 text-xs text-warn">⚠ Сквозной режим без пароля — это <b>открытый SOCKS5</b> в вашей LAN (любое устройство сможет ходить через него куда угодно). Задайте логин и пароль для защиты.</p>
        )}
        <div className="flex flex-wrap gap-4">
          <Field label="Порт прокси" className="w-32 shrink-0"><Input type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", e.target.value)} /></Field>
          <Field label="Хост для ссылки" hint="пусто = авто" className="min-w-[200px] flex-1"><Input value={form.link_host} placeholder="192.168.1.1" onChange={(e) => set("link_host", e.target.value)} /></Field>
        </div>
        <div className="flex flex-wrap gap-4">
          <Field label="Логин" hint="пусто = без пароля" className="min-w-[180px] flex-1"><Input value={form.user} autoComplete="off" placeholder="(необязательно)" onChange={(e) => set("user", e.target.value)} /></Field>
          <Field label="Пароль" className="min-w-[180px] flex-1"><Input value={form.pass} autoComplete="new-password" placeholder="(необязательно)" onChange={(e) => set("pass", e.target.value)} /></Field>
        </div>
        <div className="mt-2 flex items-center gap-2.5"><Button variant="primary" onClick={save}>Сохранить настройки</Button><span className="text-xs text-muted">при включённом прокси сохранение перезапустит его</span></div>
      </Card>

      <Card title="Статистика" sub="обновляется, пока открыта вкладка">
        <table className={tableCls}>
          <tbody>
            <StatRow l="Соединения (всего / активны)" v={`${cc.total} / ${cc.active}`} />
            <StatRow l="Telegram (WSS) / прямые" v={`${cc.telegram} / ${cc.direct}`} />
            <StatRow l="Отклонено (handshake)" v={cc.bad} />
            <StatRow l="Трафик ↑ / ↓" v={`${t.human_up || "0.0B"} / ${t.human_down || "0.0B"}`} />
            <StatRow l="Последний DC" v={live.stats.last_dc || "—"} />
          </tbody>
        </table>
      </Card>
    </>
  );
}

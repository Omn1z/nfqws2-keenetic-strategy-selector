import { useRef, useState } from "react";
import type { ReactNode } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Switch } from "@/components/ui/Switch";
import { Field, Input, Textarea } from "@/components/ui/form";
import { tableCls, tdCls } from "@/components/ui/Table";
import type { TgwsConfig, TgwsStatus } from "@/types/api";

interface Form {
  port: string;
  secret: string;
  dc: string;
  fake_tls_domain: string;
  link_host: string;
  pool_size: string;
  buffer_size: string;
  cfproxy: boolean;
  proxy_protocol: boolean;
  cfproxy_user_domain: string;
  cfproxy_worker_domain: string;
}

const dcText = (m: Record<string, string>) => Object.entries(m ?? {}).map(([k, v]) => `${k}=${v}`).join("\n");
const parseDC = (text: string): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    const p = t.split(/[=:]/);
    if (p.length >= 2) {
      const dc = parseInt(p[0].trim(), 10);
      const ip = p[1].trim();
      if (dc && ip) out[String(dc)] = ip;
    }
  }
  return out;
};
const toForm = (c: TgwsConfig): Form => ({
  port: String(c.port || 1433), secret: c.secret || "", dc: dcText(c.dc_redirects), fake_tls_domain: c.fake_tls_domain || "",
  link_host: c.link_host || "", pool_size: String(c.pool_size ?? 4), buffer_size: String(c.buffer_size || 262144),
  cfproxy: !!c.cfproxy, proxy_protocol: !!c.proxy_protocol, cfproxy_user_domain: c.cfproxy_user_domain || "", cfproxy_worker_domain: c.cfproxy_worker_domain || "",
});
const collect = (f: Form) => ({
  port: parseInt(f.port, 10) || 1433, secret: f.secret.trim(), dc_redirects: parseDC(f.dc), fake_tls_domain: f.fake_tls_domain.trim(),
  link_host: f.link_host.trim(), pool_size: parseInt(f.pool_size, 10) || 0, buffer_size: parseInt(f.buffer_size, 10) || 262144,
  cfproxy: f.cfproxy, proxy_protocol: f.proxy_protocol, cfproxy_user_domain: f.cfproxy_user_domain.trim(), cfproxy_worker_domain: f.cfproxy_worker_domain.trim(),
});

const StatRow = ({ l, v }: { l: string; v: ReactNode }) => (
  <tr><td className={cn(tdCls, "text-ink-soft")}>{l}</td><td className={cn(tdCls, "tabular-nums")}>{v}</td></tr>
);
const ToggleField = ({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) => (
  <div className="flex h-[38px] items-center"><Switch checked={checked} onChange={onChange} label={label} /></div>
);

export default function Tgws() {
  const [form, setForm] = useState<Form | null>(null);
  const [live, setLive] = useState<TgwsStatus | null>(null);
  const loaded = useRef(false);

  const apply = (st: TgwsStatus) => { setLive(st); setForm(toForm(st.config)); };
  usePoll(async () => {
    try {
      const st = await api<TgwsStatus>("GET", "/api/tgws");
      setLive(st);
      if (!loaded.current) { setForm(toForm(st.config)); loaded.current = true; }
    } catch { /* keep last */ }
  }, 2000);

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const toggle = async (on: boolean) => { try { apply(await api<TgwsStatus>("POST", on ? "/api/tgws/start" : "/api/tgws/stop", {})); toast(on ? "Прокси запущен" : "Прокси остановлен", "ok"); } catch (e) { toast((e as Error).message, "err"); } };
  const save = async () => { if (!form) return; try { apply(await api<TgwsStatus>("POST", "/api/tgws/config", collect(form))); toast("Настройки сохранены", "ok"); } catch (e) { toast((e as Error).message, "err"); } };
  const newSecret = async () => { if (!(await confirmDialog({ title: "Сгенерировать новый секрет?", body: "Старые tg:// ссылки перестанут работать.", confirmLabel: "Сгенерировать" }))) return; try { await api("POST", "/api/tgws/secret", {}); apply(await api<TgwsStatus>("GET", "/api/tgws")); toast("Новый секрет сгенерирован", "ok"); } catch (e) { toast((e as Error).message, "err"); } };
  const copy = async () => { const v = live?.link; if (!v) return; try { await navigator.clipboard.writeText(v); toast("Ссылка скопирована", "ok"); } catch { toast("Скопируйте вручную", "err"); } };

  if (!form || !live) return <Card><span className="text-xs text-muted">Загрузка…</span></Card>;
  const { connections: cc, traffic: t, ws: w } = live.stats;

  return (
    <>
      <Card title="Telegram MTProto → WebSocket прокси" head={<Badge kind={live.running ? "ok" : "bad"}>{live.running ? "работает" : "остановлен"}</Badge>}>
        <p className="mb-3 text-xs text-muted">Прокси для Telegram прямо на роутере: клиенты в LAN ходят через <code>&lt;роутер&gt;:порт</code>, трафик идёт к Telegram по WSS с запасными путями.</p>
        <div className="flex flex-wrap items-center gap-4">
          <ToggleField label="Прокси включён" checked={live.config.enabled} onChange={toggle} />
          <span className="text-xs text-muted">{live.running ? `слушает порт ${form.port}` : live.config.enabled ? "не удалось запустить" : ""}</span>
        </div>
      </Card>

      <Card title="Подключение Telegram" sub="ссылка содержит секрет">
        <Field label="tg:// ссылка"><div className="flex gap-2"><Input readOnly value={live.link} className="font-mono text-xs" /><Button onClick={copy}>Копировать</Button></div></Field>
        <p className="text-xs text-muted">Откройте ссылку на устройстве с Telegram (например, в «Избранное») — прокси добавится автоматически.</p>
      </Card>

      <Card title="Настройки">
        <div className="flex flex-wrap gap-4">
          <Field label="Порт прокси" className="w-32 shrink-0"><Input type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", e.target.value)} /></Field>
          <Field label="Секрет (32 hex)" className="min-w-[220px] flex-1"><div className="flex gap-2"><Input readOnly value={form.secret} className="font-mono text-xs" /><Button onClick={newSecret}>Сгенерировать</Button></div></Field>
        </div>
        <Field label="DC-редиректы" hint="по строке: DC=IP (например 2=149.154.167.220)"><Textarea rows={3} value={form.dc} placeholder={"2=149.154.167.220\n4=149.154.167.220"} onChange={(e) => set("dc", e.target.value)} /></Field>
        <div className="flex flex-wrap gap-4">
          <Field label="Fake-TLS домен" hint="пусто = выкл." className="min-w-[200px] flex-1"><Input value={form.fake_tls_domain} placeholder="напр. www.cloudflare.com" onChange={(e) => set("fake_tls_domain", e.target.value)} /></Field>
          <Field label="Хост для ссылки" hint="пусто = авто" className="min-w-[200px] flex-1"><Input value={form.link_host} placeholder="192.168.1.1" onChange={(e) => set("link_host", e.target.value)} /></Field>
        </div>
        <div className="flex flex-wrap gap-4">
          <Field label="Размер пула WS" className="w-32 shrink-0"><Input type="number" min={0} max={16} value={form.pool_size} onChange={(e) => set("pool_size", e.target.value)} /></Field>
          <Field label="Буфер сокета (байт)" className="w-40 shrink-0"><Input type="number" min={4096} step={4096} value={form.buffer_size} onChange={(e) => set("buffer_size", e.target.value)} /></Field>
        </div>
        <div className="flex flex-wrap items-end gap-6">
          <ToggleField label="CF fallback" checked={form.cfproxy} onChange={(v) => set("cfproxy", v)} />
          <ToggleField label="PROXY protocol" checked={form.proxy_protocol} onChange={(v) => set("proxy_protocol", v)} />
        </div>
        <div className="flex flex-wrap gap-4">
          <Field label="CF свой домен" hint="перебивает встроенный пул" className="min-w-[200px] flex-1"><Input value={form.cfproxy_user_domain} onChange={(e) => set("cfproxy_user_domain", e.target.value)} /></Field>
          <Field label="CF Worker домен" hint="пробуется первым" className="min-w-[200px] flex-1"><Input value={form.cfproxy_worker_domain} onChange={(e) => set("cfproxy_worker_domain", e.target.value)} /></Field>
        </div>
        <div className="mt-2 flex items-center gap-2.5"><Button variant="primary" onClick={save}>Сохранить настройки</Button><span className="text-xs text-muted">при включённом прокси сохранение перезапустит его</span></div>
      </Card>

      <Card title="Статистика" sub="обновляется, пока открыта вкладка">
        <table className={tableCls}>
          <tbody>
            <StatRow l="Соединения" v={cc.total} />
            <StatRow l="Активные" v={cc.active} />
            <StatRow l="WS / TCP-fallback / CF" v={`${cc.ws} / ${cc.tcp_fallback} / ${cc.cfproxy}`} />
            <StatRow l="Отклонено (плохой секрет) / маскировка" v={`${cc.bad} / ${cc.masked}`} />
            <StatRow l="Трафик ↑ / ↓" v={`${t.human_up || "0.0B"} / ${t.human_down || "0.0B"}`} />
            <StatRow l="Пул (попаданий/всего) · ошибки WS" v={`${w.pool_hits}/${w.pool_hits + w.pool_misses} · ${w.errors}`} />
          </tbody>
        </table>
      </Card>
    </>
  );
}

import { useRef, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { PageHeader, compactCard } from "@/components/ui/FeaturePage";
import AwgFallback from "./AwgFallback";
import { MtProtoContent } from "./MtProtoPresentation";
import type { InstallResult, TgwsConfig, TgwsStatus } from "@/types/api";

export interface Form {
  port: string;
  secret: string;
  dc: string;
  fake_tls_domain: string;
  link_host: string;
  pool_size: string;
  buffer_size: string;
  cfproxy: boolean;
  cfproxy_h2_media: boolean;
  proxy_protocol: boolean;
  force_test_dc: boolean;
  sni_fronting: boolean;
  disable_secure: boolean;
  cfproxy_user_domain: string;
  cfproxy_worker_domain: string;
}

const dcText = (m: Record<string, string>) => Object.entries(m ?? {}).map(([k, v]) => `${k}=${v}`).join("\n");
const parseDC = (text: string): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    const separator = t.search(/[=:]/);
    if (separator > 0) {
      const dc = parseInt(t.slice(0, separator).trim(), 10);
      const ip = t.slice(separator + 1).trim();
      if (dc && ip) out[String(dc)] = ip;
    }
  }
  return out;
};
export const toForm = (c: TgwsConfig): Form => ({
  port: String(c.port || 1433), secret: c.secret || "", dc: dcText(c.dc_redirects), fake_tls_domain: c.fake_tls_domain || "",
  link_host: c.link_host || "", pool_size: String(c.pool_size ?? 4), buffer_size: String(c.buffer_size || 262144),
  cfproxy: !!c.cfproxy, proxy_protocol: !!c.proxy_protocol, force_test_dc: !!c.force_test_dc, sni_fronting: !!c.sni_fronting, disable_secure: !!c.disable_secure,
  cfproxy_h2_media: c.cfproxy_h2_media ?? true,
  cfproxy_user_domain: c.cfproxy_user_domains?.join("\n") ?? c.cfproxy_user_domain ?? "",
  cfproxy_worker_domain: c.cfproxy_worker_domains?.join("\n") ?? c.cfproxy_worker_domain ?? "",
});
export const collect = (f: Form) => ({
  port: parseInt(f.port, 10) || 1433, secret: f.secret.trim(), dc_redirects: parseDC(f.dc), fake_tls_domain: f.fake_tls_domain.trim(),
  link_host: f.link_host.trim(), pool_size: parseInt(f.pool_size, 10) || 0, buffer_size: parseInt(f.buffer_size, 10) || 262144,
  cfproxy: f.cfproxy, proxy_protocol: f.proxy_protocol, force_test_dc: f.force_test_dc, sni_fronting: f.sni_fronting, disable_secure: f.disable_secure,
  cfproxy_h2_media: f.cfproxy_h2_media,
  cfproxy_user_domains: f.cfproxy_user_domain.split(/[\s,;]+/).filter(Boolean),
  cfproxy_worker_domains: f.cfproxy_worker_domain.split(/[\s,;]+/).filter(Boolean),
});

export default function MtProto() {
  const [form, setForm] = useState<Form | null>(null);
  const [live, setLive] = useState<TgwsStatus | null>(null);
  const [installing, setInstalling] = useState(false);
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

  if (!form || !live) return <div className="flex min-w-0 flex-col gap-4"><PageHeader title="Telegram MTProto" description="Прокси на роутере с резервными путями подключения." /><Card className={compactCard}><span role="status" className="text-xs text-muted">Загрузка…</span></Card></div>;
  const native = live.native;
  const install = async () => {
    if (!native) return;
    setInstalling(true);
    try {
      const result = await api<InstallResult>("POST", "/api/system/install", { package: native.package });
      if (!result.ok) throw new Error(result.error || "Не удалось установить TG WS");
      setLive(await api<TgwsStatus>("GET", "/api/tgws"));
      toast("Модуль TG WS установлен", "ok");
    } catch (e) { toast((e as Error).message, "err"); }
    finally { setInstalling(false); }
  };
  const nativeInfo = native && (!native.installed || native.requires_go.length > 0 || native.last_error || native.vpn_fallback === false) && (
    <Card className={compactCard}>
      {!native.installed && <p>Модуль TG WS отсутствует. {native.can_install && <Button onClick={install} disabled={installing}>{installing ? "Установка…" : "Установить TG WS"}</Button>}</p>}
      {native.requires_go.length > 0 && <p>Для настроек «{native.requires_go.join(", ")}» требуется Go-версия. Для прямого WSS отключите их и сохраните настройки.</p>}
      {native.last_error && <p role="status">{native.last_error}</p>}
      {native.vpn_fallback === false && <p>Для резервного подключения через VPN обновите пакет TG WS.</p>}
    </Card>
  );
  return <MtProtoContent live={live} form={form} set={set} onToggle={toggle} onSave={save} onNewSecret={newSecret} onCopy={copy} fallback={<>{nativeInfo}<AwgFallback /></>} />;
}

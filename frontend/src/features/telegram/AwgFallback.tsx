import { useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Field, Select } from "@/components/ui/form";
import type { AwgFallbackView } from "@/types/api";

// Shared AWG2-fallback selector for the ISP-blocked Telegram DCs (1/3/5). Rendered
// on BOTH the MTProto and SOCKS5 tabs; both edit the SAME single backend setting.
export default function AwgFallback() {
  const [data, setData] = useState<AwgFallbackView | null>(null);

  usePoll(async () => {
    try {
      setData(await api<AwgFallbackView>("GET", "/api/proxy/awg-fallback"));
    } catch {
      /* keep last */
    }
  }, 5000);

  const change = async (v: string) => {
    try {
      setData(await api<AwgFallbackView>("POST", "/api/proxy/awg-fallback", { value: v }));
      toast("AWG2-фолбэк обновлён", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  if (!data) return null;
  const servers = data.servers ?? [];
  const up = data.value === "auto" ? servers.some((s) => s.connected) : servers.find((s) => s.id === data.value)?.connected;
  const status =
    data.value === "off" ? <Badge kind="neutral">выключено</Badge> : servers.length === 0 ? <Badge kind="warn">нет серверов AWG2</Badge> : up ? <Badge kind="ok">туннель поднят</Badge> : <Badge kind="bad">туннель не поднят</Badge>;

  return (
    <Card title="AWG2-фолбэк для заблокированных DC" sub="DC1/3/5 (медиа) — общий для MTProto и SOCKS5" head={status}>
      <p className="mb-3 text-xs text-muted">
        Часть дата-центров Telegram (обычно DC1/3/5, медиа) провайдер режет напрямую. Если выбран AWG2-сервер и его туннель поднят — эти DC идут через него; иначе — обычный фолбэк (Cloudflare-воркер). Настройка общая для обоих прокси.
      </p>
      <Field label="Сервер AWG2 для фолбэка" className="max-w-sm">
        <Select value={data.value} onChange={(e) => change(e.target.value)}>
          <option value="off">Выкл — обычный фолбэк (Cloudflare-воркер)</option>
          <option value="auto">Авто — первый доступный AWG2</option>
          {servers.map((s) => (
            <option key={s.id} value={s.id}>
              {s.label}
              {s.connected ? " — подключён" : ""}
            </option>
          ))}
        </Select>
      </Field>
    </Card>
  );
}

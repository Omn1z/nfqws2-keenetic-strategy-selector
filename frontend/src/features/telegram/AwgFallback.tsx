import { useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Field, Select } from "@/components/ui/form";
import type { AwgFallbackView } from "@/types/api";

// Shared tunnel selector for the ISP-blocked Telegram DCs (1/3/5). Rendered
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
      toast("Туннель для Telegram DC обновлён", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  if (!data) return null;
  const servers = data.servers ?? [];
  const awgId = data.value.startsWith("awg:") ? data.value.slice(4) : data.value;
  const awgUp = data.value === "auto" ? servers.some((s) => s.connected) : servers.find((s) => s.id === awgId)?.connected;
  const up = data.value === "auto" ? Boolean(awgUp) : awgUp;
  const hasTunnel = servers.length > 0;
  const status =
    data.value === "off" ? <Badge kind="neutral">выключено</Badge> : !hasTunnel ? <Badge kind="warn">нет туннелей</Badge> : up ? <Badge kind="ok">туннель поднят</Badge> : <Badge kind="bad">туннель не поднят</Badge>;

  return (
    <Card title="Туннель для Telegram DC" sub="DC1/3/5 — общий для MTProto и SOCKS5" head={status}>
      <p className="mb-3 text-xs text-muted">
        Часть дата-центров Telegram провайдер режет напрямую. Можно отправить их через выбранный AWG2-профиль; если туннель не поднят, прокси вернутся к обычному фолбэку.
      </p>
      <Field label="Маршрут для фолбэка" className="max-w-sm">
        <Select value={data.value} onChange={(e) => change(e.target.value)}>
          <option value="off">Выкл — обычный фолбэк (Cloudflare-воркер)</option>
          <option value="auto">Авто — доступный AWG2</option>
          {servers.map((s) => (
            <option key={s.id} value={s.id}>
              AWG2 — {s.label}
              {s.connected ? " — подключён" : ""}
            </option>
          ))}
        </Select>
      </Field>
    </Card>
  );
}

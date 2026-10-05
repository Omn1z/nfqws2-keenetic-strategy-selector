import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";
import { Field, Textarea } from "@/components/ui/form";
import { Switch } from "@/components/ui/Switch";
import type { DnsServerStatus, DnsShadowRenewResult, DnsShadowStatus } from "@/types/api";
import type { ShadowForm } from "./shadowDnsForm";
import { ShadowDnsDiagnostics } from "./ShadowDnsDiagnostics";
import { ShadowDnsRenew } from "./ShadowDnsRenew";

export function ShadowDns({ value, status, onChange, busy, onRenewBusyChange, onRefresh, onRenewResult, onDiagnosticsStatus }: { value: ShadowForm; status?: DnsShadowStatus; onChange: (value: ShadowForm) => void; busy?: boolean; onRenewBusyChange?: (busy: boolean) => boolean; onRefresh?: () => Promise<void> | void; onRenewResult?: (result: DnsShadowRenewResult) => void; onDiagnosticsStatus?: (status: DnsServerStatus) => void }) {
  const servers = status?.servers ?? [];
  const fallback = status?.enabled && status.fallback_active === true;
  const probeAt = status?.next_probe_at ? new Date(status.next_probe_at) : null;
  const probeTime = probeAt && !Number.isNaN(probeAt.getTime()) ? probeAt.toLocaleString("ru-RU", { hour12: false }) : null;
  return <Card title="Shadow DNS" sub="выбранные домены через DNS провайдера">
    <Switch checked={value.enabled} onChange={(enabled) => onChange({ ...value, enabled })} label="Shadow DNS" />
    <div className="mt-3">
      <Field label="Домены и маски"><Textarea rows={8} value={value.patterns} onChange={(e) => onChange({ ...value, patterns: e.target.value })} placeholder={"*.ru\n*.рф\n*.vk.*\n*.avito.*"} spellCheck={false} autoCapitalize="none" /></Field>
      <p className="mt-1 text-xs text-muted">По одному правилу на строку. *.example.com включает example.com и все его поддомены. Звёздочка в другой позиции заменяет одну часть имени: *.vk.* подходит для vk.com и api.vk.ru.</p>
    </div>
    <div className="mt-3 text-xs [overflow-wrap:anywhere]">
      <Badge kind={!status?.enabled ? "neutral" : status.error ? "warn" : servers.length ? "ok" : "neutral"}>DNS определяется автоматически</Badge>
      {servers.length > 0 && <p className="mt-1">DNS провайдера: <code>{servers.join(", ")}</code></p>}
      {status?.enabled && !servers.length && !status.error && <p className="mt-1 text-muted">Адреса будут проверены при первом запросе из списка.</p>}
      {status?.error && <p role="status" className="mt-1 text-warn">{status.error}</p>}
    </div>
    {fallback && <div role="status" className="mt-3 space-y-2 rounded-md border border-line p-3 text-xs [overflow-wrap:anywhere]">
      <Badge kind="warn">Резерв: DNS Server</Badge>
      <p>DNS провайдера недоступен. Запросы направляются через настроенные DNS-маршруты сервера. Если доступных маршрутов нет, запрос вернёт ошибку.</p>
      <p className="text-muted">Повторная проверка провайдера — при следующем запросе без ответа в кеше{probeTime ? <> после <time dateTime={status?.next_probe_at}>{probeTime}</time></> : ", не чаще одного раза в 30 секунд"}. После успешного ответа снова используется провайдер.</p>
    </div>}
    <ShadowDnsRenew status={status} disabled={busy} onBusyChange={onRenewBusyChange} onRefresh={onRefresh} onResult={onRenewResult} />
    <ShadowDnsDiagnostics status={status} disabled={busy} onBusyChange={onRenewBusyChange} onStatus={onDiagnosticsStatus} onRefresh={onRefresh} />
    <p className="mt-3 text-xs text-muted">Для доменов из списка DNS провайдера имеет приоритет. Если он недоступен, используются обычные DNS-маршруты сервера с учётом групп DoH, режима VPN и отключённых методов. Кеш и блокировка рекламы сохраняются.</p>
    <p className="mt-2 text-xs text-muted">Изменения списка применяются общей кнопкой «Сохранить настройки». Переключатель диагностики действует сразу.</p>
  </Card>;
}

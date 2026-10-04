import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";
import { Field, Textarea } from "@/components/ui/form";
import { Switch } from "@/components/ui/Switch";
import type { DnsShadowStatus } from "@/types/api";
import type { ShadowForm } from "./shadowDnsForm";
import { ShadowDnsDiagnostics } from "./ShadowDnsDiagnostics";

export function ShadowDns({ value, status, onChange }: { value: ShadowForm; status?: DnsShadowStatus; onChange: (value: ShadowForm) => void }) {
  const servers = status?.servers ?? [];
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
    <ShadowDnsDiagnostics status={status} />
    <p className="mt-3 text-xs text-muted">Список имеет приоритет над группами DoH. Запросы идут напрямую через WAN, кэш и блокировка рекламы сохраняются. Если DNS провайдера недоступен, автоматического перехода к DoH или VPN нет.</p>
    <p className="mt-2 text-xs text-muted">Изменения применяются общей кнопкой «Сохранить настройки».</p>
  </Card>;
}

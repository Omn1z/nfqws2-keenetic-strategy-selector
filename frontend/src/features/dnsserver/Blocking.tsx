import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field, Textarea } from "@/components/ui/form";
import { Switch } from "@/components/ui/Switch";
import { fmtNum } from "@/lib/format";
import type { DnsBlockCategory, DnsFilteringConfig, DnsFilteringStatus } from "@/types/api";

export type BlockingForm = {
  enabled: boolean;
  lists: string[];
  customRules: string;
  allowlist: string;
};

const categoryName: Record<DnsBlockCategory, string> = {
  ads: "Реклама", trackers: "Трекеры", mixed: "Реклама и трекеры",
};

export function blockingForm(config?: DnsFilteringConfig): BlockingForm {
  return {
    enabled: config?.enabled ?? false,
    lists: config?.lists ?? [],
    customRules: (config?.custom_rules ?? []).map((rule) => `${rule.category}: ${rule.domain}`).join("\n"),
    allowlist: (config?.allowlist ?? []).join("\n"),
  };
}

export function collectBlocking(form: BlockingForm): DnsFilteringConfig {
  const custom_rules: DnsFilteringConfig["custom_rules"] = [];
  for (const [index, raw] of form.customRules.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line) continue;
    const match = /^(?:(ads|trackers|mixed)\s*:\s*)?(.+)$/i.exec(line);
    const domain = match?.[2]?.trim() ?? "";
    if (!domain || /[\s:/]/.test(domain)) throw new Error(`Правило блокировки, строка ${index + 1}: укажите домен в формате ads: example.com`);
    custom_rules.push({ category: (match?.[1]?.toLowerCase() || "trackers") as DnsBlockCategory, domain });
  }
  const allowlist = form.allowlist.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const [index, domain] of allowlist.entries()) {
    if (/[\s:/]/.test(domain)) throw new Error(`Исключение, строка ${index + 1}: укажите только домен`);
  }
  return { enabled: form.enabled, lists: [...form.lists], custom_rules, allowlist };
}

const dateLabel = (value: string) => {
  if (!value) return "ещё не обновлялся";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
};

type Props = {
  value: BlockingForm;
  onChange: (value: BlockingForm) => void;
  status?: DnsFilteringStatus;
  savedEnabled: boolean;
  running: boolean;
  disabled: boolean;
  updateBusy: boolean;
  unsaved: boolean;
  onUpdate: () => void;
};

export function Blocking({ value, onChange, status, savedEnabled, running, disabled, updateBusy, unsaved, onUpdate }: Props) {
  const change = (patch: Partial<BlockingForm>) => onChange({ ...value, ...patch });
  const selected = new Set(value.lists);
  const catalog = (status?.lists ?? []).filter((item) => item.id === "adguard-dns");
  const unknown = value.lists.filter((id) => !catalog.some((item) => item.id === id));
  const ignored = status?.ignored_rules ?? 0;
  return <Card title="Блокировка рекламы и трекеров" sub="локальная проверка DNS до обращения к DoH">
    <div className="flex flex-wrap items-center gap-3">
      <Switch checked={value.enabled} onChange={(enabled) => change({ enabled })} disabled={disabled} label="Блокировать DNS-запросы" />
      <Badge kind={!running || !savedEnabled ? "neutral" : status?.ready ? "ok" : "warn"}>{!running ? "DNS-сервер выключен" : !savedEnabled ? "сейчас выключено" : status?.ready ? "блокировка действует" : "правила не готовы"}</Badge>
      <span className="text-xs text-muted">Выбор сохраняется кнопкой «Сохранить настройки» ниже.</span>
    </div>
    <p className="mt-3 text-xs text-muted">Блокировка действует для устройств, которые используют этот DNS-сервер. Запрещённый домен получает локальный ответ NXDOMAIN без обращения к внешнему DNS. Если исходный домен разрешён, фильтр также проверяет CNAME и IP в полученном ответе.</p>

    <div className="mt-4 rounded-lg border border-line p-3 text-xs">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <span>Загружено правил: <b className="tabular-nums">{fmtNum(status?.rules ?? 0)}</b>{status?.approximate ? " (приблизительно)" : ""}</span>
        <span>Последнее обновление: {dateLabel(status?.last_updated ?? "")}</span>
        {ignored > 0 && <span title="Неподдерживаемые, повторяющиеся или неиспользуемые записи; пустые строки и комментарии не считаются">Пропущено строк: {fmtNum(ignored)}</span>}
        {status?.updating && <Badge kind="neutral">Обновляются…</Badge>}
        <Button mini disabled={disabled || updateBusy || Boolean(status?.updating)} onClick={onUpdate}>{updateBusy || status?.updating ? "Обновление…" : "Обновить AdGuard"}</Button>
      </div>
      {unsaved && <p className="mt-2 text-muted">Обновление использует сохранённую настройку AdGuard. Несохранённые изменения формы сохранятся на экране.</p>}
      {status?.last_error && <p role="alert" className="mt-2 text-bad [overflow-wrap:anywhere]">Ошибка обновления: {status.last_error}</p>}
      {running && savedEnabled && !status?.ready && !status?.updating && <p className="mt-2 text-warn">Правила ещё не готовы. Проверьте настройку AdGuard и выполните обновление.</p>}
    </div>

    <h3 className="mt-5 text-sm font-semibold">Официальный фильтр AdGuard</h3>
    <p className="mt-1 text-xs text-muted">AdGuard DNS filter блокирует рекламу и трекеры. Снимите флажок, чтобы использовать только собственные правила и исключения.</p>
    <div className="mt-2 space-y-2">
      {catalog.map((item) => <div key={item.id} className="flex gap-3 rounded-lg border border-line p-3 text-xs">
        <input id={`dns-filter-${item.id}`} type="checkbox" className="mt-0.5 size-4 shrink-0 accent-accent" checked={selected.has(item.id)} disabled={disabled} onChange={(event) => change({ lists: event.target.checked ? [item.id] : [] })} />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2"><label htmlFor={`dns-filter-${item.id}`} className="cursor-pointer font-semibold text-ink-soft">{item.name}</label><Badge kind="neutral">{categoryName[item.category] ?? item.category}</Badge><span className="text-muted">{fmtNum(item.rules)} правил</span></span>
          {item.description && <span className="mt-1 block text-muted">{item.description}</span>}
          <span className="mt-1 block text-muted">Обновлён: {dateLabel(item.last_updated)}</span>
          <span className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
            {item.homepage && <a href={item.homepage} target="_blank" rel="noopener noreferrer" className="text-accent underline">Страница проекта</a>}
            {item.url && <a href={item.url} target="_blank" rel="noopener noreferrer" className="text-accent underline">Исходный список</a>}
          </span>
          {item.last_error && <span className="mt-1 block text-bad [overflow-wrap:anywhere]">Ошибка списка: {item.last_error}</span>}
        </span>
      </div>)}
      {!catalog.length && <p className="rounded-lg border border-line p-3 text-xs text-muted">Фильтр AdGuard пока недоступен. Ручные правила можно настроить ниже.</p>}
      {catalog.length > 0 && unknown.length > 0 && <p className="text-xs text-warn">Сохранённый источник отсутствует в каталоге: {unknown.join(", ")}. Измените флажок AdGuard и сохраните настройки.</p>}
    </div>

    <div className="mt-5 grid gap-4 lg:grid-cols-2">
      <Field label="Собственные правила" hint="по одному на строку">
        <Textarea rows={5} value={value.customRules} disabled={disabled} onChange={(event) => change({ customRules: event.target.value })} placeholder={"ads: ads.example.com\ntrackers: *.metrics.example.com\nmixed: tracker.example.org"} autoCapitalize="none" spellCheck={false} />
      </Field>
      <Field label="Исключения" hint="по одному домену на строку">
        <Textarea rows={5} value={value.allowlist} disabled={disabled} onChange={(event) => change({ allowlist: event.target.value })} placeholder={"example.com\n*.trusted.example.com"} autoCapitalize="none" spellCheck={false} />
      </Field>
    </div>
    <p className="mt-2 text-xs text-muted">Правило: <code>ads: domain</code>, <code>trackers: domain</code> или <code>mixed: domain</code>. Без категории используется <code>trackers</code>. Домен и его поддомены: <code>example.com</code>; только поддомены: <code>*.example.com</code>. Узкий шаблон: <code>*-netseer-ipaddr-assoc.xy.fbcdn.net</code>. Исключения указываются без категории и разрешают домен вместе с поддоменами; <code>*.example.com</code> в исключениях равнозначно <code>example.com</code>.</p>
  </Card>;
}

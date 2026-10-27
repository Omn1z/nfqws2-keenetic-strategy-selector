import { useState } from "react";
import type { ReactNode } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Switch } from "@/components/ui/Switch";
import { Field, Input, Textarea } from "@/components/ui/form";
import { PageHeader, StatsStrip, compactCard } from "@/components/ui/FeaturePage";
import { human } from "@/lib/format";
import type { TgwsStatus } from "@/types/api";
import type { Form } from "./MtProto";

export function MtProtoSummary({ live }: { live: TgwsStatus }) {
  const { connections, traffic, ws, h2 } = live.stats;
  return <StatsStrip label="Сводка MTProto" items={[
    { label: "Служба MTProto", value: live.running ? "Работает" : live.config.enabled ? "Ошибка запуска" : "Остановлена", hint: live.running ? `Порт ${live.config.port}` : live.config.enabled ? "Прокси включён в настройках" : "Прокси выключен", tone: live.running ? "ok" : live.config.enabled ? "bad" : "neutral" },
    { label: "Активные клиенты", value: connections.active, hint: `Всего соединений: ${connections.total}` },
    { label: "Трафик сессий ↓", value: traffic.human_down || human(traffic.bytes_down), hint: `↑ ${traffic.human_up || human(traffic.bytes_up)}` },
    { label: "Медиа через HTTP/2", value: connections.h2 ?? 0, hint: `TCP-соединений: ${h2?.tcp_connections ?? 0} · запросов: ${h2?.requests ?? 0}` },
    { label: "Ошибки WS", value: ws.errors, hint: `Пул WS: ${ws.pool_hits} / ${ws.pool_hits + ws.pool_misses}` },
  ]} />;
}

function StatRow({ label, children }: { label: string; children: ReactNode }) {
  return <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-t border-line-soft py-2 text-xs first:border-t-0">
    <span className="text-ink-soft">{label}</span><span className="ml-auto text-right font-medium tabular-nums [overflow-wrap:anywhere]">{children}</span>
  </div>;
}

export function MtProtoStatistics({ live }: { live: TgwsStatus }) {
  const { connections, traffic, ws, h2 } = live.stats;
  return <Card title="Метрики и статистика" sub="обновление каждые 2 с" className={compactCard}>
    <StatRow label="Соединения">{connections.total}</StatRow>
    <StatRow label="Активные">{connections.active}</StatRow>
    <StatRow label="WS / TCP-fallback / CF">{connections.ws} / {connections.tcp_fallback} / {connections.cfproxy}</StatRow>
    <StatRow label="Медиа через HTTP/2 · TCP-соединения">{connections.h2 ?? 0} · {h2?.tcp_connections ?? 0}</StatRow>
    <StatRow label="HTTP/2 запросы / повторы / ошибки">{h2?.requests ?? 0} / {h2?.replays ?? 0} / {h2?.errors ?? 0}</StatRow>
    <StatRow label="Отклонено (плохой секрет) / маскировка">{connections.bad} / {connections.masked}</StatRow>
    <StatRow label="Трафик ↑ / ↓">{traffic.human_up || human(traffic.bytes_up)} / {traffic.human_down || human(traffic.bytes_down)}</StatRow>
    <StatRow label="Пул (попаданий/всего) · ошибки WS">{ws.pool_hits}/{ws.pool_hits + ws.pool_misses} · {ws.errors}</StatRow>
    <StatRow label="Пул CF Worker (попаданий/всего)">{ws.cf_pool_hits ?? 0}/{(ws.cf_pool_hits ?? 0) + (ws.cf_pool_misses ?? 0)}</StatRow>
    <StatRow label="Соединения через резервный SNI">{connections.fronting ?? 0}</StatRow>
  </Card>;
}

const ToggleField = ({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) => <div className="flex min-h-9 min-w-0 items-center rounded-md border border-line px-2.5 py-2"><Switch checked={checked} onChange={onChange} label={label} /></div>;

export interface MtProtoContentProps {
  live: TgwsStatus;
  form: Form;
  set: <K extends keyof Form>(key: K, value: Form[K]) => void;
  onToggle: (value: boolean) => void;
  onSave: () => void;
  onNewSecret: () => void;
  onCopy: () => void;
  fallback: ReactNode;
}

export function MtProtoContent({ live, form, set, onToggle, onSave, onNewSecret, onCopy, fallback }: MtProtoContentProps) {
  const [showLink, setShowLink] = useState(false);
  const [showSecret, setShowSecret] = useState(false);
  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="Telegram MTProto" description="Прокси на роутере: подключение Telegram по WSS с резервными путями." meta={live.upstream_version ? `TG WS Proxy ${live.upstream_version}` : undefined}
      actions={<Switch checked={live.config.enabled} onChange={onToggle} label="Прокси включён" />} />
    <MtProtoSummary live={live} />

    <div className="grid min-w-0 items-start gap-4 xl:grid-cols-2">
      <Card title="Подключение Telegram" sub="ссылка содержит секрет" className={compactCard} head={<Badge kind={live.running ? "ok" : live.config.enabled ? "bad" : "neutral"}>{live.running ? "работает" : "остановлен"}</Badge>}>
        <p className="mb-3 text-xs leading-relaxed text-ink-soft">Клиенты в LAN подключаются через <code>&lt;роутер&gt;:порт</code>. Откройте ссылку на устройстве с Telegram (например, в «Избранном») — прокси добавится автоматически.</p>
        <Field label="tg:// ссылка"><div className="flex min-w-0 flex-col gap-2 sm:flex-row">
          <Input aria-label="tg:// ссылка" type={showLink ? "text" : "password"} readOnly value={live.link} className="min-w-0 font-mono text-xs" />
          <div className="flex shrink-0 flex-wrap gap-2"><Button mini variant="ghost" aria-label={showLink ? "Скрыть ссылку" : "Показать ссылку"} aria-pressed={showLink} onClick={() => setShowLink(value => !value)}>{showLink ? "Скрыть" : "Показать"}</Button><Button mini onClick={onCopy}>Копировать</Button></div>
        </div></Field>
        <p className={`mt-3 text-xs ${!live.running && live.config.enabled ? "text-bad" : "text-muted"}`} role="status">{live.running ? `Слушает порт ${live.config.port}` : live.config.enabled ? "Не удалось запустить прокси" : "Прокси выключен"}</p>
      </Card>
      <div className="min-w-0 [&>[data-slot=card]]:mb-0 [&>[data-slot=card]]:p-4 [&_[data-slot=card-header]]:mb-3 [&_[data-slot=card-title]]:text-sm [&_[data-slot=card-description]]:text-xs">{fallback}</div>
    </div>

    <div className="grid min-w-0 items-start gap-4 xl:grid-cols-[minmax(0,7fr)_minmax(300px,5fr)]">
      <Card title="Параметры и протоколы" className={compactCard}>
        <div className="flex min-w-0 flex-col gap-4">
          <section aria-label="Адрес и доступ" className="flex min-w-0 flex-col gap-3">
            <div className="grid gap-3 sm:grid-cols-[112px_minmax(0,1fr)]">
              <Field label="Порт прокси"><Input type="number" min={1} max={65535} value={form.port} onChange={event => set("port", event.target.value)} /></Field>
              <Field label="Секрет (32 hex)"><div className="flex min-w-0 flex-col gap-2 sm:flex-row">
                <Input aria-label="Секрет MTProto" type={showSecret ? "text" : "password"} readOnly value={form.secret} className="min-w-0 font-mono text-xs" />
                <div className="flex shrink-0 flex-wrap gap-2"><Button mini variant="ghost" aria-label={showSecret ? "Скрыть секрет" : "Показать секрет"} aria-pressed={showSecret} onClick={() => setShowSecret(value => !value)}>{showSecret ? "Скрыть" : "Показать"}</Button><Button mini onClick={onNewSecret}>Сгенерировать</Button></div>
              </div></Field>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Fake-TLS домен" hint="пусто = выкл."><Input value={form.fake_tls_domain} placeholder="напр. www.cloudflare.com" onChange={event => set("fake_tls_domain", event.target.value)} /></Field>
              <Field label="Хост для ссылки" hint="пусто = авто"><Input value={form.link_host} placeholder="192.168.1.1" onChange={event => set("link_host", event.target.value)} /></Field>
            </div>
          </section>
          <section aria-label="Параметры соединений" className="flex min-w-0 flex-col gap-3 border-t border-line pt-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Размер пула WS" hint="0–16"><Input type="number" min={0} max={16} value={form.pool_size} onChange={event => set("pool_size", event.target.value)} /></Field>
              <Field label="Буфер сокета (байт)"><Input type="number" min={4096} step={4096} value={form.buffer_size} onChange={event => set("buffer_size", event.target.value)} /></Field>
            </div>
            <p className="text-[11px] text-muted">Пул WS = 0 — без прямого WS, только резервные маршруты.</p>
            <Field label="DC-редиректы" hint="по строке: DC=IP (например 2=149.154.167.220)"><Textarea rows={3} value={form.dc} placeholder={"2=149.154.167.220\n4=149.154.167.220"} onChange={event => set("dc", event.target.value)} /></Field>
          </section>
          <section aria-label="Протоколы и резервные пути" className="flex min-w-0 flex-col gap-3 border-t border-line pt-4">
            <div className="grid gap-2 sm:grid-cols-2">
              <ToggleField label="CF fallback" checked={form.cfproxy} onChange={value => set("cfproxy", value)} />
              <ToggleField label="HTTP/2 для медиа через CF" checked={form.cfproxy_h2_media} onChange={value => set("cfproxy_h2_media", value)} />
              <ToggleField label="PROXY protocol" checked={form.proxy_protocol} onChange={value => set("proxy_protocol", value)} />
              <ToggleField label="Резервный SNI" checked={form.sni_fronting} onChange={value => set("sni_fronting", value)} />
              <ToggleField label="CF без TLS (порт 80)" checked={form.disable_secure} onChange={value => set("disable_secure", value)} />
              <ToggleField label="Тестовые DC Telegram" checked={form.force_test_dc} onChange={value => set("force_test_dc", value)} />
            </div>
            <div className="flex flex-col gap-2 text-[11px] leading-relaxed text-muted">
              <p>Тестовые DC нужны для тестовой среды Telegram. Для обычного аккаунта оставьте этот переключатель выключенным.</p>
              <p>HTTP/2 передаёт несколько загрузок медиа через общее соединение CF Proxy. Используется при отсутствии готового прямого WS и после CF Worker. Требует включённого CF fallback и TLS; для тестовых DC не применяется.</p>
              <p>Резервный SNI помогает при блокировке обычного TLS к Telegram. Включайте его при необходимости: некоторые фронты принимают подключение, но не передают трафик.</p>
            </div>
          </section>
          <section aria-label="Домены Cloudflare" className="grid gap-3 border-t border-line pt-4 sm:grid-cols-2">
            <Field label="Свои CF-домены" hint="По одному на строку или через запятую. Пусто — встроенный пул с автоматическим обновлением."><Textarea rows={3} value={form.cfproxy_user_domain} onChange={event => set("cfproxy_user_domain", event.target.value)} /></Field>
            <Field label="Домены CF Worker" hint="Пробуются первыми; при ошибке используется следующий. По одному на строку или через запятую."><Textarea rows={3} value={form.cfproxy_worker_domain} onChange={event => set("cfproxy_worker_domain", event.target.value)} /></Field>
          </section>
          <div className="flex flex-wrap items-center gap-2.5 border-t border-line pt-4"><Button variant="primary" onClick={onSave}>Сохранить настройки</Button><span className="text-xs text-muted">При включённом прокси сохранение перезапустит его.</span></div>
        </div>
      </Card>
      <MtProtoStatistics live={live} />
    </div>
  </div>;
}

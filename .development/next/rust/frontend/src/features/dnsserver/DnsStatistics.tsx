import { fmtNum } from "@/lib/format";
import type { DnsServerCache, DnsServerStats } from "@/types/api";
import { Card } from "@/components/ui/Card";

export function DnsStatistics({ stats, cache, variant = "default" }: { stats: DnsServerStats; cache: DnsServerCache; variant?: "default" | "dashboard" }) {
  const hitRatio = stats.queries > 0 ? Math.min(100, 100 * stats.cache_hits / stats.queries) : 0;
  if (variant === "dashboard") return <DashboardDnsStatistics stats={stats} cache={cache} hitRatio={hitRatio} />;
  const metrics = [
    { label: "Запросов", value: fmtNum(stats.queries) },
    { label: "Из кэша", value: fmtNum(stats.cache_hits), hint: `${hitRatio.toFixed(1)}% запросов` },
    { label: "Общий ответ", value: fmtNum(stats.shared_responses ?? 0), hint: "Ожидали уже выполняющийся запрос" },
    { label: "Через NFQWS", value: fmtNum(stats.nfqws_success) },
    { label: "Через AWG", value: fmtNum(stats.awg_success) },
    { label: "Shadow DNS", value: fmtNum(stats.shadow_success ?? 0), hint: "Ответов напрямую от DNS провайдера" },
    { label: "Ошибок", value: fmtNum(stats.failures) },
    { label: "Записей в кэше", value: `${fmtNum(cache.entries)} / ${fmtNum(cache.capacity)}`, hint: cache.capacity ? `Хранение до ${fmtNum(cache.ttl_seconds)} сек.` : "Кэш выключен" },
    { label: "Заблокировано", value: fmtNum(stats.blocked_total ?? 0) },
    { label: "Реклама", value: fmtNum(stats.blocked_ads ?? 0), hint: "Правила категории ads" },
    { label: "Трекеры", value: fmtNum(stats.blocked_trackers ?? 0), hint: "Правила категории trackers" },
    { label: "Реклама и трекеры", value: fmtNum(stats.blocked_mixed ?? 0), hint: "AdGuard и правила категории mixed" },
  ];
  return (
    <>
      <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-3 xl:grid-cols-5">
        {metrics.map(({ label, value, hint }) => <div key={label} className="min-w-0 rounded-lg border border-line p-3">
          <p className="text-muted">{label}</p>
          <p className="mt-1 text-lg font-semibold tabular-nums">{value}</p>
          {hint && <p className="mt-1 text-[11px] text-muted">{hint}</p>}
        </div>)}
      </div>
      <p className="mt-2 text-xs text-muted">Счётчики показывают заблокированные DNS-запросы с запуска сервера, включая блокировки CNAME и IP в ответах. AdGuard не разделяет правила на рекламу и трекеры, поэтому его блокировки входят в общий счётчик «Реклама и трекеры». Сохранение настроек DNS перезапускает сервер и сбрасывает счётчики.</p>
    </>
  );
}

function DnsRow({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 border-t border-line-soft py-1.5 text-xs first:border-t-0">
    <span className="text-ink-soft">{label}</span><b className={`ml-auto text-right tabular-nums ${warn ? "text-warn" : "text-ink"}`}>{value}</b>
  </div>;
}

function DashboardDnsStatistics({ stats, cache, hitRatio }: { stats: DnsServerStats; cache: DnsServerCache; hitRatio: number }) {
  const shared = stats.shared_responses ?? 0;
  const sharedRatio = stats.queries > 0 ? Math.min(100 - hitRatio, Math.max(0, 100 * shared / stats.queries)) : 0;
  const card = "mb-0 min-w-0 p-4 sm:p-4 [&_[data-slot=card-header]]:mb-3 [&_[data-slot=card-title]]:text-sm";
  return <>
    <div className="grid gap-3 lg:grid-cols-3">
      <Card title="Запросы и кэш" className={card} head={<span className="text-xs tabular-nums text-ink-soft">{hitRatio.toFixed(1)}% из кэша</span>}>
        <p className="mb-3 text-2xl font-semibold tabular-nums">{fmtNum(stats.queries)} <span className="text-xs font-normal text-muted">запросов</span></p>
        <div className="mb-2 flex h-1.5 overflow-hidden rounded-full bg-line-soft" aria-label={`Из кэша: ${hitRatio.toFixed(1)}% запросов`}>
          <span style={{ width: `${hitRatio}%`, background: "var(--c-accent)" }} />
          <span style={{ width: `${sharedRatio}%`, background: "var(--c-warn)" }} />
        </div>
        <DnsRow label="Из кэша" value={fmtNum(stats.cache_hits)} />
        <DnsRow label="Общий ответ" value={fmtNum(shared)} />
        <DnsRow label="Записей в кэше" value={`${fmtNum(cache.entries)} / ${fmtNum(cache.capacity)}`} />
        <p className="mt-2 text-[11px] text-muted">{cache.capacity ? `Хранение до ${fmtNum(cache.ttl_seconds)} сек.` : "Кэш выключен"} Общий ответ — ожидание уже выполняющегося запроса, отдельно от попаданий в кэш.</p>
      </Card>
      <Card title="Маршрутизация DNS" className={card}>
        <DnsRow label="Через NFQWS" value={fmtNum(stats.nfqws_success)} />
        <DnsRow label="Через AWG" value={fmtNum(stats.awg_success)} />
        <DnsRow label="Shadow DNS" value={fmtNum(stats.shadow_success ?? 0)} />
        <DnsRow label="Ошибок" value={fmtNum(stats.failures)} warn={stats.failures > 0} />
        <p className="mt-2 text-[11px] text-muted">Shadow DNS — ответы напрямую от DNS провайдера.</p>
      </Card>
      <Card title="Реклама и трекеры" className={card}>
        <p className="mb-3 text-2xl font-semibold tabular-nums">{fmtNum(stats.blocked_total ?? 0)} <span className="text-xs font-normal text-muted">заблокировано</span></p>
        <DnsRow label="Реклама · ads" value={fmtNum(stats.blocked_ads ?? 0)} />
        <DnsRow label="Трекеры · trackers" value={fmtNum(stats.blocked_trackers ?? 0)} />
        <DnsRow label="Реклама и трекеры · mixed" value={fmtNum(stats.blocked_mixed ?? 0)} />
        <p className="mt-2 text-[11px] text-muted">Блокировки CNAME и IP в ответах включены. Правила AdGuard входят в mixed и не разделяются на рекламу и трекеры.</p>
      </Card>
    </div>
    <p className="mt-2 text-[11px] text-muted">Счётчики с последнего запуска DNS-сервера. Сохранение настроек DNS перезапускает сервер и сбрасывает счётчики.</p>
  </>;
}

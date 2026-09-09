import { fmtNum } from "@/lib/format";
import type { DnsServerCache, DnsServerStats } from "@/types/api";

export function DnsStatistics({ stats, cache }: { stats: DnsServerStats; cache: DnsServerCache }) {
  const hitRatio = stats.queries > 0 ? Math.min(100, 100 * stats.cache_hits / stats.queries) : 0;
  const metrics = [
    { label: "Запросов", value: fmtNum(stats.queries) },
    { label: "Из кэша", value: fmtNum(stats.cache_hits), hint: `${hitRatio.toFixed(1)}% запросов` },
    { label: "Через NFQWS", value: fmtNum(stats.nfqws_success) },
    { label: "Через AWG", value: fmtNum(stats.awg_success) },
    { label: "Ошибок", value: fmtNum(stats.failures) },
    { label: "Записей в кэше", value: `${fmtNum(cache.entries)} / ${fmtNum(cache.capacity)}`, hint: cache.capacity ? `Хранение до ${fmtNum(cache.ttl_seconds)} сек.` : "Кэш выключен" },
  ];
  return (
    <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-3 xl:grid-cols-6">
      {metrics.map(({ label, value, hint }) => <div key={label} className="min-w-0 rounded-lg border border-line p-3">
        <p className="text-muted">{label}</p>
        <p className="mt-1 text-lg font-semibold tabular-nums">{value}</p>
        {hint && <p className="mt-1 text-[11px] text-muted">{hint}</p>}
      </div>)}
    </div>
  );
}

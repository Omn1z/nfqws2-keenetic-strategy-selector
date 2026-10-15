import { useRef, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import type { AwgRoutingDiscoveries, AwgZone } from "@/types/api";
import { matchingRoutingDiscovery, routingDiscoveryCatchAll, routingDiscoveryConfirmed, routingDiscoveryTime, visibleRoutingDiscoveries } from "./routingDiscoveriesModel";

export const readRoutingDiscoveries = (signal?: AbortSignal) => api<AwgRoutingDiscoveries>("GET", "/api/awg2/routing/discovered", undefined, { signal });

/** Snapshot reads do not participate in the editor's save lock or dirty state. */
export function useRoutingDiscoveries(active: boolean) {
  const [snapshot, setSnapshot] = useState<AwgRoutingDiscoveries | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const fetching = useRef(false);
  usePoll(async signal => {
    if (fetching.current || document.hidden || signal.aborted) return;
    fetching.current = true; setLoading(true);
    try {
      const value = await readRoutingDiscoveries(signal);
      if (!signal.aborted) { setSnapshot(value); setError(""); }
    } catch (cause) {
      if (!signal.aborted) setError((cause as Error).message);
    } finally { fetching.current = false; if (!signal.aborted) setLoading(false); }
  }, 5000, active);
  return { snapshot, error, loading };
}

export function RoutingDiscoveries({ rule, index, snapshot, loading }: { rule: AwgZone; index: number; snapshot: AwgRoutingDiscoveries | null; loading: boolean }) {
  const [showAll, setShowAll] = useState(false);
  const observed = matchingRoutingDiscovery(snapshot, rule, index);
  const entries = visibleRoutingDiscoveries(observed?.entries ?? [], showAll);
  const additionalCount = observed?.entries.filter(entry => entry.additional).length ?? 0;
  const rootsCount = (observed?.entries.length ?? 0) - additionalCount;
  const catchAll = routingDiscoveryCatchAll(rule);
  return <details className="rounded-md border border-line bg-panel-soft/30 font-sans text-[11px]">
    <summary className="cursor-pointer px-2 py-1.5 text-ink-soft">Обнаруженные маршруты ({observed ? additionalCount : "—"}) <span className="text-muted">· {rule.name || `Правило ${index + 1}`} · только чтение</span></summary>
    <div className="space-y-2 border-t border-line p-2">
      <p className="text-muted">Дополнительные имена, замеченные по DNS-запросам устройств. Исходный список правила остаётся прежним. Ранее замеченные имена повторно используются при применении правил.</p>
      {catchAll ? <p className="text-muted">Правило охватывает весь трафик; отдельные обнаруженные адресные маршруты ему не нужны.</p> : !snapshot ? <p className="text-muted">{loading ? "Загрузка наблюдений…" : "Наблюдения ещё не загружены."}</p> : !observed ? <p className="text-warn">Настройки этого правила отличаются от снимка роутера. Наблюдения появятся после сохранения и обновления снимка.</p> : <>
        {rootsCount > 0 && <Button mini variant="ghost" aria-pressed={showAll} onClick={() => setShowAll(current => !current)}>{showAll ? "Только дополнительные поддомены" : `Показать также исходные домены (${rootsCount})`}</Button>}
        {!entries.length && <p className="text-muted">{showAll ? "Наблюдений пока нет." : "Дополнительные поддомены пока не обнаружены."} Они появятся после DNS-запросов к именам, подходящим этому правилу.</p>}
        <div className="grid max-h-72 grid-cols-1 gap-2 overflow-y-auto sm:grid-cols-2">{entries.map((entry, entryIndex) => {
          const seen = routingDiscoveryTime(entry.last_seen);
          const confirmed = routingDiscoveryConfirmed(snapshot, entry);
          return <div key={`${entry.source}:${entry.domain}:${entry.source_ips.join(",")}:${entryIndex}`} className="min-w-0 space-y-1 rounded border border-line bg-panel p-2 [overflow-wrap:anywhere]">
            <div className="flex flex-wrap items-center gap-1.5"><code className="min-w-0 flex-1 font-medium">{entry.domain}</code><Badge kind={confirmed ? "ok" : "neutral"}>{confirmed ? "Подтверждён" : "История"}</Badge><span className="text-muted">{entry.source === "sni" ? "SNI" : "DNS · A/AAAA"}</span></div>
            <p className="font-mono text-ink-soft">{entry.ips.length ? entry.ips.join(", ") : "IP не получены"}</p>
            {entry.source_ips.length > 0 && <p className="text-muted">Источники LAN: <code>{entry.source_ips.join(", ")}</code></p>}
            <p className="text-muted">Замечен: <time dateTime={seen.dateTime}>{seen.label}</time></p>
          </div>;
        })}</div>
        {!!observed.entries.length && <p className="text-muted">Статусы относятся к последнему снимку роутера. «Подтверждён» — маршрут подтверждён в работающей конфигурации. «История» — адрес был замечен ранее; текущий маршрут не подтверждён.{snapshot.limit > 0 && <> Хранится до {snapshot.limit} наблюдений.</>}</p>}
      </>}
    </div>
  </details>;
}

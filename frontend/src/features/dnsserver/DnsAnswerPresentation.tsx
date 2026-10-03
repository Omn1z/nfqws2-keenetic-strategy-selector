import { Badge } from "@/components/ui/Badge";
import type { DnsServerStats, DnsServerTestResult } from "@/types/api";
import { DnsRequestOrigin } from "./DnsRequestOrigin";

export const DNS_CACHE_NOTE = "Повторный запрос к провайдеру не выполнялся.";
export const DNS_SHARED_NOTE = "Ожидал уже выполняющийся такой же запрос; отдельное обращение к провайдеру не выполнялось.";
type RouteName = (id: string) => string;

function ReusedAnswerOrigin({ route, upstream, routeName }: { route?: string; upstream?: string; routeName: RouteName }) {
  if ((!route || route === "cache") && !upstream) return null;
  return <details className="mt-2 text-muted">
    <summary className="cursor-pointer">Первичный источник</summary>
    <div className="mt-1 space-y-1 [overflow-wrap:anywhere]">
      {upstream && <p>DNS-провайдер первичного запроса: {upstream}</p>}
      {route && route !== "cache" && <p>Маршрут первичного запроса: {routeName(route)}</p>}
    </div>
  </details>;
}

export function DnsLastRequest({ stats, routeName }: { stats: DnsServerStats; routeName: RouteName }) {
  if (!stats.last_domain) return null;
  const reused = stats.last_cached || stats.last_shared;
  return <div className="mt-2 text-xs text-muted [overflow-wrap:anywhere]">
    <p>Последний запрос: {stats.last_domain}{reused ? <> · <b className="text-accent">{stats.last_cached ? "Из кэша" : "Общий ответ"}</b></>
      : <> · {routeName(stats.last_route || "")} · {stats.last_upstream || "—"}</>}</p>
    <DnsRequestOrigin source={stats.last_source} clientIP={stats.last_client_ip} transport={stats.last_transport} />
    {reused && <>
      <p className="mt-1">{stats.last_cached ? DNS_CACHE_NOTE : DNS_SHARED_NOTE}</p>
      <ReusedAnswerOrigin route={stats.last_route} upstream={stats.last_upstream} routeName={routeName} />
    </>}
  </div>;
}

export function DnsTestAnswer({ result: test, routeName }: { result: DnsServerTestResult; routeName: RouteName }) {
  const cached = test.cached && test.ok && !test.blocked && !test.error;
  const shared = !cached && test.shared && test.ok && !test.blocked && !test.error;
  return <div role="status" className="mt-3 rounded-lg border border-line p-3 text-xs">
    <div className="flex flex-wrap items-center gap-2">
      <Badge kind={test.blocked ? "warn" : test.ok ? "ok" : "bad"}>{test.blocked ? "Заблокировано локально" : cached ? "Из кэша" : shared ? "Общий ответ" : test.ok ? "Ответ получен" : "Ошибка"}</Badge>
      <span>{test.domain} · {test.type} · {Math.round(test.duration_ms)} мс</span>
      <DnsRequestOrigin source={test.source} clientIP={test.client_ip} transport={test.transport} />
    </div>
    {test.blocked ? <p className="mt-2 [overflow-wrap:anywhere]">Ответ NXDOMAIN сформирован локально.{test.block_domain && test.block_domain !== test.domain ? ` В ответе DNS заблокирован адрес: ${test.block_domain}.` : ""}{test.block_category ? ` Категория: ${test.block_category === "ads" ? "реклама" : test.block_category === "mixed" ? "реклама и трекеры" : "трекеры"}` : ""}{test.block_source ? ` · Источник: ${test.block_source}` : ""}{test.block_rule ? ` · Правило: ${test.block_rule}` : ""}</p>
      : cached || shared ? <>
        <p className="mt-2">{cached ? DNS_CACHE_NOTE : DNS_SHARED_NOTE}</p>
        <ReusedAnswerOrigin route={test.route} upstream={test.upstream} routeName={routeName} />
      </> : <p className="mt-2 [overflow-wrap:anywhere]">Маршрут: {routeName(test.route)} · DNS: {test.upstream || "—"}</p>}
    {test.answers?.length > 0 && <pre className="mt-2 whitespace-pre-wrap font-mono text-xs [overflow-wrap:anywhere]">{test.answers.join("\n")}</pre>}
    {test.error && !test.blocked && <p className="mt-2 text-bad [overflow-wrap:anywhere]">{test.error}</p>}
  </div>;
}

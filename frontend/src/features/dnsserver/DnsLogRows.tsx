import type { DnsServerLogEntry } from "@/types/api";
import { cancellationChips, compactLogMessage, groupLogRows, isCacheEvent, isSharedEvent, isLogProblem, logCount, logEventPresentation, shortProvider } from "./dnsLogPresentation";
import { DNS_CACHE_NOTE, DNS_SHARED_NOTE } from "./DnsAnswerPresentation";
import { DnsRequestOrigin, DnsRequestOriginDetails } from "./DnsRequestOrigin";

const clock = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString("ru-RU", { hour12: false });
};
const fullTime = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
};
const tones = { ok: "text-ok", accent: "text-accent", muted: "text-muted", bad: "text-bad", warn: "text-warn" };

function EntryTime({ entry }: { entry: DnsServerLogEntry }) {
  return <time className="shrink-0 text-muted tabular-nums" dateTime={entry.time} title={fullTime(entry.time)}>{clock(entry.time)}</time>;
}

function EntryDetails({ entry, routeName }: { entry: DnsServerLogEntry; routeName: (id: string) => string }) {
  const cached = isCacheEvent(entry);
  const shared = isSharedEvent(entry);
  const reused = cached || shared;
  return <div className="flex flex-wrap gap-x-3 gap-y-1 text-muted [overflow-wrap:anywhere]">
    <span>{fullTime(entry.time)}</span>
    <DnsRequestOriginDetails source={entry.source} clientIP={entry.client_ip} transport={entry.transport} />
    {reused && <span>{cached ? DNS_CACHE_NOTE : DNS_SHARED_NOTE}</span>}
    {entry.route && entry.route !== "cache" && <span>{reused ? "Маршрут первичного запроса" : "Маршрут"}: {routeName(entry.route)}{routeName(entry.route) !== entry.route ? ` (${entry.route})` : ""}</span>}
    {entry.upstream && <span>{reused ? "Первичный источник" : "DNS-провайдер"}: {entry.upstream}</span>}
    {entry.duration_ms !== undefined && <span>{Math.round(entry.duration_ms)} мс</span>}
    {entry.block_category && <span>Категория: {entry.block_category === "ads" ? "реклама" : entry.block_category === "mixed" ? "реклама и трекеры" : "трекеры"}</span>}
    {entry.block_source && <span>Источник: {entry.block_source}</span>}
    {entry.block_rule && <span>Правило: {entry.block_rule}</span>}
    {entry.block_domain && entry.block_domain !== entry.domain && <span>Заблокировано в ответе DNS: {entry.block_domain}</span>}
  </div>;
}

function EventRow({ entry, routeName }: { entry: DnsServerLogEntry; routeName: (id: string) => string }) {
  const meta = logEventPresentation(entry);
  const message = compactLogMessage(entry);
  const problem = isLogProblem(entry);
  const cached = isCacheEvent(entry);
  const reused = cached || isSharedEvent(entry);
  const hasDetails = Boolean(reused || entry.upstream || entry.route || entry.source || entry.client_ip || entry.transport || entry.block_category || entry.block_source || entry.block_rule);
  const content = <>
    <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
      <EntryTime entry={entry} />
      <span className={`w-4 shrink-0 text-center font-semibold ${tones[meta.tone]}`} title={meta.label} aria-label={meta.label}>{meta.symbol}</span>
      {entry.domain ? <><span className="font-semibold text-ink-soft">{entry.domain}</span>{entry.qtype && <span className="text-muted">{entry.qtype}</span>}</> : <span className={tones[meta.tone]}>{meta.label}</span>}
      {entry.count !== undefined && <span className="text-muted">×{logCount(entry)}</span>}
      <DnsRequestOrigin source={entry.source} clientIP={entry.client_ip} transport={entry.transport} />
      {reused && entry.domain && <span className="rounded bg-line-soft px-1.5 text-accent">{meta.label}</span>}
      {!reused && entry.upstream && <span className="min-w-0 text-muted" title={entry.upstream}>{shortProvider(entry.upstream)}</span>}
      {!reused && entry.route && entry.route !== "cache" && entry.route !== "blocked" && <span className="rounded bg-line-soft px-1.5 text-ink-soft" title={entry.route}>{routeName(entry.route)}</span>}
      {entry.event === "blocked" && <span className="text-warn">{entry.block_category === "ads" ? "реклама" : entry.block_category === "mixed" ? "реклама и трекеры" : entry.block_category === "trackers" ? "трекеры" : "локально"}{entry.block_source ? ` · ${entry.block_source}` : ""}{entry.block_rule ? ` · ${entry.block_rule}` : ""}</span>}
      {entry.duration_ms !== undefined && <span className="ml-auto shrink-0 text-muted tabular-nums">{Math.round(entry.duration_ms)} мс</span>}
      {hasDetails && <><span className="text-[10px] text-muted group-open:hidden" aria-hidden="true">⌄</span><span className="hidden text-[10px] text-muted group-open:inline" aria-hidden="true">⌃</span></>}
    </div>
    {message && <p className={`mt-0.5 whitespace-pre-wrap pl-[5.7rem] ${problem ? tones[meta.tone] : "text-ink-soft"}`}>{message}</p>}
  </>;
  const className = "group border-b border-line/60 py-1 last:border-0 [overflow-wrap:anywhere]";
  return hasDetails ? <details className={className}>
    <summary className="cursor-pointer list-none [&::-webkit-details-marker]:hidden" title="Показать подробности DNS-события">{content}</summary>
    <div className="mt-1 border-l border-line pl-3"><EntryDetails entry={entry} routeName={routeName} /></div>
  </details> : <div className={className}>{content}</div>;
}

function CancellationRow({ entries, routeName }: { entries: DnsServerLogEntry[]; routeName: (id: string) => string }) {
  const count = entries.reduce((total, entry) => total + logCount(entry), 0);
  const chips = cancellationChips(entries);
  return <details className="group border-b border-line/60 py-1 text-muted last:border-0">
    <summary className="flex cursor-pointer list-none flex-wrap items-baseline gap-x-2 gap-y-1 [&::-webkit-details-marker]:hidden" title="Показать время и подробности отмен">
      <EntryTime entry={entries[0]} />
      <span className="w-4 shrink-0 text-center" title="Отмены без штрафа" aria-label={`Отмены без штрафа: ${count}`}>⊘</span>
      {chips.map((chip) => <span key={JSON.stringify([chip.domain, chip.qtype])} className="inline-flex items-baseline gap-1 rounded border border-line px-1.5" title={`${fullTime(chip.firstTime)}${chip.lastTime !== chip.firstTime ? ` — ${fullTime(chip.lastTime)}` : ""} · ${chip.domain || "запрос"} ${chip.qtype} · отмен: ${chip.count}${chip.queries > 1 ? ` · запросов: ${chip.queries}` : ""}`}>
        <span>{chip.domain || "запрос"}</span>{chip.qtype && <span className="text-[10px]">{chip.qtype}</span>}<span className="font-semibold tabular-nums">×{chip.count}</span>
      </span>)}
      <span className="ml-auto text-[10px] group-open:hidden" aria-hidden="true">⌄</span><span className="ml-auto hidden text-[10px] group-open:inline" aria-hidden="true">⌃</span>
    </summary>
    <div className="mt-2 space-y-1 border-l border-line pl-3">
      {entries.map((entry) => <div key={entry.id}><span className="text-ink-soft">{entry.domain || "Запрос"} {entry.qtype} · ⊘ ×{logCount(entry)}</span><EntryDetails entry={entry} routeName={routeName} /></div>)}
    </div>
  </details>;
}

export function DnsLogRows({ entries, routeName }: { entries: DnsServerLogEntry[]; routeName: (id: string) => string }) {
  return groupLogRows(entries).map((row) => row.kind === "cancellations"
    ? <CancellationRow key={`cancel-${row.entries[0].id}`} entries={row.entries} routeName={routeName} />
    : <EventRow key={row.entry.id} entry={row.entry} routeName={routeName} />);
}

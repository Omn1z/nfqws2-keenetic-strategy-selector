import type { DnsServerLogEntry } from "@/types/api";

const cancellationEvents = new Set(["cancel", "canceled", "cancelled", "attempt_cancelled"]);
const cacheEvents = new Set(["cache", "cache_hit"]);

export const isLogProblem = (entry: DnsServerLogEntry) => entry.level === "error" || entry.level === "warn" || ["error", "failure", "attempt_error"].includes(entry.event);
export const isCancellation = (entry: DnsServerLogEntry) => cancellationEvents.has(entry.event);
export const logCount = (entry: DnsServerLogEntry) => Number.isSafeInteger(entry.count) && (entry.count ?? 0) > 0 ? entry.count! : 1;

export function compactLogMessage(entry: DnsServerLogEntry): string {
  const message = entry.message ?? "";
  if (isLogProblem(entry)) return message;
  if (isCancellation(entry) && message === "Попытка отменена; штраф планировщика не начисляется") return "";
  if (cacheEvents.has(entry.event) && message === "Ответ из DNS-кэша") return "";
  if (["answer", "success"].includes(entry.event) && message === "Первый успешный ответ возвращён клиенту") return "";
  if (entry.event === "attempt_success" && message === "Получен корректный ответ DNS") return "";
  return message;
}

export function shortProvider(address: string): string {
  try { return new URL(address).host; } catch { return address; }
}

export function matchesLogFilter(entry: DnsServerLogEntry, query: string, routeName: (id: string) => string = (id) => id): boolean {
  const meta = logEventPresentation(entry);
  return [entry.domain, entry.qtype, entry.route, entry.route ? routeName(entry.route) : "", entry.upstream, entry.message, entry.event, meta.label, meta.symbol]
    .filter(Boolean).join(" ").toLowerCase().includes(query.trim().toLowerCase());
}

type EventPresentation = { symbol: string; label: string; tone: "ok" | "accent" | "muted" | "bad" | "warn" };
export function logEventPresentation(entry: DnsServerLogEntry): EventPresentation {
  if (isLogProblem(entry)) return { symbol: "!", label: entry.event === "attempt_error" ? "Ошибка маршрута" : "Ошибка", tone: entry.level === "warn" ? "warn" : "bad" };
  if (isCancellation(entry)) return { symbol: "⊘", label: "Отмена без штрафа", tone: "muted" };
  if (cacheEvents.has(entry.event)) return { symbol: "⚡", label: "Из кэша", tone: "accent" };
  if (["answer", "success", "attempt_success"].includes(entry.event)) return { symbol: "✓", label: entry.event === "attempt_success" ? "Ответ маршрута" : "Ответ", tone: "ok" };
  if (entry.event === "cache_clear") return { symbol: "↺", label: "Кэш очищен", tone: "accent" };
  const labels: Record<string, string> = { query: "Запрос", attempt: "Попытка", attempt_start: "Запуск попытки", start: "Запуск", stop: "Остановка", logging: "Журнал", config: "Настройки", service: "Сервис" };
  return { symbol: "·", label: labels[entry.event] || entry.event || entry.level, tone: "muted" };
}

export type DnsLogRow = { kind: "entry"; entry: DnsServerLogEntry } | { kind: "cancellations"; entries: DnsServerLogEntry[] };

export type CancellationChip = { domain: string; qtype: string; count: number; queries: number; firstTime: string; lastTime: string };
export function cancellationChips(entries: DnsServerLogEntry[]): CancellationChip[] {
  const chips = new Map<string, CancellationChip>();
  for (const entry of entries) {
    const domain = entry.domain ?? "";
    const qtype = entry.qtype ?? "";
    const key = JSON.stringify([domain, qtype]);
    const chip = chips.get(key);
    if (chip) { chip.count += logCount(entry); chip.queries++; chip.lastTime = entry.time; }
    else chips.set(key, { domain, qtype, count: logCount(entry), queries: 1, firstTime: entry.time, lastTime: entry.time });
  }
  return [...chips.values()];
}

export function groupLogRows(entries: DnsServerLogEntry[]): DnsLogRow[] {
  const rows: DnsLogRow[] = [];
  for (const entry of entries) {
    if (isCancellation(entry) && !isLogProblem(entry) && !compactLogMessage(entry)) {
      const previous = rows.at(-1);
      if (previous?.kind === "cancellations") previous.entries.push(entry);
      else rows.push({ kind: "cancellations", entries: [entry] });
    } else rows.push({ kind: "entry", entry });
  }
  return rows;
}

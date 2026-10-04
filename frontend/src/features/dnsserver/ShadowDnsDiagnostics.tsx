import { useEffect, useRef, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import type { DnsShadowDiagnosticAttempt, DnsShadowStatus } from "@/types/api";
import { copyShadowDiagnostics, downloadShadowDiagnostics, latestShadowAttempt, shadowDiagnosticState } from "./shadowDiagnosticsReport";

function timestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU", { hour12: false });
}

function AttemptTimeline({ attempt }: { attempt: DnsShadowDiagnosticAttempt }) {
  return <div className="space-y-2 [overflow-wrap:anywhere]">
    <p className="text-muted">Начало: <time dateTime={attempt.started_at}>{timestamp(attempt.started_at)}</time> · {Math.round(attempt.duration_ms)} мс{attempt.finished_at ? " · завершено" : " · выполняется"}</p>
    {attempt.error && <p className="text-warn">{attempt.error}</p>}
    {attempt.servers.length > 0 && <p>Найдены DNS: <code>{attempt.servers.join(", ")}</code></p>}
    <ol className="space-y-3 border-l border-line pl-3">
      {attempt.events.map((event, index) => <li key={index}>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-muted">
          <time dateTime={event.at} title={event.at}>{timestamp(event.at)}</time>
          <code className="text-[11px]">{event.stage}</code>
          {event.duration_ms !== undefined && <span>{Math.round(event.duration_ms)} мс</span>}
        </div>
        <p className="mt-0.5 whitespace-pre-wrap">{event.message}</p>
      </li>)}
    </ol>
    {!attempt.events.length && <p className="text-muted">События ещё не записаны.</p>}
  </div>;
}

export function ShadowDnsDiagnostics({ status }: { status?: DnsShadowStatus }) {
  const [open, setOpen] = useState(!!status?.error);
  const expandedForError = useRef(!!status?.error);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const trace = status?.diagnostics;
  const latest = latestShadowAttempt(status);
  const state = shadowDiagnosticState(status);
  useEffect(() => {
    if (status?.error && !expandedForError.current) {
      setOpen(true); expandedForError.current = true;
    }
  }, [status?.error]);

  // Older servers keep the existing status UI; no speculative API requests.
  if (!trace) return null;

  const exportReport = async (copy: boolean) => {
    if (!status || busy) return;
    setBusy(true); setNotice("");
    try {
      if (copy) {
        const result = await copyShadowDiagnostics(status);
        setNotice(result === "copied" ? "Отчёт скопирован — его можно отправить для диагностики." : "Буфер обмена недоступен. Отчёт сохранён в JSON-файл — его можно отправить для диагностики.");
      } else {
        downloadShadowDiagnostics(status);
        setNotice("Отчёт сохранён в JSON-файл.");
      }
    } catch (error) {
      setNotice(`Не удалось сохранить отчёт: ${(error as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  return <details open={open} onToggle={(event) => setOpen(event.currentTarget.open)} className="mt-3 rounded-md border border-line text-xs">
    <summary className="cursor-pointer px-3 py-2 font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">Диагностика Shadow DNS</summary>
    <div className="space-y-3 border-t border-line p-3">
      <div className="flex flex-wrap items-center gap-2" role="status">
        <Badge kind={state === "failed" || state === "waiting" ? "warn" : state === "success" ? "ok" : "neutral"}>
          {state === "running" ? "Поиск DNS выполняется" : state === "waiting" ? "Ожидание повторной попытки" : state === "failed" ? "Последняя попытка не удалась" : state === "success" ? "DNS обнаружены" : "Попыток ещё нет"}
        </Badge>
        {latest && <span className="text-muted">Последняя попытка: <time dateTime={latest.started_at}>{timestamp(latest.started_at)}</time></span>}
      </div>
      <p className="text-muted [overflow-wrap:anywhere]">Снимок: <time dateTime={trace.captured_at}>{timestamp(trace.captured_at)}</time>{trace.app_version && <> · {trace.app_version}</>}{trace.platform && <> · {trace.platform}</>}</p>
      {state === "running" && status?.error && <p className="text-muted">Ошибка выше относится к предыдущей попытке. Текущий поиск ещё не завершён.</p>}
      {state === "waiting" && latest?.next_retry_at && <p className="text-muted">Сейчас используется результат предыдущей попытки. Новый поиск возможен с <time dateTime={latest.next_retry_at}>{timestamp(latest.next_retry_at)}</time> при следующем запросе к домену из списка Shadow DNS.</p>}
      {state === "failed" && <p className="text-muted">Это результат последней попытки. Следующий запрос к домену из списка Shadow DNS повторит поиск.</p>}
      {state === "empty" && <p className="text-muted">История появится после первого запроса к домену из списка Shadow DNS.</p>}
      <p className="text-muted">Отчёт содержит этапы поиска и сведения об обмене DHCP, включая сетевые адреса. Открытие и копирование отчёта не запускают проверку и не меняют WAN.</p>
      <div className="flex flex-wrap gap-2">
        <Button mini disabled={busy} onClick={() => { void exportReport(true); }}>Скопировать диагностику</Button>
        <Button mini disabled={busy} onClick={() => { void exportReport(false); }}>Скачать JSON</Button>
      </div>
      {notice && <p role="status" className="text-muted [overflow-wrap:anywhere]">{notice}</p>}
      {latest && <div className="max-h-96 overflow-y-auto rounded-md border border-line p-3"><AttemptTimeline attempt={latest} /></div>}
      {trace.attempts.length > 1 && <details className="border-t border-line pt-2">
        <summary className="cursor-pointer text-muted">Предыдущие попытки ({trace.attempts.length - 1})</summary>
        <div className="mt-3 max-h-96 space-y-3 overflow-y-auto">
          {trace.attempts.slice(0, -1).reverse().map((attempt) => <div key={attempt.id} className="rounded-md border border-line p-3"><AttemptTimeline attempt={attempt} /></div>)}
        </div>
      </details>}
    </div>
  </details>;
}

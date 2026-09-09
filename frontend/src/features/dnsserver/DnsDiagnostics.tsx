import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field, Input } from "@/components/ui/form";
import { Switch } from "@/components/ui/Switch";
import { toast } from "@/components/ui/Toast";
import type { DnsServerLogSnapshot, DnsServerSchedulerSnapshot, DnsServerStatus } from "@/types/api";
import { DnsLogRows } from "./DnsLogRows";
import { isLogProblem, matchesLogFilter } from "./dnsLogPresentation";

const duration = (v: number) => `${Math.round(v)} мс`;
const clock = (v: string) => {
  const date = new Date(v);
  return Number.isNaN(date.getTime()) ? v : date.toLocaleTimeString("ru-RU", { hour12: false });
};
function SchedulerTime({ value }: { value?: string }) {
  if (!value) return <>—</>;
  const date = new Date(value);
  return <time dateTime={value} title={Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU")}>{clock(value)}</time>;
}

function SchedulerPanel({ running }: { running: boolean }) {
  const [mode, setMode] = useState<"general" | "domain">("general");
  const [input, setInput] = useState("");
  const [domain, setDomain] = useState("");
  const [snapshot, setSnapshot] = useState<DnsServerSchedulerSnapshot | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const requested = useRef({ query: "" as string | null, revision: 0, fetching: false });
  const refresh = async () => {
    const request = requested.current;
    if (request.fetching || request.query === null || document.hidden) return;
    request.fetching = true; setLoading(true);
    try {
      const path = request.query ? `/api/dnsserver/scheduler?domain=${encodeURIComponent(request.query)}` : "/api/dnsserver/scheduler";
      const result = await api<DnsServerSchedulerSnapshot>("GET", path);
      if (request.revision === requested.current.revision) { setSnapshot(result); setError(""); }
    } catch (e) { if (request.revision === requested.current.revision) setError((e as Error).message); }
    finally {
      if (request.revision === requested.current.revision) { request.fetching = false; setLoading(false); }
    }
  };
  usePoll(refresh, 5000);
  const selectView = (query: string | null) => {
    requested.current = { query, revision: requested.current.revision + 1, fetching: false };
    setSnapshot(null); setError(""); setLoading(false);
    void refresh();
  };
  const changeMode = (next: "general" | "domain") => {
    if (next === mode) return;
    setMode(next);
    selectView(next === "general" ? "" : domain || null);
  };
  const inspect = () => {
    const next = input.trim();
    if (!next) return;
    if (next === domain) void refresh();
    else { setDomain(next); selectView(next); }
  };
  return <Card title="Планировщик DNS" sub="очередь сочетаний маршрута и DoH по сохранённым настройкам">
    <p className="mb-3 text-xs text-muted">Чем больше очков, тем выше приоритет. Быстрые успешные ответы поднимают сочетание в очереди, ошибки и серии неудач опускают его. Приоритет определяет порядок запуска параллельных попыток: готовый ответ не ждёт остальных.</p>
    <div className="mb-3 flex flex-wrap gap-2" role="group" aria-label="Режим планировщика">
      <Button mini variant={mode === "general" ? "primary" : "default"} aria-pressed={mode === "general"} onClick={() => changeMode("general")}>Общий</Button>
      <Button mini variant={mode === "domain" ? "primary" : "default"} aria-pressed={mode === "domain"} onClick={() => changeMode("domain")}>По домену</Button>
    </div>
    {mode === "general" && <p className="text-xs text-muted">Общий планировщик: пул по умолчанию. Оценки сочетаний DoH и маршрутов учитывают результаты запросов к разным доменам.</p>}
    {mode === "domain" && <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); inspect(); }}>
      <Field label="Домен для выбора пула" className="min-w-[180px] flex-1"><Input value={input} onChange={(e) => setInput(e.target.value)} placeholder="claude.ai" autoCapitalize="none" spellCheck={false} /></Field>
      <Button type="submit" disabled={loading || !input.trim()}>{loading ? "Обновление…" : "Показать очередь"}</Button>
    </form>}
    {error && <p role="alert" className="mt-3 text-xs text-bad">Не удалось обновить планировщик: {error}{snapshot ? ". Показано последнее полученное состояние." : ""}</p>}
    {!snapshot && !error && <p className="mt-3 text-xs text-muted">{mode === "domain" && !domain ? "Введите домен и нажмите «Показать очередь», чтобы увидеть подходящий ему пул." : loading ? "Загрузка планировщика…" : "Ожидание обновления планировщика…"}</p>}
    {snapshot && <>
      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs"><Badge kind="neutral">{snapshot.pool_source === "default" ? "Пул по умолчанию" : `Пул: ${snapshot.pool_source}`}</Badge><span className="text-muted">{mode === "general" ? "Общий планировщик" : snapshot.domain} · Вариантов: {snapshot.candidates.length} · Одновременно: до {snapshot.parallel_limit}</span>{snapshot.active_probes !== undefined && <Badge kind="neutral">Фоновых замеров: {snapshot.active_probes}</Badge>}</div>
      {snapshot.formula && <div className="mt-3 rounded-lg border border-line p-3 text-xs"><p className="mb-1 font-semibold text-ink-soft">Расчёт очков</p><p className="whitespace-pre-wrap [overflow-wrap:anywhere]">{snapshot.formula}</p></div>}
      <div className="mt-3 max-h-[34rem] overflow-auto rounded-lg border border-line">
        <table className="w-full min-w-[1040px] text-left text-xs">
          <thead className="sticky top-0 z-10 bg-card text-muted"><tr>{["Место / маршрут", "DoH", "Очки", "Задержка", "Успешность", "Попытки / ошибки", "Фоновые замеры"].map((label) => <th key={label} className="border-b border-line px-3 py-2 font-semibold">{label}</th>)}</tr></thead>
          <tbody>{snapshot.candidates.map((v) => <tr key={`${v.route}\n${v.upstream}`} className="border-b border-line last:border-0">
            <td className="px-3 py-3 align-top"><div className="flex items-center gap-2"><span className="font-semibold tabular-nums">{v.position}.</span><span className="font-semibold">{v.route_name || v.route}</span></div><div className="mt-2"><Badge kind={!v.available ? "warn" : v.successes + v.failures === 0 ? "neutral" : "ok"}>{!v.available ? "недоступен" : v.successes + v.failures === 0 ? "нет замеров" : "доступен"}</Badge></div>{v.exploration && <p className="mt-1 text-muted" title="Повышен приоритет запуска в следующем параллельном запросе">Приоритет проверки</p>}</td>
            <td className="max-w-64 px-3 py-3 align-top"><code className="[overflow-wrap:anywhere]">{v.upstream}</code>{v.last_error && <p className="mt-2 text-bad [overflow-wrap:anywhere]">{v.last_error}</p>}</td>
            <td className="px-3 py-3 align-top tabular-nums"><p className="text-base font-semibold">{v.score.toFixed(1)}</p><p className="mt-1 text-muted">За задержку: −{v.latency_penalty.toFixed(1)}</p><p className="mt-1 text-muted">За ошибки: −{v.failure_penalty.toFixed(1)}</p></td>
            <td className="px-3 py-3 align-top tabular-nums">{duration(v.latency_ms)}<p className="mt-1 text-muted">{v.successes > 0 ? "сглаженная" : "начальная оценка"}</p></td>
            <td className="px-3 py-3 align-top tabular-nums">{(v.reliability * 100).toFixed(1)}%<p className="mt-1 text-muted">{v.successes + v.failures === 0 ? "начальная оценка" : `Ответов: ${v.successes}`}</p></td>
            <td className="px-3 py-3 align-top tabular-nums"><p>{v.attempts} / <span className={v.failures ? "text-warn" : ""}>{v.failures}</span></p><p className="mt-1 text-muted">Неудач подряд: {v.consecutive_failures}</p><p className="mt-1 text-muted" title="Последний завершённый замер: ответ или ошибка. Отмена это время не обновляет.">Результат: <SchedulerTime value={v.last_result_at} /></p>{v.last_attempt_at && <p className="mt-1 text-muted" title="Последний запуск, в том числе отменённый после победы другого варианта">Запуск: <SchedulerTime value={v.last_attempt_at} /></p>}</td>
            <td className="px-3 py-3 align-top tabular-nums"><Badge kind={v.probing ? "ok" : "neutral"}>{v.probing ? "измеряется" : !running ? "остановлены" : !v.available ? "нет маршрута" : "ожидание"}</Badge><p className="mt-2 text-muted" title="Последний запуск независимого фонового замера">Запуск: <SchedulerTime value={v.last_probe_at} /></p><p className="mt-1 text-muted" title="Завершённые фоновые замеры">✓ {v.probe_successes ?? 0} · <span className={(v.probe_failures ?? 0) > 0 ? "text-warn" : ""}>! {v.probe_failures ?? 0}</span><span className="sr-only"> — успешных и неудачных замеров</span></p></td>
          </tr>)}</tbody>
        </table>
        {!snapshot.candidates.length && <p className="p-4 text-xs text-muted">{mode === "general" ? "В пуле по умолчанию пока нет вариантов маршрута и DoH." : "Для выбранного домена пока нет вариантов маршрута и DoH."}</p>}
      </div>
      <p className="mt-3 text-xs text-muted">{snapshot.probe_interval_seconds && snapshot.probe_recheck_seconds ? `Фоновая очередь проверяется каждые ${snapshot.probe_interval_seconds} с: сначала варианты без замеров, затем без нового результата ${snapshot.probe_recheck_seconds} с и дольше. ` : ""}Фоновый замер дожидается ответа или ошибки независимо от победителя основного запроса. Отмена не обновляет время результата и не начисляет штраф. Оценки хранятся в памяти; перезапуск панели сбрасывает обучение.</p>
    </>}
    {!running && <p className="mt-3 text-xs text-muted">DNS-сервер не работает. Фоновые замеры возобновятся после запуска.</p>}
  </Card>;
}

type Props = { loggingEnabled: boolean; running: boolean; routes: DnsServerStatus["routes"]; onLoggingChange: (enabled: boolean) => void };
export function DnsDiagnostics({ loggingEnabled, running, routes, onLoggingChange }: Props) {
  const [logs, setLogs] = useState<DnsServerLogSnapshot | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [paused, setPaused] = useState(false);
  const [follow, setFollow] = useState(true);
  const [problemsOnly, setProblemsOnly] = useState(false);
  const [filter, setFilter] = useState("");
  const fetching = useRef(false);
  const acting = useRef(false);
  const revision = useRef(0);
  const consoleRef = useRef<HTMLDivElement>(null);
  const refresh = async () => {
    if (fetching.current || acting.current || document.hidden) return;
    fetching.current = true;
    const before = revision.current;
    try {
      const result = await api<DnsServerLogSnapshot>("GET", "/api/dnsserver/logs");
      if (before === revision.current) { setLogs(result); setError(""); }
    } catch (e) { if (before === revision.current) setError((e as Error).message); }
    finally { fetching.current = false; }
  };
  usePoll(refresh, 2500, !paused);
  const mutate = async (path: "logging" | "logs/clear", body: unknown) => {
    if (acting.current) return;
    acting.current = true; revision.current++; setBusy(true);
    try {
      const result = await api<DnsServerLogSnapshot>("POST", `/api/dnsserver/${path}`, body);
      setLogs(result); setError(""); onLoggingChange(result.enabled);
    } catch (e) { toast((e as Error).message, "err"); }
    finally { acting.current = false; setBusy(false); }
  };
  useEffect(() => {
    if (follow && !paused && consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  }, [logs?.last_id, follow, paused, problemsOnly, filter]);
  const routeName = (id: string) => routes.find((v) => v.id === id)?.name || (id === "nfqws" ? "NFQWS" : id === "cache" ? "Кэш" : id);
  const entries = (logs?.entries ?? []).filter((entry) => (!problemsOnly || isLogProblem(entry)) && matchesLogFilter(entry, filter, routeName));
  const maxLogKiB = Math.round((logs?.max_bytes || 128 * 1024) / 1024);
  return <>
    <SchedulerPanel running={running} />
    <Card title="Консоль DNS" sub={`журнал в памяти · до ${maxLogKiB} КиБ · старые записи удаляются автоматически`} head={<Switch checked={loggingEnabled} disabled={busy} onChange={(enabled) => mutate("logging", { enabled })} label="Логирование" />}>
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Поиск в журнале" className="min-w-[180px] flex-1"><Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Домен, DoH, маршрут или ошибка" /></Field>
        <Button mini onClick={() => setPaused((v) => !v)}>{paused ? "Продолжить просмотр" : "Пауза просмотра"}</Button>
        <Button mini disabled={busy || !logs?.entries.length} onClick={() => mutate("logs/clear", {})}>Очистить журнал</Button>
      </div>
      <div className="my-3 flex flex-wrap items-center gap-4 text-xs"><Switch checked={follow} onChange={setFollow} label="Автопрокрутка" /><Switch checked={problemsOnly} onChange={setProblemsOnly} label="Только ошибки" />{logs && <span className="text-muted">{(logs.bytes / 1024).toFixed(1)} / {maxLogKiB} КиБ · Записей: {logs.entries.length}{logs.dropped > 0 ? ` · Удалено старых: ${logs.dropped}` : ""}</span>}</div>
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted" aria-label="Обозначения журнала"><span><b className="text-ok">✓</b> ответ</span><span><b className="text-accent">⚡</b> кэш</span><span><b>⊘ ×N</b> отмены без штрафа</span><span><b className="text-bad">!</b> ошибка</span><span className="ml-auto">⌄ подробности</span></div>
      {paused && <p className="mb-3 text-xs text-warn">Просмотр приостановлен. Сервер продолжает записывать события, если логирование включено.</p>}
      {error && <p role="alert" className="mb-3 text-xs text-bad">Не удалось обновить журнал: {error}</p>}
      <div ref={consoleRef} role="log" aria-label="Журнал DNS" aria-live="off" tabIndex={0} className="h-80 overflow-auto rounded-lg border border-line bg-input px-3 py-1 font-mono text-[11px] leading-relaxed">
        {!entries.length && <p className="text-muted">{logs === null ? "Загрузка журнала…" : logs.entries.length ? "Нет записей, подходящих под фильтр." : loggingEnabled ? "Журнал пуст. Здесь появятся новые DNS-запросы и события сервиса." : "Логирование выключено. Включите его для записи новых событий."}</p>}
        <DnsLogRows entries={entries} routeName={routeName} />
      </div>
    </Card>
  </>;
}

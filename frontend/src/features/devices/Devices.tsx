import { useRef, useState } from "react";
import { api, downloadFile } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { hostOf, human } from "@/lib/format";
import { navigate } from "@/lib/router";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import { PageHeader, StatsStrip, compactCard } from "@/components/ui/FeaturePage";
import { Switch } from "@/components/ui/Switch";
import { Skeleton } from "@/components/ui/Skeleton";
import { fieldCls } from "@/components/ui/form";
import type { Device, Trace, Pcap, PcapStart, InstallResult } from "@/types/api";
import { deviceRows, deviceSummary, hasDeviceFailures } from "./devicesView";

const diagnosticCard = cn(compactCard, "[&_[data-slot=card-title]]:min-w-0 [&_[data-slot=card-title]]:[overflow-wrap:anywhere]");

const KIND: Record<string, { label: string; cls: string }> = {
  new: { label: "NEW", cls: "text-ink-soft" },
  unreplied: { label: "НЕТ ОТВЕТА", cls: "text-bad" },
  replied: { label: "ОТВЕТ", cls: "text-ok" },
  gone: { label: "ЗАКРЫТО", cls: "text-warn" },
};
const problems = (t: Trace) => (t.events ?? []).filter((e) => e.kind === "unreplied" || e.kind === "gone").length;

function downloadTrace(t: Trace) {
  const lines = [
    `# Трассировка ${t.ip} — ${t.seconds}с — ${new Date(t.started_at * 1000).toLocaleString("ru-RU")}`,
    `# соединений: ${t.conns.length}, событий: ${t.events.length}`,
    "",
    "## События",
    ...(t.events ?? []).map((e) => `+${(e.at_ms / 1000).toFixed(1)}с ${e.kind.toUpperCase()} ${e.proto} ${e.dst}${e.note ? " — " + e.note : ""}`),
    "",
    "## Соединения",
    ...(t.conns ?? []).map((c) => `${c.proto} ${c.dst} state=${c.state || "-"} ${c.first_ms}-${c.last_ms}мс пакетов≈${c.max_packets} байт≈${c.max_bytes}${c.unreplied ? " UNREPLIED" : ""}${c.gone ? " GONE" : ""}`),
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `trace-${t.ip}-${t.id.slice(0, 6)}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

const DstList = ({ items }: { items: string[] }) =>
  !items.length ? (
    <p className="py-4 text-center text-xs text-muted">Нет соединений</p>
  ) : (
    <ul className="m-0 max-h-[168px] min-w-0 list-none overflow-y-auto p-0 font-mono text-xs">
      {items.slice(0, 50).map((x, i) => <li key={i} className="border-b border-line-soft px-1 py-1 text-ink-soft [overflow-wrap:anywhere]">{x}</li>)}
      {items.length > 50 && <li className="py-0.5 text-muted">…ещё {items.length - 50}</li>}
    </ul>
  );

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [err, setErr] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [filter, setFilter] = useState("");
  const [failOnly, setFailOnly] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const refreshInFlight = useRef(false);
  const [trace, setTrace] = useState<Trace | null>(null);
  const [tracing, setTracing] = useState(false);
  const [traceStarting, setTraceStarting] = useState(false);
  const [pcap, setPcap] = useState<Pcap | null>(null);
  const [pcapping, setPcapping] = useState(false);
  const [pcapStarting, setPcapStarting] = useState(false);
  const [installIP, setInstallIP] = useState<string | null>(null);
  const [installing, setInstalling] = useState(false);
  const { setPendingTargets } = useStore();

  const refresh = async (signal?: AbortSignal) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    setRefreshing(true);
    try {
      const value = await api<{ devices: Device[] }>("GET", "/api/devices", undefined, { signal });
      if (signal?.aborted) return;
      setDevices(value.devices ?? []); setLoaded(true); setErr("");
    } catch (error) {
      if (!signal?.aborted) setErr((error as Error).message);
    } finally {
      refreshInFlight.current = false;
      if (!signal?.aborted) setRefreshing(false);
    }
  };
  usePoll(refresh, 5000);

  usePoll(async () => {
    if (!trace) return;
    try {
      const t = await api<Trace>("GET", `/api/trace/${trace.id}`);
      setTrace(t);
      if (t.status !== "running") {
        setTracing(false);
        toast(`Трассировка ${t.ip} завершена — проблем: ${problems(t)}`, problems(t) ? "warn" : "ok");
      }
    } catch (e) { setTracing(false); toast((e as Error).message, "err"); }
  }, 1000, tracing);

  usePoll(async () => {
    if (!pcap) return;
    try {
      const p = await api<Pcap>("GET", `/api/pcap/${pcap.id}`);
      setPcap(p);
      if (p.status !== "running") {
        setPcapping(false);
        toast(p.status === "error" ? `Захват ${p.ip}: ${p.error}` : `Захват ${p.ip} готов — ${p.packets} пакетов`, p.status === "error" ? "err" : "ok");
      }
    } catch (e) { setPcapping(false); toast((e as Error).message, "err"); }
  }, 1000, pcapping);

  const sendToRun = (failing: string[]) => {
    setPendingTargets([...new Set(failing.map(hostOf).filter(Boolean))]);
    navigate("runs");
  };
  const startTrace = async (ip: string) => {
    if (tracing || traceStarting) return;
    setTraceStarting(true);
    try { const t = await api<Trace>("POST", `/api/devices/${encodeURIComponent(ip)}/trace`, { seconds: 30 }); setTrace(t); setTracing(true); toast(`Трассировка ${ip} запущена на 30 с`, "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
    finally { setTraceStarting(false); }
  };
  // Start a tcpdump capture; if the router lacks tcpdump the backend asks to install it first (modal).
  const beginPcap = async (ip: string) => {
    if (pcapping || pcapStarting) return;
    setPcapStarting(true);
    try {
      const r = await api<PcapStart>("POST", `/api/devices/${encodeURIComponent(ip)}/pcap`, { seconds: 30 });
      if ("need_install" in r) { setInstallIP(ip); return; }
      setPcap(r); setPcapping(true); toast(`Захват ${ip} запущен на ${r.seconds} с`, "ok");
    } catch (e) { toast((e as Error).message, "err"); }
    finally { setPcapStarting(false); }
  };
  const confirmInstall = async () => {
    const ip = installIP;
    if (!ip) return;
    setInstalling(true);
    try {
      const r = await api<InstallResult>("POST", "/api/system/install", { package: "tcpdump" });
      if (!r.ok) { toast(`Не удалось установить tcpdump: ${r.error ?? ""}`, "err"); return; }
      toast("tcpdump установлен", "ok");
      setInstallIP(null);
      await beginPcap(ip);
    } catch (e) { toast((e as Error).message, "err"); }
    finally { setInstalling(false); }
  };
  const downloadPcap = (p: Pcap) =>
    downloadFile(`/api/pcap/${p.id}/download`, `pcap-${p.ip}-${p.id.slice(0, 6)}.pcap`).catch((e) => toast((e as Error).message, "err"));

  const rows = deviceRows(devices, filter, failOnly);
  const summary = deviceSummary(devices);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader title="Устройства" description="Активность клиентов LAN, соединения и диагностика обрывов."
        meta="Обновление каждые 5 с"
        actions={<Button mini onClick={() => { void refresh(); }} disabled={refreshing} aria-busy={refreshing}>↻ Обновить хосты</Button>} />
      <StatsStrip label="Сводка устройств" items={[
        { label: "Устройства LAN", value: loaded ? summary.hosts : "—", hint: "В текущем списке" },
        { label: "С проблемами", value: loaded ? summary.failingHosts : "—", hint: loaded ? `Не отвечают: ${summary.failing}` : "Без ответа / SYN_SENT", tone: summary.failingHosts ? "bad" : "neutral" },
        { label: "Установлено", value: loaded ? summary.established : "—", hint: loaded ? `Всего сессий: ${summary.total}` : "Соединения устройств", tone: "ok" },
        { label: "Суммарный трафик", value: loaded && summary.bytes !== null ? human(summary.bytes) : "—", hint: summary.bytes === null ? "Данные трафика недоступны" : "Отправлено + получено" },
        { label: "Диагностика", value: tracing || pcapping ? "Идёт запись" : installIP ? "Нужен tcpdump" : "30 с", hint: tracing && pcapping ? "Трассировка и .pcap" : tracing ? "Трассировка соединений" : pcapping ? "Захват .pcap" : "Трассировка / захват .pcap" },
      ]} />
      {trace && (
        <Card
          className={diagnosticCard}
          title={`Трассировка ${trace.ip}`}
          sub={tracing ? "идёт запись…" : trace.status === "error" ? `ошибка: ${trace.error}` : "готово"}
          head={
            <div className="flex max-w-full flex-wrap items-center gap-2.5">
              {trace.status !== "running" && <Button mini onClick={() => downloadTrace(trace)}>Скачать лог</Button>}
              <Button mini variant="ghost" onClick={() => { setTrace(null); setTracing(false); }}>Закрыть</Button>
            </div>
          }
        >
          <div className="mb-2 flex flex-wrap gap-3 text-xs text-ink-soft [overflow-wrap:anywhere]">
            <span>прошло: <b className="tabular-nums">{(trace.elapsed_ms / 1000).toFixed(1)} / {trace.seconds} с</b></span>
            <span>соединений: <b>{(trace.conns ?? []).length || new Set((trace.events ?? []).filter((e) => e.kind === "new").map((e) => e.dst)).size}</b></span>
            <span className={problems(trace) ? "text-bad" : ""}>проблемы: <b>{problems(trace)}</b></span>
          </div>
          {tracing && (
            <div className="mb-2 h-2 overflow-hidden rounded-full bg-line">
              <div className="h-full rounded-full bg-accent transition-[width]" style={{ width: `${Math.min(100, trace.elapsed_ms / (trace.seconds * 10))}%` }} />
            </div>
          )}
          <div className="max-h-[280px] overflow-auto rounded-lg border border-line bg-input p-3 font-mono text-xs leading-relaxed">
            {(trace.events ?? []).length === 0 && <div className="text-muted">Пока нет событий… (повоспроизводите проблему — игру, звонок и т.п.)</div>}
            {(trace.events ?? []).map((e, i) => {
              const k = KIND[e.kind] ?? { label: e.kind, cls: "text-ink" };
              return (
                <div key={i} className="whitespace-pre-wrap [overflow-wrap:anywhere]">
                  <span className="text-muted">+{(e.at_ms / 1000).toFixed(1)}с</span>{" "}
                  <span className={cn("font-semibold", k.cls)}>{k.label}</span>{" "}
                  <span className="text-ink-soft">{e.proto} {e.dst}</span>
                  {e.note ? <span className="text-muted"> — {e.note}</span> : null}
                </div>
              );
            })}
          </div>
          <p className="mt-2 text-xs text-muted">Полная запись идёт и в «Логи» (модуль <code>trace</code>). «Нет ответа»/«закрыто» — вероятная потеря соединения с сервером.</p>
        </Card>
      )}

      {pcap && (
        <Card
          className={diagnosticCard}
          title={`Захват пакетов ${pcap.ip}`}
          sub={pcapping ? "идёт захват…" : pcap.status === "error" ? `ошибка: ${pcap.error}` : "готово"}
          head={
            <div className="flex max-w-full flex-wrap items-center gap-2.5">
              {pcap.status === "done" && pcap.size_bytes > 0 && <Button mini onClick={() => downloadPcap(pcap)}>Скачать .pcap</Button>}
              <Button mini variant="ghost" onClick={() => { setPcap(null); setPcapping(false); }}>Закрыть</Button>
            </div>
          }
        >
          <div className="mb-2 flex flex-wrap gap-3 text-xs text-ink-soft [overflow-wrap:anywhere]">
            <span>интерфейс: <b>{pcap.iface}</b></span>
            <span>прошло: <b className="tabular-nums">{(pcap.elapsed_ms / 1000).toFixed(1)} / {pcap.seconds} с</b></span>
            <span>пакетов: <b className="tabular-nums">{pcap.packets}</b></span>
            <span className={pcap.dropped ? "text-bad" : ""}>отброшено ядром: <b className="tabular-nums">{pcap.dropped}</b></span>
            <span>размер: <b className="tabular-nums">{human(pcap.size_bytes)}</b></span>
          </div>
          {pcapping && (
            <div className="mb-2 h-2 overflow-hidden rounded-full bg-line">
              <div className="h-full rounded-full bg-accent transition-[width]" style={{ width: `${Math.min(100, pcap.elapsed_ms / (pcap.seconds * 10))}%` }} />
            </div>
          )}
          <p className="mt-1 text-xs text-muted">
            Полный дамп пакетов устройства (<code>tcpdump</code> на {pcap.iface}). Открой <code>.pcap</code> в Wireshark, чтобы разобрать дропы, ретрансмиты и RST — потери соединения в играх/звонках.
          </p>
        </Card>
      )}

      <Card className={compactCard} title="Активность устройств локальной сети"
        head={<span className="font-mono text-xs text-muted">{rows.length} из {devices.length} хостов</span>}>
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <input type="search" aria-label="Поиск устройств" placeholder="Поиск по IP, MAC или имени устройства…"
            className={cn(fieldCls, "min-w-0 flex-1 basis-full sm:basis-64")} value={filter} onChange={event => setFilter(event.target.value)} />
          <Switch checked={failOnly} onChange={setFailOnly} label="только с проблемами" />
        </div>
        <p className="mb-3 text-xs leading-relaxed text-muted">«Не отвечают» — без ответа (<code>[UNREPLIED]</code>) или TCP в <code>SYN_SENT</code>. «Отследить 30с» записывает новые, неотвечающие и закрытые соединения устройства.</p>
        {err && <p role="alert" className="mb-3 text-xs text-bad [overflow-wrap:anywhere]">Не удалось обновить устройства: {err}{loaded && " Показан последний полученный список."}</p>}
        {!loaded && !err && <div className="flex flex-col gap-3" aria-label="Загрузка устройств">{[0, 1, 2].map(index => <Skeleton key={index} className="h-32 w-full" />)}</div>}
        {!loaded && err && <p className="py-8 text-center text-xs text-muted">Данные временно недоступны.</p>}
        {loaded && !rows.length && <p className="py-8 text-center text-xs text-muted">{devices.length ? "Нет устройств, соответствующих фильтрам." : "Нет активных устройств LAN."}</p>}
        <div className="flex min-w-0 flex-col gap-3">
        {rows.map((d) => {
          const working = d.working ?? [], failing = d.failing_dsts ?? [];
          return (
            <article key={d.ip} className={cn("min-w-0 rounded-lg border bg-panel p-3", hasDeviceFailures(d) ? "border-bad/30" : "border-line")}>
              <div className="mb-3 flex flex-col items-start justify-between gap-3 border-b border-line pb-3 sm:flex-row sm:flex-wrap">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-2">
                    {d.hostname && <b className="max-w-full text-sm text-ink [overflow-wrap:anywhere]">{d.hostname}</b>}
                    <span className="max-w-full font-mono text-sm font-bold [overflow-wrap:anywhere]">{d.ip}</span>
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-muted">
                    {d.mac && <span className="max-w-full font-mono [overflow-wrap:anywhere]">{d.mac}</span>}
                    {d.iface && <span className="max-w-full rounded border border-line bg-line-soft px-1.5 py-0.5 [overflow-wrap:anywhere]">{d.iface}</span>}
                  </div>
                  {!!d.ipv6?.length && <details className="mt-1 min-w-0 text-[11px] text-muted">
                    <summary className="cursor-pointer">IPv6 · {d.ipv6.length} адресов</summary>
                    <ul className="mt-1 flex flex-col gap-1 font-mono [overflow-wrap:anywhere]">{d.ipv6.map(address => <li key={address}>{address}</li>)}</ul>
                  </details>}
                </div>
                <div className="flex max-w-full flex-wrap items-center gap-2">
                  <span className="basis-full text-xs sm:basis-auto">
                    <span className="text-ok">{d.established} работают</span> ·{" "}
                    <span className={d.failing ? "text-bad" : "text-muted"}>{d.failing} не отвечают</span>
                  </span>
                  <Button mini onClick={() => startTrace(d.ip)} disabled={tracing || traceStarting}>Отследить 30с</Button>
                  <Button mini variant="ghost" onClick={() => beginPcap(d.ip)} disabled={pcapping || pcapStarting || installing}>Захват .pcap</Button>
                </div>
              </div>
              <div className="grid min-w-0 grid-cols-1 gap-3 md:grid-cols-2">
                <div className="min-w-0 rounded-md border border-line bg-line-soft/40 p-2.5">
                  <div className="mb-2 text-xs font-semibold text-ok">Работают ({working.length})</div>
                  <DstList items={working} />
                </div>
                <div className={cn("min-w-0 rounded-md border bg-line-soft/40 p-2.5", failing.length ? "border-bad/20" : "border-line")}>
                  <div className={cn("mb-2 flex flex-wrap items-center justify-between gap-2 text-xs font-semibold", failing.length ? "text-bad" : "text-muted")}>
                    Не отвечают ({failing.length})
                    {failing.length > 0 && <Button mini onClick={() => sendToRun(failing)}>→ В прогон</Button>}
                  </div>
                  <DstList items={failing} />
                </div>
              </div>
            </article>
          );
        })}
        </div>
      </Card>

      {installIP && (
        <Modal
          title="Нужен пакет tcpdump"
          onClose={() => { if (!installing) setInstallIP(null); }}
          actions={
            <>
              <Button variant="ghost" onClick={() => setInstallIP(null)} disabled={installing}>Отмена</Button>
              <Button variant="primary" onClick={confirmInstall} disabled={installing}>{installing ? "Установка…" : "Установить"}</Button>
            </>
          }
        >
          <p>Для захвата пакетов нужен <b>tcpdump</b> — на роутере он не установлен. Поставить его через системный менеджер пакетов (~1–2 МБ)?</p>
          <p className="mt-2 text-muted">Установка единоразовая. После неё захват для <b className="font-mono [overflow-wrap:anywhere]">{installIP}</b> запустится автоматически.</p>
        </Modal>
      )}
    </div>
  );
}

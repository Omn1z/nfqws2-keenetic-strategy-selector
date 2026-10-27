import { useRef, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { fmtNum } from "@/lib/format";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Skeleton } from "@/components/ui/Skeleton";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import { toast } from "@/components/ui/Toast";
import { Sparkline } from "@/components/ui/Chart";
import { Nfqws2ServiceControls, useNfqws2ServiceControl } from "@/features/nfqws2/Nfqws2ServiceControl";
import type { Dashboard as DashboardData } from "@/types/api";
import { DashboardOverview, DASH_CARD, DashboardRow, type Rate, type Sample, type TraceRates } from "./DashboardOverview";
const MAX_SAMPLES = 120; // ~5 min at 2.5s

interface ServiceResult {
  name: string;
  ok: boolean;
  detail: string;
}

const RESTART_SERVICES = [
  { id: "nfqws2", label: "NFQWS2 (обход DPI)" },
  { id: "tgws", label: "TG WS Proxy (MTProto)" },
  { id: "socks5", label: "Telegram SOCKS5" },
];

const svcToast = (r: ServiceResult) =>
  toast(`${r.name}: ${r.ok ? "ок" : "ошибка"}${r.detail ? " — " + r.detail.split("\n").filter(Boolean).slice(-1)[0] : ""}`, r.ok ? "ok" : "err");

// Restart selected on-router services (works around the upstream nfqws2 init's
// pgrep-collision that orphans nfqws2 on reboot). Never reboots the router.
function RestartButton() {
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState<string[]>(["nfqws2"]);
  const [busy, setBusy] = useState(false);
  const toggle = (id: string) => setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const run = async () => {
    if (!sel.length) return;
    setBusy(true);
    try {
      const d = await api<{ results: ServiceResult[] }>("POST", "/api/services/restart", { services: sel });
      for (const r of d.results) svcToast(r);
      setOpen(false);
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Button mini onClick={() => setOpen(true)} title="Перезапуск сервисов">↻ Перезапуск</Button>
      {open && (
        <Modal
          title="Перезапуск сервисов"
          onClose={() => { if (!busy) setOpen(false); }}
          actions={
            <>
              <Button variant="ghost" onClick={() => setOpen(false)} disabled={busy}>Отмена</Button>
              <Button variant="primary" onClick={run} disabled={busy || !sel.length}>{busy ? "Перезапуск…" : "Перезапустить"}</Button>
            </>
          }
        >
          <p className="mb-3 text-muted">Выберите сервисы. <b className="text-ink">NFQWS2</b> на ~2&nbsp;секунды прервёт обход DPI (роутер не перезагружается).</p>
          <div className="flex flex-col gap-2.5">
            {RESTART_SERVICES.map((s) => (
              <label key={s.id} className="flex cursor-pointer items-center gap-2.5 text-[13.5px]">
                <input type="checkbox" className="h-4 w-4 rounded-[4px] accent-[var(--c-accent)] outline-none focus-visible:ring-2 focus-visible:ring-ring/40" checked={sel.includes(s.id)} onChange={() => toggle(s.id)} />
                <span>{s.label}</span>
              </label>
            ))}
          </div>
        </Modal>
      )}
    </>
  );
}

// NFQWS2 service controls share one full restart for every configuration change.
export function Nfqws2Card({ running, queue, queueStat, pps, history }: { running: boolean; queue: number; queueStat?: DashboardData["queues"][number]; pps: number; history: Sample[] }) {
  const service = useNfqws2ServiceControl();
  const liveRunning = service.status?.running ?? running;
  return (
    <Card title="NFQWS2" sub="движок DPI" head={<Badge kind={liveRunning ? "ok" : "neutral"}>{liveRunning ? "работает" : "стоп"}</Badge>} className={DASH_CARD}>
      {queueStat ? <>
        <DashboardRow label={`Очередь ${queue} · пакетов/с`}>{fmtNum(Math.round(pps))}</DashboardRow>
        <DashboardRow label="Всего обработано">{fmtNum(queueStat.id_seq)}</DashboardRow>
        <DashboardRow label="В очереди сейчас">{fmtNum(queueStat.queued)}</DashboardRow>
        <DashboardRow label="Отброшено · ядро / пользователь"><span className={queueStat.queue_drop || queueStat.user_drop ? "text-bad" : ""}>{fmtNum(queueStat.queue_drop)} / {fmtNum(queueStat.user_drop)}</span></DashboardRow>
        <div className="mt-2"><Sparkline data={history.map(sample => sample.pps)} label="Пакеты DPI · история" value="" /></div>
      </> : <p className="mb-3 text-xs text-muted">Очередь {queue} не активна — DPI-обход не запущен.</p>}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Nfqws2ServiceControls status={service.status} error={service.error} pending={service.pending}
          onToggle={enabled => { void service.run(enabled ? "start" : "stop"); }}
          onRestart={() => { void service.run("restart"); }} />
      </div>
      {service.error && <p className="mt-2 text-xs text-bad" role="status">{service.error}</p>}
      <p className="mt-2 text-xs text-muted">Перезапуск применяет конфиг, стратегии и списки. Обход DPI ненадолго прерывается.</p>
    </Card>
  );
}

export default function Dashboard() {
  const [d, setD] = useState<DashboardData | null>(null);
  const [rates, setRates] = useState<Record<string, Rate>>({});
  const [awgRates, setAwgRates] = useState<Record<string, Rate>>({});
  const [hist, setHist] = useState<Sample[]>([]);
  const [traceRates, setTraceRates] = useState<TraceRates | null>(null);
  const wanPrev = useRef<Record<string, Rate & { t: number }>>({});
  const awgPrev = useRef<Record<string, Rate & { t: number }>>({});
  const qPrev = useRef<{ seq: number; t: number } | null>(null);
  const tracePrev = useRef<{ c: DashboardData["trace_counters"]; t: number } | null>(null);
  // Ring of (timestamp, counters) samples kept over the last ~75 s, so
  // we can compute REAL "за последние 60 секунд" — not RPS×60, which spikes
  // wildly on a sparse home LAN where a single query mid-interval reads as
  // "30/мин".
  const traceWindow = useRef<{ t: number; c: DashboardData["trace_counters"] }[]>([]);

  usePoll(async () => {
    try {
      const data = await api<DashboardData>("GET", "/api/dashboard");
      const now = Date.now();
      const nextRates: Record<string, Rate> = {};
      let rxSum = 0, txSum = 0;
      for (const f of data.wan ?? []) {
        const p = wanPrev.current[f.iface];
        if (p && now > p.t) {
          const dt = (now - p.t) / 1000;
          const r = { rx: Math.max(0, (f.rx_bytes - p.rx) / dt), tx: Math.max(0, (f.tx_bytes - p.tx) / dt) };
          nextRates[f.iface] = r;
          rxSum += r.rx;
          txSum += r.tx;
        }
        wanPrev.current[f.iface] = { rx: f.rx_bytes, tx: f.tx_bytes, t: now };
      }
      const q = data.queues?.find((x) => x.queue === data.main_queue);
      let pps = 0;
      if (q) {
        const p = qPrev.current;
        if (p && now > p.t) pps = Math.max(0, (q.id_seq - p.seq) / ((now - p.t) / 1000));
        qPrev.current = { seq: q.id_seq, t: now };
      }
      // AWG2 tunnel rates — same diff-over-time as WAN, keyed by connection id.
      const nextAwg: Record<string, Rate> = {};
      for (const c of data.awg ?? []) {
        const p = awgPrev.current[c.id];
        if (p && now > p.t) {
          const dt = (now - p.t) / 1000;
          nextAwg[c.id] = { rx: Math.max(0, (c.rx_bytes - p.rx) / dt), tx: Math.max(0, (c.tx_bytes - p.tx) / dt) };
        }
        awgPrev.current[c.id] = { rx: c.rx_bytes, tx: c.tx_bytes, t: now };
      }
      // Trace counter rates — diff lifetime totals to get RPS for each
      // bucket. First sample (no prev) seeds the baseline.
      if (data.trace_counters) {
        const tc = data.trace_counters;
        const win = traceWindow.current;
        win.push({ t: now, c: tc });
        // Trim samples older than 75 s — keeps the 60 s lookup well within
        // the window even if a poll tick is late.
        const cutoff = now - 75_000;
        while (win.length > 1 && win[0].t < cutoff) win.shift();
        // Find the oldest sample inside the 60 s window. If we don't have a
        // full minute of history yet, scale up what we do have.
        const target = now - 60_000;
        let base = win[0];
        for (const s of win) if (s.t <= target) base = s;
        const elapsedSec = Math.max(1, (now - base.t) / 1000);
        const scale = 60 / elapsedSec;
        const d = (cur: number, prev: number) => Math.max(0, (cur - prev) * scale);
        setTraceRates({
          dns: d(tc.dns, base.c.dns),
          sni: d(tc.sni, base.c.sni),
          tunnel: d(tc.tunnel, base.c.tunnel),
          direct: d(tc.direct, base.c.direct),
          blocked: d(tc.blocked, base.c.blocked),
          cdnSkip: d(tc.cdn_skip, base.c.cdn_skip),
        });
        tracePrev.current = { c: tc, t: now };
      }
      setAwgRates(nextAwg);
      setRates(nextRates);
      setD(data);
      // Connection and DPI history remain available even without WAN counters.
      // An absent WAN contributes zero bytes; the WAN card reports no data.
      setHist((h) => [...h, { conns: data.conns.total, pps, rx: rxSum, tx: txSum }].slice(-MAX_SAMPLES));
    } catch {
      /* keep last view */
    }
  }, 2500);

  if (!d) return <div className="flex flex-col gap-4">
    <div className="flex justify-end"><RestartButton /></div>
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5">
      {Array.from({ length: 5 }).map((_, index) => <div key={index} className="rounded-lg border border-line p-3"><Skeleton className="mb-2 h-3 w-20" /><Skeleton className="h-6 w-24" /></div>)}
    </div>
    <Card title="Каналы и подключения" className={DASH_CARD}><Skeleton className="mb-3 h-4 w-full" /><Skeleton className="mb-3 h-4 w-full" /><Skeleton className="h-4 w-full" /></Card>
  </div>;
  return <DashboardOverview d={d} rates={rates} awgRates={awgRates} hist={hist} traceRates={traceRates}
    restart={<RestartButton />}
    nfqws2={<Nfqws2Card running={d.nfqws2_running} queue={d.main_queue} queueStat={d.queues?.find(queue => queue.queue === d.main_queue)} pps={hist[hist.length - 1]?.pps ?? 0} history={hist} />} />;
}

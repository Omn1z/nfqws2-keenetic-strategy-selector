import { useRef, useState } from "react";
import type { ReactNode } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { fmtNum, human } from "@/lib/format";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Skeleton } from "@/components/ui/Skeleton";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Sparkline } from "@/components/ui/Chart";
import type { Dashboard as DashboardData } from "@/types/api";

const Row = ({ l, children }: { l: string; children: ReactNode }) => (
  <div className="flex justify-between gap-3 border-t border-line-soft py-1.5 text-[13px] first:border-t-0">
    <span className="text-ink-soft">{l}</span>
    <b className="whitespace-nowrap tabular-nums">{children}</b>
  </div>
);

const Big = ({ value, sub }: { value: ReactNode; sub: string }) => (
  <div className="mb-2.5 text-[30px] font-bold leading-tight tabular-nums text-accent-d">
    {value}
    <span className="mt-0.5 block text-xs font-medium text-muted">{sub}</span>
  </div>
);

// Service-status cards in a 3-up row; metric cards in their own 3-up row.
const GRID3 = "grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3";
const CARD = "mb-0 h-full"; // cancel the Card stacking margin + stretch to row height

type Rate = { rx: number; tx: number };
interface Sample {
  conns: number;
  pps: number;
  rx: number; // bytes/s
  tx: number; // bytes/s
}
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
      <Button onClick={() => setOpen(true)} title="Перезапуск сервисов">↻ Перезапуск</Button>
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

// NFQWS2 service controls: status + Start / Stop / Reload / Restart. Stop and
// Restart interrupt DPI bypass, so they confirm first; Reload is a SIGHUP (safe).
function Nfqws2Card({ running, queue }: { running: boolean; queue: number }) {
  const [busy, setBusy] = useState("");
  const run = async (key: string, fn: () => Promise<void>, confirm?: { title: string; body?: string; danger?: boolean }) => {
    if (confirm && !(await confirmDialog({ title: confirm.title, body: confirm.body, confirmLabel: "Да", danger: confirm.danger }))) return;
    setBusy(key);
    try { await fn(); } catch (e) { toast((e as Error).message, "err"); } finally { setBusy(""); }
  };
  const start = () => run("start", async () => svcToast(await api<ServiceResult>("POST", "/api/nfqws2/start", {})));
  const stop = () => run("stop", async () => svcToast(await api<ServiceResult>("POST", "/api/nfqws2/stop", {})), { title: "Остановить NFQWS2?", body: "Обход DPI перестанет работать до следующего запуска.", danger: true });
  const reload = () => run("reload", async () => { await api("POST", "/api/nfqws2/reload", {}); toast("nfqws2: конфиг перечитан (reload)", "ok"); });
  const restart = () => run("restart", async () => { const d = await api<{ results: ServiceResult[] }>("POST", "/api/services/restart", { services: ["nfqws2"] }); if (d.results?.[0]) svcToast(d.results[0]); }, { title: "Перезапустить NFQWS2?", body: "Обход DPI прервётся на ~2 секунды." });
  const B = ({ k, label, variant, onClick }: { k: string; label: string; variant?: "primary" | "danger"; onClick: () => void }) => (
    <Button mini variant={variant} disabled={!!busy} onClick={onClick}>{busy === k ? "…" : label}</Button>
  );
  return (
    <Card title="NFQWS2" sub="движок DPI" head={<Badge kind={running ? "ok" : "bad"}>{running ? "работает" : "остановлен"}</Badge>} className={CARD}>
      <p className="mb-2.5 text-[13px] text-ink-soft">Очередь {queue}: <b>{running ? "активна" : "не активна"}</b></p>
      <div className="flex flex-wrap gap-2">
        <B k="start" label="Старт" variant="primary" onClick={start} />
        <B k="stop" label="Стоп" variant="danger" onClick={stop} />
        <B k="reload" label="Reload" onClick={reload} />
        <B k="restart" label="Перезапуск" onClick={restart} />
      </div>
      <p className="mt-2 text-xs text-muted">Reload перечитывает списки без обрыва очереди; Стоп/Перезапуск прерывают обход.</p>
    </Card>
  );
}

export default function Dashboard() {
  const [d, setD] = useState<DashboardData | null>(null);
  const [rates, setRates] = useState<Record<string, Rate>>({});
  const [hist, setHist] = useState<Sample[]>([]);
  const wanPrev = useRef<Record<string, Rate & { t: number }>>({});
  const qPrev = useRef<{ seq: number; t: number } | null>(null);

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
      setRates(nextRates);
      setD(data);
      // Push a history sample only once a baseline exists (first poll seeds prev).
      if (qPrev.current && Object.keys(wanPrev.current).length) {
        setHist((h) => [...h, { conns: data.conns.total, pps, rx: rxSum, tx: txSum }].slice(-MAX_SAMPLES));
      }
    } catch {
      /* keep last view */
    }
  }, 2500);

  // First paint: skeleton in a 3-card grid so nothing jumps on load.
  if (!d)
    return (
      <>
        <div className="mb-4 flex justify-end"><RestartButton /></div>
        <div className={GRID3}>
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i} className={CARD}>
              <Skeleton className="mb-3 h-4 w-28" />
              <Skeleton className="mb-2.5 h-8 w-24" />
              <Skeleton className="mb-1.5 h-3 w-full" />
              <Skeleton className="h-3 w-2/3" />
            </Card>
          ))}
        </div>
      </>
    );

  const { connections: cc, traffic: tr } = d.tgws.stats;
  const sc = d.socks5.stats.connections, str = d.socks5.stats.traffic;
  const bp = d.conns.by_proto ?? {};
  const q = d.queues?.find((x) => x.queue === d.main_queue);
  const last = hist[hist.length - 1];
  const wan = d.wan ?? [];
  const wan0 = wan[0];
  const wan0r = wan0 ? rates[wan0.iface] : undefined;

  return (
    <>
      <div className="mb-4 flex justify-end"><RestartButton /></div>

      {/* Сервисы — статусы и управление */}
      <div className={`${GRID3} mb-4`}>
        <Card title="TG WS Proxy" sub="MTProto" className={CARD}>
          <Row l="Статус"><Badge kind={d.tgws.running ? "ok" : "bad"}>{d.tgws.running ? "работает" : "остановлен"}</Badge></Row>
          <Row l="Активные / всего">{cc.active} / {cc.total}</Row>
          <Row l="WS / TCP / CF">{cc.ws} / {cc.tcp_fallback} / {cc.cfproxy}</Row>
          <Row l="Трафик ↑ / ↓">{tr.human_up || "0 Б"} / {tr.human_down || "0 Б"}</Row>
        </Card>

        <Card title="SOCKS5" sub="Telegram" className={CARD}>
          <Row l="Статус"><Badge kind={d.socks5.running ? "ok" : "bad"}>{d.socks5.running ? "работает" : "остановлен"}</Badge></Row>
          <Row l="Активные / всего">{sc.active} / {sc.total}</Row>
          <Row l="Telegram / прямые">{sc.telegram} / {sc.direct}</Row>
          <Row l="Трафик ↑ / ↓">{str.human_up || "0 Б"} / {str.human_down || "0 Б"}</Row>
        </Card>

        <Nfqws2Card running={d.nfqws2_running} queue={d.main_queue} />
      </div>

      {/* Метрики */}
      <div className={GRID3}>
        <Card title="Активные соединения" sub="conntrack" className={CARD}>
          <Big value={fmtNum(d.conns.total)} sub={`из ${fmtNum(d.conntrack.max)} макс.`} />
          <Row l="TCP / UDP / ICMP">{bp.tcp ?? 0} / {bp.udp ?? 0} / {bp.icmp ?? 0}</Row>
          <Row l="Не отвечают"><span className={d.conns.failing ? "text-bad" : ""}>{d.conns.failing}</span></Row>
        </Card>

        <Card title="Пакеты DPI" sub={`nfqws2 · очередь ${d.main_queue}`} className={CARD}>
          {q ? (
            <>
              <Big value={fmtNum(q.id_seq)} sub="пакетов обработано" />
              <Row l="В очереди сейчас">{fmtNum(q.queued)}</Row>
              <Row l="Отброшено (ядро / польз.)"><span className={q.queue_drop || q.user_drop ? "text-bad" : ""}>{fmtNum(q.queue_drop)} / {fmtNum(q.user_drop)}</span></Row>
            </>
          ) : (
            <p className="text-xs text-muted">Очередь {d.main_queue} не активна — nfqws2 не запущен?</p>
          )}
        </Card>

        <Card title="WAN" sub="интерфейс" className={CARD}>
          {wan.length ? (
            <>
              <Big value={wan0r ? `${human(wan0r.rx)}/с` : "…"} sub={`${wan0.iface} ↓ сейчас`} />
              {wan.map((f) => {
                const r = rates[f.iface];
                return (
                  <div key={f.iface}>
                    <Row l={`${f.iface} всего ↓ / ↑`}>{human(f.rx_bytes)} / {human(f.tx_bytes)}</Row>
                    <Row l={`${f.iface} ↑ сейчас`}>{r ? `${human(r.tx)}/с` : "…"}</Row>
                  </div>
                );
              })}
            </>
          ) : (
            <p className="text-xs text-muted">Нет данных по WAN-интерфейсу.</p>
          )}
        </Card>
      </div>

      <Card title="Нагрузка" sub="живые графики, ~5 минут" className="mt-4">
        <div className="grid grid-cols-2 gap-x-8 gap-y-4 max-[640px]:grid-cols-1">
          <Sparkline data={hist.map((s) => s.conns)} label="Соединения" value={fmtNum(d.conns.total)} />
          <Sparkline data={hist.map((s) => s.pps)} label="Пакеты DPI / с" value={fmtNum(Math.round(last?.pps ?? 0))} color="var(--c-ok)" />
          <Sparkline data={hist.map((s) => s.rx / 1024)} label="WAN ↓ КБ/с" value={`${Math.round((last?.rx ?? 0) / 1024)}`} />
          <Sparkline data={hist.map((s) => s.tx / 1024)} label="WAN ↑ КБ/с" value={`${Math.round((last?.tx ?? 0) / 1024)}`} color="var(--c-warn)" />
        </div>
      </Card>
    </>
  );
}

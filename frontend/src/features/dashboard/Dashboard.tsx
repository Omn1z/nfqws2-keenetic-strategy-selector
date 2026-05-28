import { useRef, useState } from "react";
import type { ReactNode } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { fmtNum, human } from "@/lib/format";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
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

type Rate = { rx: number; tx: number };

export default function Dashboard() {
  const [d, setD] = useState<DashboardData | null>(null);
  const [rates, setRates] = useState<Record<string, Rate>>({});
  const prev = useRef<Record<string, Rate & { t: number }>>({});

  usePoll(async () => {
    try {
      const data = await api<DashboardData>("GET", "/api/dashboard");
      const now = Date.now();
      const next: Record<string, Rate> = {};
      for (const f of data.wan ?? []) {
        const p = prev.current[f.iface];
        if (p && now > p.t) {
          const dt = (now - p.t) / 1000;
          next[f.iface] = { rx: Math.max(0, (f.rx_bytes - p.rx) / dt), tx: Math.max(0, (f.tx_bytes - p.tx) / dt) };
        }
        prev.current[f.iface] = { rx: f.rx_bytes, tx: f.tx_bytes, t: now };
      }
      setRates(next);
      setD(data);
    } catch {
      /* keep last view */
    }
  }, 2500);

  if (!d) return <Card><span className="text-xs text-muted">Загрузка…</span></Card>;
  const { connections: cc, traffic: tr } = d.tgws.stats;
  const bp = d.conns.by_proto ?? {};
  const q = d.queues?.find((x) => x.queue === d.main_queue);

  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(252px,1fr))] items-start gap-4">
      <Card title="TG WS Proxy">
        <Row l="Статус"><Badge kind={d.tgws.running ? "ok" : "bad"}>{d.tgws.running ? "работает" : "остановлен"}</Badge></Row>
        <Row l="Активные / всего">{cc.active} / {cc.total}</Row>
        <Row l="WS / TCP / CF">{cc.ws} / {cc.tcp_fallback} / {cc.cfproxy}</Row>
        <Row l="Трафик ↑ / ↓">{tr.human_up || "0 Б"} / {tr.human_down || "0 Б"}</Row>
      </Card>

      <Card title="Активные соединения" sub="conntrack">
        <Big value={fmtNum(d.conns.total)} sub={`из ${fmtNum(d.conntrack.max)} макс.`} />
        <Row l="TCP / UDP / ICMP">{bp.tcp ?? 0} / {bp.udp ?? 0} / {bp.icmp ?? 0}</Row>
        <Row l="Не отвечают"><span className={d.conns.failing ? "text-bad" : ""}>{d.conns.failing}</span></Row>
      </Card>

      <Card title="Пакеты DPI" sub="nfqws2">
        {q ? (
          <>
            <Big value={fmtNum(q.id_seq)} sub={`пакетов · очередь ${d.main_queue}`} />
            <Row l="В очереди сейчас">{fmtNum(q.queued)}</Row>
            <Row l="Отброшено (ядро / польз.)"><span className={q.queue_drop || q.user_drop ? "text-bad" : ""}>{fmtNum(q.queue_drop)} / {fmtNum(q.user_drop)}</span></Row>
          </>
        ) : (
          <p className="text-xs text-muted">Очередь {d.main_queue} не активна — сервис nfqws2 не запущен?</p>
        )}
      </Card>

      <Card title="WAN" sub="интерфейс">
        {(d.wan ?? []).length ? (
          (d.wan ?? []).map((f) => {
            const r = rates[f.iface];
            return (
              <div key={f.iface}>
                <Row l={`${f.iface} всего ↓ / ↑`}>{human(f.rx_bytes)} / {human(f.tx_bytes)}</Row>
                <Row l="скорость ↓ / ↑">{r ? `${human(r.rx)}/с / ${human(r.tx)}/с` : "…"}</Row>
              </div>
            );
          })
        ) : (
          <p className="text-xs text-muted">Нет данных по WAN-интерфейсу.</p>
        )}
      </Card>
    </div>
  );
}

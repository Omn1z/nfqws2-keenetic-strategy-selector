import { useState, useRef } from "react";
import { api } from "../api.js";
import { usePoll } from "../hooks.js";
import { Card } from "../components.jsx";
import { human, fmtNum } from "../util.js";

const Row = ({ l, children }) => <div className="stat-row"><span>{l}</span><b>{children}</b></div>;

export default function Dashboard() {
  const [d, setD] = useState(null);
  const [rates, setRates] = useState({});
  const prev = useRef({});

  usePoll(async () => {
    try {
      const data = await api("GET", "/api/dashboard");
      const now = Date.now(), nr = {};
      (data.wan || []).forEach((f) => {
        const p = prev.current[f.iface];
        if (p && now > p.t) {
          const dt = (now - p.t) / 1000;
          nr[f.iface] = { rx: Math.max(0, (f.rx_bytes - p.rx) / dt), tx: Math.max(0, (f.tx_bytes - p.tx) / dt) };
        }
        prev.current[f.iface] = { rx: f.rx_bytes, tx: f.tx_bytes, t: now };
      });
      setRates(nr);
      setD(data);
    } catch (_) {}
  }, 2500);

  if (!d) return <div className="card"><span className="hint">Загрузка…</span></div>;
  const tg = d.tgws || {}, st = tg.stats || {}, cc = st.connections || {}, tr = st.traffic || {};
  const cn = d.conns || {}, ct = d.conntrack || {}, bp = cn.by_proto || {};
  const q = (d.queues || []).find((x) => x.queue === d.main_queue);

  return (
    <div className="dash-grid">
      <Card title="TG WS Proxy">
        <Row l="Статус"><span className={"badge " + (tg.running ? "ok" : "bad")}>{tg.running ? "работает" : "остановлен"}</span></Row>
        <Row l="Активные / всего">{(cc.active || 0)} / {(cc.total || 0)}</Row>
        <Row l="WS / TCP / CF">{(cc.ws || 0)} / {(cc.tcp_fallback || 0)} / {(cc.cfproxy || 0)}</Row>
        <Row l="Трафик ↑ / ↓">{(tr.human_up || "0 Б")} / {(tr.human_down || "0 Б")}</Row>
      </Card>

      <Card title="Активные соединения" sub="conntrack">
        <div className="stat-big">{fmtNum(cn.total)}<span className="stat-big-sub">из {fmtNum(ct.max)} макс.</span></div>
        <Row l="TCP / UDP / ICMP">{(bp.tcp || 0)} / {(bp.udp || 0)} / {(bp.icmp || 0)}</Row>
        <Row l="Не отвечают"><span className={cn.failing ? "txt-bad" : ""}>{cn.failing || 0}</span></Row>
      </Card>

      <Card title="Пакеты DPI" sub="nfqws2">
        {q ? (
          <>
            <div className="stat-big">{fmtNum(q.id_seq)}<span className="stat-big-sub">пакетов · очередь {d.main_queue}</span></div>
            <Row l="В очереди сейчас">{fmtNum(q.queued)}</Row>
            <Row l="Отброшено (ядро / польз.)"><span className={(q.queue_drop || q.user_drop) ? "txt-bad" : ""}>{fmtNum(q.queue_drop)} / {fmtNum(q.user_drop)}</span></Row>
          </>
        ) : <p className="hint">Очередь {d.main_queue} не активна — сервис nfqws2 не запущен?</p>}
      </Card>

      <Card title="WAN" sub="интерфейс">
        {(d.wan || []).length ? (d.wan || []).map((f) => {
          const r = rates[f.iface];
          return (
            <div key={f.iface}>
              <Row l={f.iface + " всего ↓ / ↑"}>{human(f.rx_bytes)} / {human(f.tx_bytes)}</Row>
              <Row l="скорость ↓ / ↑">{r ? `${human(r.rx)}/с / ${human(r.tx)}/с` : "…"}</Row>
            </div>
          );
        }) : <p className="hint">Нет данных по WAN-интерфейсу.</p>}
      </Card>
    </div>
  );
}

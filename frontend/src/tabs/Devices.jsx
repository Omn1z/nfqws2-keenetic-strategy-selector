import { useState } from "react";
import { api } from "../api.js";
import { usePoll } from "../hooks.js";
import { Card } from "../components.jsx";
import { useStore } from "../store.jsx";
import { hostOf } from "../util.js";

const DstList = ({ items }) =>
  !items.length ? (
    <ul className="dst-list"><li className="muted">—</li></ul>
  ) : (
    <ul className="dst-list">
      {items.slice(0, 50).map((x, i) => <li key={i}>{x}</li>)}
      {items.length > 50 && <li className="muted">…ещё {items.length - 50}</li>}
    </ul>
  );

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [err, setErr] = useState("");
  const { setPendingTargets } = useStore();

  usePoll(async () => {
    try { const v = await api("GET", "/api/devices"); setDevices(v.devices || []); setErr(""); }
    catch (e) { setErr(e.message); }
  }, 5000);

  const sendToRun = (failing) => {
    const ips = [...new Set(failing.map((x) => hostOf(x)).filter(Boolean))];
    setPendingTargets(ips);
    location.hash = "runs";
  };

  return (
    <Card title="Активность устройств" sub="кто к чему подключается">
      <p className="hint">
        Соединения сгруппированы по устройству LAN (по исходному IP). «Не отвечают» — соединения без ответа
        (<code>[UNREPLIED]</code>) или TCP в <code>SYN_SENT</code>: именно эти адреса стоит прогнать на вкладке «Прогоны».
      </p>
      {err && <p className="empty">Нет данных ({err}).</p>}
      {!err && !devices.length && <p className="empty">Нет активных устройств LAN.</p>}
      {devices.map((d) => {
        const working = d.working || [], failing = d.failing_dsts || [];
        return (
          <div className="dev-card" key={d.ip}>
            <div className="dev-head">
              <span className="dev-ip mono">{d.ip}</span>
              {d.mac && <span className="dev-mac mono">{d.mac}</span>}
              {d.iface && <span className="badge">{d.iface}</span>}
              <span className="dev-counts">
                <span className="txt-ok">{d.established} работают</span> · <span className={d.failing ? "txt-bad" : "muted"}>{d.failing} не отвечают</span>
              </span>
            </div>
            <div className="dev-cols">
              <div><div className="dev-col-h txt-ok">Работают ({working.length})</div><DstList items={working} /></div>
              <div>
                <div className="dev-col-h txt-bad">Не отвечают ({failing.length})
                  {failing.length > 0 && <button className="btn btn-mini" onClick={() => sendToRun(failing)}>→ В прогон</button>}
                </div>
                <DstList items={failing} />
              </div>
            </div>
          </div>
        );
      })}
    </Card>
  );
}

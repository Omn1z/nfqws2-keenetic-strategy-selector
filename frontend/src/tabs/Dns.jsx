import { useState } from "react";
import { api } from "../api.js";
import { useStore } from "../store.jsx";
import { toast } from "../toast.jsx";
import { Card, Args, DnsBadge } from "../components.jsx";

export default function Dns() {
  const { dns, reloadDns } = useStore();
  const [name, setName] = useState("");
  const [type, setType] = useState("doh");
  const [addr, setAddr] = useState("");

  const save = async () => {
    if (!name.trim() || !addr.trim()) { toast("Заполните название и адрес", "err"); return; }
    try { await api("POST", "/api/dns", { name: name.trim(), type, addr: addr.trim() }); setName(""); setAddr(""); await reloadDns(); toast("DNS добавлен", "ok"); }
    catch (e) { toast(e.message, "err"); }
  };
  const del = async (id, nm) => {
    if (!confirm("Удалить DNS «" + (nm || id) + "»?")) return;
    try { await api("DELETE", "/api/dns/" + encodeURIComponent(id)); await reloadDns(); toast("DNS удалён", "ok"); }
    catch (e) { toast(e.message, "err"); }
  };
  const reset = async () => {
    if (!confirm("Сбросить список DNS к стандартным? Добавленные вами записи будут удалены.")) return;
    try { await api("POST", "/api/dns/reset"); await reloadDns(); toast("Список DNS сброшен", "ok"); }
    catch (e) { toast(e.message, "err"); }
  };

  return (
    <>
      <Card title="DNS-серверы (DoH / DoT)" head={<button className="btn btn-mini head-action" onClick={reset}>Сбросить к стандартным</button>}>
        <p className="hint">Шифрованные DNS для прогонов: в прогоне можно выбрать, через какие из них резолвить цели. <b>DoH</b> — ссылка <code>https://…/dns-query</code>; <b>DoT</b> — <code>host</code> или <code>host:порт</code> (по умолчанию 853).</p>
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>Название</th><th>Тип</th><th>Адрес</th><th className="col-actions"></th></tr></thead>
            <tbody>
              {dns.length === 0 && <tr><td colSpan="4" className="empty-cell">Список пуст — добавьте DNS ниже или нажмите «Сбросить к стандартным».</td></tr>}
              {dns.map((d) => (
                <tr key={d.id}>
                  <td>{d.name || d.id}</td>
                  <td><DnsBadge name={(d.type || "").toUpperCase()} id={d.id} /></td>
                  <td><Args>{d.addr}</Args></td>
                  <td className="row-actions"><button className="btn btn-mini btn-ghost-danger" title="Удалить" onClick={() => del(d.id, d.name)}>×</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Добавить DNS">
        <div className="run-row mid">
          <label className="field">Название<input type="text" value={name} placeholder="Мой DNS" onChange={(e) => setName(e.target.value)} /></label>
          <label className="field field-sm">Тип<select value={type} onChange={(e) => setType(e.target.value)}><option value="doh">DoH</option><option value="dot">DoT</option></select></label>
          <label className="field field-grow">Адрес<input type="text" value={addr} placeholder="https://dns.example/dns-query  ·  dns.example[:853]" onChange={(e) => setAddr(e.target.value)} /></label>
        </div>
        <div className="actions"><button className="btn btn-primary" onClick={save}>Добавить</button></div>
      </Card>
    </>
  );
}

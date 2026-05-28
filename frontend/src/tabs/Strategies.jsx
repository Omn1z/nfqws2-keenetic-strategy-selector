import { useState, useRef } from "react";
import { api, exportStrategy, uploadForm } from "../api.js";
import { useStore } from "../store.jsx";
import { toast } from "../toast.jsx";
import { Card, Args } from "../components.jsx";

const EMPTY = { id: "", name: "", l7: "tls", args: "" };

export default function Strategies() {
  const { strategies, reloadStrategies, reloadBlobs } = useStore();
  const [form, setForm] = useState(EMPTY);
  const fileRef = useRef(null);

  const save = async () => {
    if (!form.args.trim()) { toast("Пустые аргументы", "err"); return; }
    try {
      await api("POST", "/api/strategies", { ...form, name: form.name.trim(), l7: form.l7.trim(), args: form.args.trim(), source: "custom" });
      setForm(EMPTY); await reloadStrategies(); toast("Стратегия сохранена", "ok");
    } catch (e) { toast(e.message, "err"); }
  };
  const del = async (id) => {
    if (!confirm("Удалить стратегию?")) return;
    try { await api("DELETE", "/api/strategies/" + id); await reloadStrategies(); } catch (e) { toast(e.message, "err"); }
  };
  const onImport = async (e) => {
    const f = e.target.files[0]; if (!f) return;
    const fd = new FormData(); fd.append("file", f);
    try { const d = await uploadForm("/api/strategies/import", fd); await reloadStrategies(); await reloadBlobs(); toast("Импортирована стратегия: " + (d.name || d.id), "ok"); }
    catch (err) { toast(err.message, "err"); }
    e.target.value = "";
  };

  return (
    <>
      <Card title="Каталог стратегий" head={<>
        <button className="btn btn-mini head-action" onClick={() => fileRef.current.click()}>Импорт стратегии (ZIP)</button>
        <input ref={fileRef} type="file" accept=".zip" hidden onChange={onImport} />
      </>}>
        <div className="table-wrap scrollable">
          <table className="data">
            <thead><tr><th>ID</th><th>Название</th><th>L7</th><th>Args</th><th>Источник</th><th className="col-actions"></th></tr></thead>
            <tbody>
              {strategies.map((s) => {
                const custom = s.source === "custom";
                return (
                  <tr key={s.id}>
                    <td className="mono">{s.id}</td>
                    <td>{s.name || ""}</td>
                    <td>{s.l7 || ""}</td>
                    <td><Args>{s.args}</Args></td>
                    <td>{s.source}</td>
                    <td className="row-actions">
                      <button className="btn btn-mini" title="Экспорт (ZIP)" onClick={() => exportStrategy(s.name || s.id, s.l7 || "", s.args).catch((e) => toast(e.message, "err"))}>⤓</button>
                      {custom && <><button className="btn btn-mini" onClick={() => setForm({ id: s.id, name: s.name || "", l7: s.l7 || "tls", args: s.args || "" })}>Изм.</button>
                        <button className="btn btn-mini btn-ghost-danger" onClick={() => del(s.id)}>×</button></>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title={form.id ? "Редактировать стратегию" : "Добавить свою стратегию"}>
        <div className="two">
          <label className="field">Название<input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
          <label className="field field-sm">L7<input type="text" value={form.l7} onChange={(e) => setForm({ ...form, l7: e.target.value })} /></label>
        </div>
        <label className="field">Args <span className="hint">строка аргументов nfqws2 без --new</span>
          <textarea rows="3" value={form.args} placeholder="--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=..." onChange={(e) => setForm({ ...form, args: e.target.value })} /></label>
        <div className="actions">
          <button className="btn btn-primary" onClick={save}>Сохранить</button>
          <button className="btn btn-ghost" onClick={() => setForm(EMPTY)}>Очистить</button>
        </div>
      </Card>
    </>
  );
}

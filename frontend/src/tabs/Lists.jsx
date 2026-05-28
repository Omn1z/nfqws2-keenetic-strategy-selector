import { useState, useEffect } from "react";
import { api, exportStrategy } from "../api.js";
import { useStore } from "../store.jsx";
import { toast } from "../toast.jsx";
import { Card, Pager, pageSlice, Args, DnsBadge } from "../components.jsx";
import { kb } from "../util.js";

export default function Lists() {
  const { lists, reloadLists, geo } = useStore();
  const [sel, setSel] = useState(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState("20");
  const [gFile, setGFile] = useState("");
  const [gCat, setGCat] = useState("");
  const [gLimit, setGLimit] = useState(50);

  const select = async (id) => { try { setSel(await api("GET", "/api/lists/" + id)); setPage(1); } catch (e) { toast(e.message, "err"); } };
  const newList = () => setSel({ name: "", domains: [], ips: [] });
  const save = async () => {
    const body = {
      id: sel.id || "", name: (sel.name || "").trim(), domains: sel.domains || [], ips: sel.ips || [],
      base_strategy_ids: sel.base_strategy_ids || [], successful_strategies: sel.successful_strategies || [],
    };
    try { const out = await api("POST", "/api/lists", body); setSel(out); await reloadLists(); toast("Список сохранён", "ok"); }
    catch (e) { toast(e.message, "err"); }
  };
  const del = async (id, name) => {
    if (!confirm("Удалить список «" + (name || "без имени") + "»?")) return;
    try { await api("DELETE", "/api/lists/" + id); if (sel && sel.id === id) setSel(null); await reloadLists(); toast("Список удалён", "ok"); }
    catch (e) { toast(e.message, "err"); }
  };

  const cats = (geo.find((g) => g.name === gFile)?.categories) || [];
  useEffect(() => { if (!gFile && geo[0]) setGFile(geo[0].name); }, [geo, gFile]);
  useEffect(() => { if (cats[0] && !cats.some((c) => c.name === gCat)) setGCat(cats[0].name); }, [gFile, cats, gCat]);
  const geoAdd = async () => {
    if (!sel || !sel.id) { toast("Сначала сохраните список", "err"); return; }
    if (!gCat) { toast("Нет категорий", "err"); return; }
    try {
      const out = await api("POST", "/api/geo/import", { geo: gFile, category: gCat, limit: parseInt(gLimit, 10) || 0, list_id: sel.id });
      setSel(out); await reloadLists();
      toast(`Добавлено: ${(out.domains || []).length} дом. / ${(out.ips || []).length} IP`, "ok");
    } catch (e) { toast(e.message, "err"); }
  };

  const saved = (sel && sel.successful_strategies) || [];
  const apply = async (args) => {
    if (!confirm("Применить стратегию в основной конфиг nfqws2?\n\n" + args)) return;
    const restart = confirm("Перезапустить сервис nfqws2 сейчас? (затронет всю сеть)\n\nOK — перезапустить, Отмена — только записать конфиг.");
    try { await api("POST", "/api/apply", { args, restart }); toast(restart ? "Применено и перезапущено" : "Записано в конфиг", "ok"); }
    catch (e) { toast(e.message, "err"); }
  };

  return (
    <div className="grid">
      <aside className="col-lists">
        <button className="btn btn-primary btn-block" onClick={newList}>+ Новый список</button>
        <ul className="cards">
          {lists.map((l) => (
            <li key={l.id} className={sel && sel.id === l.id ? "active" : ""}>
              <div className="li-main" onClick={() => select(l.id)}>
                <div className="nm">{l.name || "(без имени)"}</div>
                <div className="meta">{(l.domains || []).length} дом. · {(l.ips || []).length} IP · {(l.successful_strategies || []).length} рабочих</div>
              </div>
              <button className="li-del" title="Удалить" onClick={(e) => { e.stopPropagation(); del(l.id, l.name); }}>×</button>
            </li>
          ))}
        </ul>
      </aside>
      <div className="col-editor">
        {!sel && <p className="empty">Выберите список слева или создайте новый.</p>}
        {sel && (
          <>
            <Card title="Список" head={sel.id && <button className="btn btn-mini btn-ghost-danger head-action" onClick={() => del(sel.id, sel.name)}>Удалить список</button>}>
              <label className="field">Название<input type="text" value={sel.name || ""} placeholder="Мой список" onChange={(e) => setSel({ ...sel, name: e.target.value })} /></label>
              <div className="two">
                <label className="field">Домены <span className="hint">по одному в строке</span>
                  <textarea rows="7" value={(sel.domains || []).join("\n")} placeholder="rutracker.org&#10;x.com" onChange={(e) => setSel({ ...sel, domains: e.target.value.split("\n") })} /></label>
                <label className="field">IP / CIDR <span className="hint">по одному в строке</span>
                  <textarea rows="7" value={(sel.ips || []).join("\n")} placeholder="1.2.3.0/24" onChange={(e) => setSel({ ...sel, ips: e.target.value.split("\n") })} /></label>
              </div>
              {geo.length > 0 && (
                <div className="geo-row">
                  <label className="field field-grow">Добавить из GeoSite/GeoIP<select value={gFile} onChange={(e) => setGFile(e.target.value)}>{geo.map((f) => <option key={f.name} value={f.name}>{f.name} [{f.kind}]</option>)}</select></label>
                  <label className="field field-grow">Категория<select value={gCat} onChange={(e) => setGCat(e.target.value)}>{cats.map((c) => <option key={c.name} value={c.name}>{c.name} ({c.count})</option>)}</select></label>
                  <label className="field field-sm">Лимит<input type="number" min="0" value={gLimit} onChange={(e) => setGLimit(e.target.value)} /></label>
                  <button className="btn" onClick={geoAdd}>Добавить в список</button>
                </div>
              )}
              <div className="actions"><button className="btn btn-primary" onClick={save}>Сохранить</button></div>
            </Card>
            <Card title="Рабочие стратегии списка" sub="по скорости">
              <div className="table-wrap scrollable">
                <table className="data">
                  <thead><tr><th>Стратегия</th><th>DNS</th><th>Задержка</th><th>Скорость</th><th>Коэф.</th><th className="col-actions"></th></tr></thead>
                  <tbody>
                    {saved.length === 0 && <tr><td colSpan="6" className="empty-cell">Пока нет рабочих стратегий — запустите прогон на этом списке.</td></tr>}
                    {pageSlice(saved, page, pageSize).map((s, i) => (
                      <tr key={s.strategy_id + i} className="ok">
                        <td>{s.name || s.strategy_id}<Args>{s.args}</Args></td>
                        <td><DnsBadge name={s.dns} id={s.dns_id} /></td>
                        <td className="num">{s.avg_ttfb_ms} мс</td>
                        <td className="num">{kb(s.avg_speed_bps)} КБ/с</td>
                        <td className="num">{Math.round(s.coefficient)}</td>
                        <td className="row-actions">
                          <button className="btn btn-mini" onClick={() => apply(s.args)}>Применить</button>
                          <button className="btn btn-mini" title="Экспорт (ZIP)" onClick={() => exportStrategy(s.name || s.strategy_id, "", s.args).catch((e) => toast(e.message, "err"))}>⤓</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager total={saved.length} page={page} setPage={setPage} pageSize={pageSize} setPageSize={setPageSize} />
            </Card>
          </>
        )}
      </div>
    </div>
  );
}

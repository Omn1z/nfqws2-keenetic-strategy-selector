import { useState, useRef } from "react";
import { api, uploadForm } from "../api.js";
import { useStore } from "../store.jsx";
import { toast } from "../toast.jsx";
import { Card, Badge } from "../components.jsx";

function GeoFileCard({ f, lists, onChanged }) {
  const cats = f.categories || [];
  const [cat, setCat] = useState(cats[0]?.name || "");
  const [limit, setLimit] = useState(25);
  const [listId, setListId] = useState("");
  const [newName, setNewName] = useState("");

  const del = async () => {
    if (!confirm("Удалить geo-файл «" + f.name + "»?")) return;
    try { await api("DELETE", "/api/geo/" + encodeURIComponent(f.name)); onChanged(); } catch (e) { toast(e.message, "err"); }
  };
  const imp = async () => {
    if (!cat) { toast("Нет категорий в файле", "err"); return; }
    try {
      const list = await api("POST", "/api/geo/import", { geo: f.name, category: cat, limit: parseInt(limit, 10) || 0, list_id: listId, list_name: newName.trim() });
      toast(`Импортировано в «${list.name}» (${(list.domains || []).length} дом. / ${(list.ips || []).length} IP)`, "ok");
      onChanged();
    } catch (e) { toast(e.message, "err"); }
  };

  return (
    <Card>
      <div className="card-head geo-title">
        <h2>{f.name}</h2><Badge>{f.kind}</Badge><span className="hint">{cats.length} категорий</span>
        <button className="btn btn-mini btn-ghost-danger" style={{ marginLeft: "auto" }} onClick={del}>Удалить</button>
      </div>
      <div className="geo-row">
        <label className="field field-grow">Категория<select value={cat} onChange={(e) => setCat(e.target.value)}>{cats.map((c) => <option key={c.name} value={c.name}>{c.name} ({c.count})</option>)}</select></label>
        <label className="field field-sm">Лимит<input type="number" min="0" value={limit} onChange={(e) => setLimit(e.target.value)} /></label>
        <label className="field field-grow">В список<select value={listId} onChange={(e) => setListId(e.target.value)}><option value="">— новый список —</option>{lists.map((l) => <option key={l.id} value={l.id}>{l.name || l.id}</option>)}</select></label>
        {!listId && <label className="field field-grow">Имя нового<input type="text" value={newName} placeholder={f.name + ":категория"} onChange={(e) => setNewName(e.target.value)} /></label>}
        <button className="btn btn-primary" onClick={imp}>Импортировать</button>
      </div>
    </Card>
  );
}

export default function Geo() {
  const { geo, reloadGeo, lists, reloadLists } = useStore();
  const [kind, setKind] = useState("geosite");
  const [drag, setDrag] = useState(false);
  const [status, setStatus] = useState("");
  const fileRef = useRef(null);

  const upload = async (file) => {
    if (!file) return;
    setStatus("Загрузка: " + file.name);
    const fd = new FormData(); fd.append("file", file); fd.append("kind", kind);
    try { const d = await uploadForm("/api/geo", fd); setStatus("✓ " + d.name); toast("Загружено: " + d.name, "ok"); await reloadGeo(); }
    catch (e) { setStatus(""); toast(e.message, "err"); }
  };
  const onChanged = async () => { await reloadGeo(); await reloadLists(); };

  return (
    <>
      <Card title="GeoSite / GeoIP">
        <p className="hint">Загрузите <code>geosite.dat</code> / <code>geoip.dat</code> (формат v2ray) или текстовый список (домен/IP в строке). Затем импортируйте нужную категорию в тестовый список.</p>
        <div className="geo-upload">
          <label className="field field-sm">Тип<select value={kind} onChange={(e) => setKind(e.target.value)}><option value="geosite">geosite.dat</option><option value="geoip">geoip.dat</option><option value="text">текст</option></select></label>
          <div className={"dropzone" + (drag ? " drag" : "")} tabIndex={0} role="button" onClick={() => fileRef.current.click()}
            onDragEnter={(e) => { e.preventDefault(); setDrag(true); }} onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
            onDragLeave={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setDrag(false); }}
            onDrop={(e) => { e.preventDefault(); setDrag(false); upload(e.dataTransfer.files[0]); }}>
            <svg className="dz-icon" viewBox="0 0 24 24" width="30" height="30"><path d="M12 16V4m0 0 4 4m-4-4L8 8M5 16v2a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-2" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
            <div className="dz-text"><b>Перетащите файл</b> или нажмите</div>
            <div className="dz-name">{status}</div>
            <input ref={fileRef} type="file" hidden onChange={(e) => { if (e.target.files[0]) upload(e.target.files[0]); e.target.value = ""; }} />
          </div>
        </div>
      </Card>
      {geo.map((f) => <GeoFileCard key={f.name} f={f} lists={lists} onChanged={onChanged} />)}
    </>
  );
}

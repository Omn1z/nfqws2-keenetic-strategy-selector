import { useState, useRef } from "react";
import { api, uploadForm, downloadFile } from "../api.js";
import { useStore } from "../store.jsx";
import { toast } from "../toast.jsx";
import { Card } from "../components.jsx";

export default function Blobs() {
  const { blobs, reloadBlobs } = useStore();
  const [sel, setSel] = useState(new Set());
  const [drag, setDrag] = useState(false);
  const [status, setStatus] = useState("");
  const fileRef = useRef(null);

  const all = [...blobs.custom.map((n) => ({ name: n, custom: true })), ...blobs.system.map((n) => ({ name: n, custom: false }))];
  const toggle = (n) => { const s = new Set(sel); s.has(n) ? s.delete(n) : s.add(n); setSel(s); };
  const toggleAll = () => setSel(sel.size === all.length ? new Set() : new Set(all.map((b) => b.name)));
  const selCustom = () => [...sel].filter((n) => blobs.custom.includes(n));

  const upload = async (files) => {
    files = Array.from(files || []); if (!files.length) return;
    const existing = new Set(blobs.custom.map((n) => n.toLowerCase())), dups = [];
    const queue = files.filter((f) => {
      if (/\.zip$/i.test(f.name)) return true;
      if (existing.has(f.name.toLowerCase())) { dups.push(f.name); return false; }
      return true;
    });
    if (dups.length) toast(`Пропущены дубликаты (${dups.length}): ` + dups.join(", "), "warn");
    if (!queue.length) { setStatus("дубликаты пропущены: " + dups.length); return; }
    let ok = 0;
    for (const file of queue) {
      setStatus("Загрузка: " + file.name);
      const zip = /\.zip$/i.test(file.name);
      const fd = new FormData(); fd.append("file", file);
      try { const d = await uploadForm(zip ? "/api/blobs/zip" : "/api/blobs", fd); ok += zip ? (d.imported || 0) : 1; }
      catch (e) { toast(file.name + ": " + e.message, "err"); }
    }
    setStatus("✓ загружено: " + ok + (dups.length ? " · пропущено дубликатов: " + dups.length : ""));
    if (ok) toast("Блобы загружены: " + ok, "ok");
    await reloadBlobs(); setSel(new Set());
  };
  const del = async (name) => {
    if (!confirm("Удалить блоб «" + name + "»?")) return;
    try { await api("DELETE", "/api/blobs/" + encodeURIComponent(name)); toast("Блоб удалён", "ok"); await reloadBlobs(); }
    catch (e) { toast(e.message, "err"); }
  };
  const exportSel = () => {
    const names = [...sel]; if (!names.length) { toast("Выберите блобы для экспорта", "err"); return; }
    downloadFile("/api/blobs/export", "blobs.zip", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ names }) }).catch((e) => toast(e.message, "err"));
  };
  const delSel = async () => {
    const names = selCustom(); if (!names.length) { toast("Выберите пользовательские блобы", "err"); return; }
    if (!confirm("Удалить выбранные блобы (" + names.length + ")?")) return;
    for (const n of names) { try { await api("DELETE", "/api/blobs/" + encodeURIComponent(n)); } catch (e) { toast(n + ": " + e.message, "err"); } }
    toast("Удалено: " + names.length, "ok"); await reloadBlobs(); setSel(new Set());
  };

  return (
    <>
      <Card title="Загрузка блобов">
        <p className="hint">Свой блоб используется в стратегии так: <code>--blob=имя:@/путь</code>. Можно загрузить несколько файлов сразу или ZIP-архив.</p>
        <div className={"dropzone" + (drag ? " drag" : "")} tabIndex={0} role="button" onClick={() => fileRef.current.click()}
          onDragEnter={(e) => { e.preventDefault(); setDrag(true); }} onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setDrag(false); }}
          onDrop={(e) => { e.preventDefault(); setDrag(false); upload(e.dataTransfer.files); }}>
          <svg className="dz-icon" viewBox="0 0 24 24" width="34" height="34"><path d="M12 16V4m0 0 4 4m-4-4L8 8M5 16v2a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-2" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <div className="dz-text"><b>Перетащите файлы или ZIP</b> или нажмите, чтобы выбрать</div>
          <div className="dz-name">{status}</div>
          <input ref={fileRef} type="file" multiple hidden onChange={(e) => { upload(e.target.files); e.target.value = ""; }} />
        </div>
      </Card>
      <Card title="Список блобов" head={
        <div className="head-action" style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-mini" onClick={exportSel}>Экспорт выбранных (ZIP)</button>
          {selCustom().length > 0 && <button className="btn btn-mini btn-ghost-danger" onClick={delSel}>Удалить выбранные</button>}
        </div>
      }>
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th style={{ width: 30 }}><input type="checkbox" checked={all.length > 0 && sel.size === all.length} onChange={toggleAll} /></th><th>Имя</th><th>Тип</th><th></th></tr></thead>
            <tbody>
              {all.length === 0 && <tr><td colSpan="4" className="empty-cell">Нет блобов.</td></tr>}
              {all.map((b) => (
                <tr key={b.name}>
                  <td><input type="checkbox" checked={sel.has(b.name)} onChange={() => toggle(b.name)} /></td>
                  <td className="mono">{b.name}</td>
                  <td>{b.custom ? "свой" : "системный"}</td>
                  <td>{b.custom && <button className="btn btn-mini btn-ghost-danger" onClick={() => del(b.name)}>×</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

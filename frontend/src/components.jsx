import { useState, useEffect, useImperativeHandle } from "react";
import { api } from "./api.js";
import { VERDICT } from "./util.js";

export const Card = ({ title, sub, head, children }) => (
  <div className="card">
    {(title || head) && (
      <div className="card-head">
        {title && <h2>{title}</h2>}
        {sub && <span className="hint">{sub}</span>}
        {head}
      </div>
    )}
    {children}
  </div>
);

export const Badge = ({ kind, children }) => <span className={"badge " + (kind || "")}>{children}</span>;

export const VerdictBadge = ({ v }) => {
  const [label, kind] = VERDICT[v] || [v || "?", "bad"];
  return <Badge kind={kind}>{label}</Badge>;
};

// DnsBadge highlights which DNS produced a result (system = muted).
export const DnsBadge = ({ name, id }) =>
  !name ? <span>—</span> : <span className={"dns-tag" + (id ? "" : " sys")}>{name}</span>;

export const Switch = ({ checked, onChange, label }) => (
  <label className="switch">
    <input type="checkbox" checked={!!checked} onChange={(e) => onChange(e.target.checked)} />
    <span className="track" />
    {label}
  </label>
);

export const Args = ({ children }) => (
  <div className="args" title={children}>{children}</div>
);

// pageSlice returns the rows for the current page (pageSize may be "all").
export function pageSlice(arr, page, pageSize) {
  const total = arr.length;
  const size = pageSize === "all" ? Math.max(total, 1) : parseInt(pageSize, 10);
  const pages = Math.max(1, Math.ceil(total / size));
  const p = Math.min(Math.max(page, 1), pages);
  return arr.slice((p - 1) * size, (p - 1) * size + size);
}

// Pager — page-size select + prev/next, rendered BELOW the table.
export function Pager({ total, page, setPage, pageSize, setPageSize }) {
  const size = pageSize === "all" ? Math.max(total, 1) : parseInt(pageSize, 10);
  const pages = Math.max(1, Math.ceil(total / size));
  const p = Math.min(Math.max(page, 1), pages);
  if (total === 0) return null;
  return (
    <div className="pager">
      <label className="pager-size">Показывать
        <select value={pageSize} onChange={(e) => { setPageSize(e.target.value); setPage(1); }}>
          <option value="20">20</option>
          <option value="50">50</option>
          <option value="100">100</option>
          <option value="all">Все</option>
        </select>
      </label>
      <button className="btn btn-mini" disabled={p <= 1} onClick={() => setPage(p - 1)}>‹ Назад</button>
      <span className="hint">стр. {p} из {pages} · {total} записей</span>
      <button className="btn btn-mini" disabled={p >= pages} onClick={() => setPage(p + 1)}>Вперёд ›</button>
    </div>
  );
}

// Checklist — controlled multi-select with a smart select-all toggle.
export function Checklist({ title, hint, items, value, onChange, disabled }) {
  const sel = new Set(value);
  const allOn = items.length > 0 && items.every((i) => sel.has(i.value));
  const toggleAll = () => onChange(allOn ? [] : items.map((i) => i.value));
  const toggle = (v) => { const s = new Set(sel); s.has(v) ? s.delete(v) : s.add(v); onChange([...s]); };
  return (
    <div className="field field-grow">
      <div className="cl-head">
        <span>{title} {hint && <span className="hint">{hint}</span>}</span>
        <button type="button" className="btn btn-mini" disabled={disabled} onClick={toggleAll}>
          {allOn ? "Снять все" : "Выбрать все"}
        </button>
      </div>
      <div className={"checklist" + (disabled ? " disabled" : "")}>
        {items.map((it) => (
          <label key={it.value} className="cl-item">
            <input type="checkbox" checked={sel.has(it.value)} disabled={disabled} onChange={() => toggle(it.value)} />
            <span className="cl-text">{it.label}</span>
            {it.sub && <span className="cl-sub">{it.sub}</span>}
          </label>
        ))}
      </div>
    </div>
  );
}

// SourceSelector — segmented "Список / GeoSite-GeoIP / Текст" target picker.
// Parent holds a ref and calls `await ref.current.resolve()` → {list_id}|{targets}.
export function SourceSelector({ lists, geo, initialText, ref }) {
  const [mode, setMode] = useState(initialText ? "text" : "list");
  const [listId, setListId] = useState("");
  const [geoFile, setGeoFile] = useState("");
  const [geoCat, setGeoCat] = useState("");
  const [geoLimit, setGeoLimit] = useState(50);
  const [text, setText] = useState(initialText || "");

  useEffect(() => { if (!listId && lists[0]) setListId(lists[0].id); }, [lists, listId]);
  useEffect(() => { if (!geoFile && geo[0]) setGeoFile(geo[0].name); }, [geo, geoFile]);
  const cats = (geo.find((g) => g.name === geoFile)?.categories) || [];
  useEffect(() => { if (cats[0] && !cats.some((c) => c.name === geoCat)) setGeoCat(cats[0].name); }, [geoFile, cats, geoCat]);

  useImperativeHandle(ref, () => ({
    async resolve() {
      if (mode === "list") {
        if (!listId) throw new Error("Нет списков — создайте список во вкладке «Списки»");
        return { list_id: listId };
      }
      if (mode === "geo") {
        if (!geoFile || !geoCat) throw new Error("Загрузите GeoSite/GeoIP и выберите категорию");
        const r = await api("POST", "/api/geo/resolve", { geo: geoFile, category: geoCat, limit: parseInt(geoLimit, 10) || 0 });
        const t = (r && r.targets) || [];
        if (!t.length) throw new Error("Категория пустая");
        return { targets: t };
      }
      const t = text.split("\n").map((s) => s.trim()).filter(Boolean);
      if (!t.length) throw new Error("Введите домены или IP");
      return { targets: t };
    },
  }), [mode, listId, geoFile, geoCat, geoLimit, text]);

  const seg = (m, label) => (
    <button type="button" className={"seg-btn" + (mode === m ? " active" : "")} onClick={() => setMode(m)}>{label}</button>
  );
  return (
    <div className="srcsel">
      <div className="seg">{seg("list", "Список")}{seg("geo", "GeoSite/GeoIP")}{seg("text", "Текст")}</div>
      {mode === "list" && (
        <label className="field field-grow">Список
          <select value={listId} onChange={(e) => setListId(e.target.value)}>
            {lists.map((l) => <option key={l.id} value={l.id}>{(l.name || l.id)} ({(l.domains || []).length} дом. / {(l.ips || []).length} IP)</option>)}
          </select>
        </label>
      )}
      {mode === "geo" && (
        <div className="geo-row">
          <label className="field field-grow">Файл
            <select value={geoFile} onChange={(e) => setGeoFile(e.target.value)}>
              {geo.map((f) => <option key={f.name} value={f.name}>{f.name} [{f.kind}]</option>)}
            </select>
          </label>
          <label className="field field-grow">Категория
            <select value={geoCat} onChange={(e) => setGeoCat(e.target.value)}>
              {cats.map((c) => <option key={c.name} value={c.name}>{c.name} ({c.count})</option>)}
            </select>
          </label>
          <label className="field field-sm">Лимит
            <input type="number" min="0" value={geoLimit} onChange={(e) => setGeoLimit(e.target.value)} />
          </label>
        </div>
      )}
      {mode === "text" && (
        <label className="field">Домены / IP <span className="hint">по одному в строке</span>
          <textarea rows="5" value={text} placeholder="rutracker.org&#10;1.2.3.4" onChange={(e) => setText(e.target.value)} />
        </label>
      )}
    </div>
  );
}

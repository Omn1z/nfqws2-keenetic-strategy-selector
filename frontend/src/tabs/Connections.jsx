import { useState } from "react";
import { api } from "../api.js";
import { usePoll } from "../hooks.js";
import { Card, Pager, pageSlice } from "../components.jsx";
import { human, connFailing } from "../util.js";

const sortVal = (c, k) => {
  switch (k) {
    case "proto": return c.proto || "";
    case "state": return c.state || (c.unreplied ? "UNREPLIED" : "");
    case "src": return c.src || "";
    case "dst": return c.dst || "";
    case "dport": return c.dport || 0;
    case "bytes": return (c.bytes || 0) + (c.reply_bytes || 0);
    case "zone": return c.zone || "";
  }
  return 0;
};

export default function Connections() {
  const [conns, setConns] = useState([]);
  const [filter, setFilter] = useState("");
  const [failOnly, setFailOnly] = useState(false);
  const [sort, setSort] = useState({ key: "bytes", dir: -1 });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState("50");

  usePoll(async () => { try { const v = await api("GET", "/api/connections"); setConns(v.items || []); } catch (_) {} }, 3000);

  const f = filter.toLowerCase().trim();
  let rows = conns.filter((c) => {
    if (failOnly && !connFailing(c)) return false;
    if (!f) return true;
    return [c.proto, c.state, c.src, c.dst, String(c.dport || ""), c.zone].some((x) => String(x || "").toLowerCase().includes(f));
  });
  rows = [...rows].sort((a, b) => { const va = sortVal(a, sort.key), vb = sortVal(b, sort.key); return va < vb ? -sort.dir : va > vb ? sort.dir : 0; });
  const failTotal = conns.filter(connFailing).length;

  const th = (k, l) => (
    <th data-sort={k} onClick={() => setSort((s) => s.key === k ? { key: k, dir: -s.dir } : { key: k, dir: (k === "bytes" || k === "dport") ? -1 : 1 })}>{l}</th>
  );
  const head = <span className="head-action hint">{rows.length} из {conns.length} · не отвечают {failTotal}</span>;

  return (
    <Card title="Активные соединения" sub="обновляется, пока открыта вкладка" head={head}>
      <div className="conns-toolbar">
        <input type="search" placeholder="Фильтр: IP, порт, протокол, состояние…" value={filter} onChange={(e) => { setFilter(e.target.value); setPage(1); }} />
        <label className="switch"><input type="checkbox" checked={failOnly} onChange={(e) => { setFailOnly(e.target.checked); setPage(1); }} /><span className="track" />только проблемные</label>
      </div>
      <div className="table-wrap scrollable">
        <table className="data">
          <thead><tr>{th("proto", "Proto")}{th("state", "Состояние")}{th("src", "Источник (LAN)")}{th("dst", "Назначение")}{th("dport", "Порт")}{th("bytes", "Трафик")}{th("zone", "Зона")}</tr></thead>
          <tbody>
            {pageSlice(rows, page, pageSize).map((c, i) => {
              const fail = connFailing(c);
              const label = c.state || (c.unreplied ? "нет ответа" : (c.proto === "udp" ? "udp" : "—"));
              const cls = fail ? "bad" : (c.state === "ESTABLISHED" ? "ok" : "");
              return (
                <tr key={`${c.proto}|${c.src}|${c.sport}|${c.dst}|${c.dport}|${i}`} className={fail ? "fail" : ""}>
                  <td>{c.proto}</td>
                  <td><span className={"conn-badge " + cls}>{label}</span></td>
                  <td className="mono">{c.src}</td>
                  <td className="mono">{c.dst}</td>
                  <td className="num">{c.dport || "—"}</td>
                  <td className="num">{human((c.bytes || 0) + (c.reply_bytes || 0))}</td>
                  <td>{c.zone || ""}</td>
                </tr>
              );
            })}
            {rows.length === 0 && <tr><td colSpan="7" className="empty-cell">Нет соединений.</td></tr>}
          </tbody>
        </table>
      </div>
      <Pager total={rows.length} page={page} setPage={setPage} pageSize={pageSize} setPageSize={setPageSize} />
    </Card>
  );
}

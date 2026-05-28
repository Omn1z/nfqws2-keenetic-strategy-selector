import { useState, useRef, useEffect } from "react";
import { api, exportStrategy } from "../api.js";
import { useStore } from "../store.jsx";
import { toast } from "../toast.jsx";
import { usePoll } from "../hooks.js";
import { Card, Pager, pageSlice, Args, DnsBadge, Checklist, SourceSelector, VerdictBadge, Switch } from "../components.jsx";
import { kb } from "../util.js";

const sortVal = (r, k) => {
  switch (k) {
    case "status": return r.error ? 0 : (r.success ? 2 : 1);
    case "name": return (r.name || "").toLowerCase();
    case "dns": return (r.dns || "").toLowerCase();
    case "targets": return r.targets_ok;
    case "latency": return r.avg_ttfb_ms || 1e12;
    case "speed": return r.avg_speed_bps;
    case "coef": return r.coefficient;
  }
  return 0;
};
const FILTERS = { all: () => true, one: (r) => r.targets_ok > 0, "50": (r) => r.targets_total && r.targets_ok / r.targets_total >= 0.5,
  "75": (r) => r.targets_total && r.targets_ok / r.targets_total >= 0.75, "100": (r) => r.targets_total > 0 && r.targets_ok === r.targets_total };

export default function Runs() {
  const { lists, geo, strategies, blobs, dns, reloadLists, pendingTargets, setPendingTargets } = useStore();
  const srcRef = useRef(null);
  const [initialText] = useState(() => (pendingTargets ? pendingTargets.join("\n") : ""));
  useEffect(() => { if (pendingTargets) setPendingTargets(null); }, []); // consume the handoff once

  const [threads, setThreads] = useState(4);
  const [auto, setAuto] = useState(false);
  const [stratSel, setStratSel] = useState([]);
  const [blobSel, setBlobSel] = useState([]);
  const [dnsSel, setDnsSel] = useState([]);

  const [run, setRun] = useState(null);
  const [running, setRunning] = useState(false);
  const [sort, setSort] = useState({ key: "coef", dir: -1 });
  const [filterMode, setFilterMode] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState("20");

  const stratItems = strategies.map((s) => ({ value: s.id, label: s.name || s.id, sub: s.l7 || "?" }));
  const blobItems = [...blobs.custom.map((n) => ({ value: n, label: n, sub: "свой" })), ...blobs.system.map((n) => ({ value: n, label: n }))];
  const dnsItems = [{ value: "system", label: "Системный", sub: "без DoH/DoT" }, ...dns.map((d) => ({ value: d.id, label: d.name || d.id, sub: (d.type || "").toUpperCase() }))];

  usePoll(async () => {
    if (!run) return;
    try {
      const r = await api("GET", "/api/runs/" + run.id);
      setRun(r);
      if (r.status !== "running") {
        setRunning(false);
        reloadLists();
        const ok = (r.results || []).filter((x) => x.success).length;
        if (r.status === "cancelled") toast("Прогон отменён", "ok");
        else if (r.auto && r.total === 0) toast("Цели доступны без обхода — обходить нечего", "ok");
        else toast(`Прогон завершён: найдено рабочих ${ok}`, "ok");
      }
    } catch (e) { setRunning(false); toast(e.message, "err"); }
  }, 1000, running);

  const start = async () => {
    let target;
    try { target = await srcRef.current.resolve(); } catch (e) { toast(e.message, "err"); return; }
    const req = { ...target, strategy_ids: auto ? [] : stratSel, blobs: blobSel, dns: dnsSel, auto, threads: parseInt(threads, 10) || 4 };
    try { const r = await api("POST", "/api/runs", req); setRun(r); setPage(1); setRunning(true); }
    catch (e) { toast(e.message, "err"); }
  };
  const cancel = async () => { setRunning(false); if (run) { try { await api("POST", "/api/runs/" + run.id + "/cancel"); } catch (_) {} } };
  const addThread = async () => {
    if (!run) return;
    const next = (run.threads || 1) + 1;
    if (next > 8) { toast("Максимум 8 потоков", "err"); return; }
    try { const d = await api("POST", "/api/runs/" + run.id + "/threads", { threads: next }); toast("Потоков: " + d.threads, "ok"); }
    catch (e) { toast(e.message, "err"); }
  };
  const apply = async (args) => {
    if (!confirm("Применить стратегию в основной конфиг nfqws2?\n\n" + args)) return;
    const restart = confirm("Перезапустить сервис nfqws2 сейчас? (затронет всю сеть)\n\nOK — перезапустить, Отмена — только записать конфиг.");
    try { await api("POST", "/api/apply", { args, restart }); toast(restart ? "Применено и перезапущено" : "Записано в конфиг", "ok"); }
    catch (e) { toast(e.message, "err"); }
  };

  const results = run?.results || [];
  const filtered = results.filter(FILTERS[filterMode]);
  const sorted = [...filtered].sort((a, b) => { const va = sortVal(a, sort.key), vb = sortVal(b, sort.key); return va < vb ? -sort.dir : va > vb ? sort.dir : 0; });
  const th = (k, l) => <th data-sort={k} onClick={() => setSort((s) => s.key === k ? { key: k, dir: -s.dir } : { key: k, dir: k === "latency" ? 1 : -1 })}>{l}</th>;
  const found = results.filter((x) => x.success).length, errored = results.filter((x) => x.error).length;
  const pct = run && run.total ? Math.round(run.done * 100 / run.total) : 0;
  const base = (run && run.auto && run.baseline) || [];

  return (
    <>
      <Card title="Прогон стратегий" sub="подбор рабочих стратегий обхода">
        <SourceSelector ref={srcRef} lists={lists} geo={geo} initialText={initialText} />
        <div className="run-row mid">
          <label className="field field-sm">Потоков<input type="number" min="1" max="8" value={threads} onChange={(e) => setThreads(e.target.value)} /></label>
          <div className="field auto-field"><span className="field-cap">Автоподбор</span><Switch checked={auto} onChange={setAuto} /></div>
        </div>
        <div className="run-row cols">
          <Checklist title="Стратегии" hint="пусто = все" items={stratItems} value={stratSel} onChange={setStratSel} disabled={auto} />
          <Checklist title="Блобы" hint="каждый блоб — отдельный прогон" items={blobItems} value={blobSel} onChange={setBlobSel} />
          <Checklist title="DNS" hint="каждый DNS — отдельный прогон" items={dnsItems} value={dnsSel} onChange={setDnsSel} />
        </div>
        {auto && <p className="hint">Автоподбор сам перебирает встроенный каталог кандидатов — выбор стратегий не используется.</p>}
        <div className="actions">
          <button className="btn btn-primary" onClick={start} disabled={running}>▶ Запустить прогон</button>
          {running && <button className="btn btn-ghost-danger" onClick={cancel}>■ Отменить</button>}
          {running && <button className="btn btn-mini" onClick={addThread} disabled={(run?.threads || 0) >= 8}>+ поток</button>}
          {run && <span className="run-status">{run.status}</span>}
        </div>
        {running && (
          <div>
            <div className="progress"><div className="progress-bar" style={{ width: pct + "%" }} /></div>
            <span className="hint">{run.done}/{run.total} стратегий · {run.threads} потоков · найдено {found} · с ошибкой {errored} · {run.status}</span>
          </div>
        )}
      </Card>

      <Card title="Результаты прогона" sub="клик по заголовку — сортировка" head={
        <label className="pager-size head-action">Показывать
          <select value={filterMode} onChange={(e) => { setFilterMode(e.target.value); setPage(1); }}>
            <option value="all">Все</option>
            <option value="one">≥1 цель пройдена</option>
            <option value="50">≥50% целей</option>
            <option value="75">≥75% целей</option>
            <option value="100">100% целей</option>
          </select>
        </label>
      }>
        {base.length > 0 && (
          <div className="baseline">
            <b>Базовый замер без обхода:</b> заблокировано {base.filter((b) => b.blocked).length} из {base.length}.{" "}
            {base.filter((b) => b.blocked).length === 0 ? "Обходить нечего — всё доступно." : "Автоподбор тестируется только на заблокированных целях."}
            <div style={{ marginTop: 6 }}>{base.map((b, i) => <span key={i}>{b.host} <VerdictBadge v={b.verdict} /> </span>)}</div>
          </div>
        )}
        <div className="table-wrap scrollable">
          <table className="data">
            <thead><tr>{th("status", "Статус")}{th("name", "Стратегия")}{th("dns", "DNS")}{th("targets", "Цели")}{th("latency", "Задержка")}{th("speed", "Скорость")}{th("coef", "Коэф.")}<th className="col-actions"></th></tr></thead>
            <tbody>
              {sorted.length === 0 && <tr><td colSpan="8" className="empty-cell">{results.length ? "Нет результатов под фильтр." : "Запустите прогон."}</td></tr>}
              {pageSlice(sorted, page, pageSize).map((r, i) => (
                <tr key={(r.strategy_id || "") + (r.dns_id || "") + i} className={r.success ? "ok" : "fail"}>
                  <td>{r.error ? <span className="badge bad" title={r.error}>ошибка</span> : (r.success ? <span className="badge ok">OK</span> : <span className="badge bad">нет</span>)}</td>
                  <td>{r.name || r.strategy_id}<Args>{r.args}</Args></td>
                  <td><DnsBadge name={r.dns} id={r.dns_id} /></td>
                  <td className="num">{r.targets_ok}/{r.targets_total}</td>
                  <td className="num">{r.avg_ttfb_ms ? r.avg_ttfb_ms + " мс" : "—"}</td>
                  <td className="num">{r.avg_speed_bps ? kb(r.avg_speed_bps) + " КБ/с" : "—"}</td>
                  <td className="num">{r.coefficient ? Math.round(r.coefficient) : "—"}</td>
                  <td className="row-actions">
                    {r.success && <button className="btn btn-mini" onClick={() => apply(r.args)}>Применить</button>}
                    <button className="btn btn-mini" title="Экспорт (ZIP)" onClick={() => exportStrategy(r.name || r.strategy_id, r.l7 || "", r.args).catch((e) => toast(e.message, "err"))}>⤓</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pager total={sorted.length} page={page} setPage={setPage} pageSize={pageSize} setPageSize={setPageSize} />
      </Card>
    </>
  );
}

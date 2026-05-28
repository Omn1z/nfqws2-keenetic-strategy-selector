import { useState, useRef } from "react";
import { api } from "../api.js";
import { useStore } from "../store.jsx";
import { toast } from "../toast.jsx";
import { usePoll } from "../hooks.js";
import { Card, SourceSelector, VerdictBadge, Args } from "../components.jsx";
import { kb } from "../util.js";

export default function BlockCheck() {
  const { lists, geo } = useStore();
  const srcRef = useRef(null);
  const [threads, setThreads] = useState(4);
  const [bc, setBc] = useState(null);
  const [running, setRunning] = useState(false);

  usePoll(async () => {
    if (!bc) return;
    try {
      const r = await api("GET", "/api/blockcheck/" + bc.id);
      setBc(r);
      if (r.status !== "running") {
        setRunning(false);
        const blocked = (r.targets || []).filter((t) => t.blocked).length;
        if (r.status === "cancelled") toast("Проверка отменена", "ok");
        else toast(`Проверка завершена: заблокировано ${blocked} из ${r.total}`, "ok");
      }
    } catch (e) { setRunning(false); toast(e.message, "err"); }
  }, 1000, running);

  const start = async () => {
    let target;
    try { target = await srcRef.current.resolve(); } catch (e) { toast(e.message, "err"); return; }
    try { const r = await api("POST", "/api/blockcheck", { ...target, threads: parseInt(threads, 10) || 4 }); setBc(r); setRunning(true); }
    catch (e) { toast(e.message, "err"); }
  };
  const cancel = async () => { setRunning(false); if (bc) { try { await api("POST", "/api/blockcheck/" + bc.id + "/cancel"); } catch (_) {} } };

  const targets = bc?.targets || [];
  const pct = bc && bc.total ? Math.round(bc.done * 100 / bc.total) : 0;

  return (
    <>
      <Card title="BlockCheck" sub="проверка блокировки без обхода">
        <p className="hint">Проверяет доступность доменов/IP напрямую: тестовое соединение исключается из основного сервиса nfqws2 и не обходится, поэтому видно, что реально блокирует провайдер (RST, таймаут, обрыв на ~16 КБ).</p>
        <SourceSelector ref={srcRef} lists={lists} geo={geo} />
        <div className="run-row mid"><label className="field field-sm">Потоков<input type="number" min="1" max="8" value={threads} onChange={(e) => setThreads(e.target.value)} /></label></div>
        <div className="actions">
          <button className="btn btn-primary" onClick={start} disabled={running}>▶ Проверить</button>
          {running && <button className="btn btn-ghost-danger" onClick={cancel}>■ Отменить</button>}
          {bc && <span className="run-status">{bc.status}</span>}
        </div>
        {running && <div><div className="progress"><div className="progress-bar" style={{ width: pct + "%" }} /></div><span className="hint">{bc.done}/{bc.total} целей · {bc.status}</span></div>}
      </Card>
      <Card title="Результаты проверки" sub="заблокированные сверху">
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>Цель</th><th>Статус</th><th>Задержка</th><th>Скорость</th><th>Код</th></tr></thead>
            <tbody>
              {targets.length === 0 && <tr><td colSpan="5" className="empty-cell">Запустите проверку.</td></tr>}
              {[...targets].sort((a, b) => (b.blocked ? 1 : 0) - (a.blocked ? 1 : 0)).map((t, i) => (
                <tr key={t.host + i} className={t.blocked ? "blocked" : "reachable"}>
                  <td>{t.host}</td>
                  <td><VerdictBadge v={t.verdict} />{t.err && <Args>{t.err}</Args>}</td>
                  <td className="num">{t.ttfb_ms ? t.ttfb_ms + " мс" : "—"}</td>
                  <td className="num">{t.speed_bps ? kb(t.speed_bps) + " КБ/с" : "—"}</td>
                  <td className="num">{t.code || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

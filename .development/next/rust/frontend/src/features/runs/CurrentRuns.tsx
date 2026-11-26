import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useStore } from "@/providers/StoreProvider";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { PageHeader, compactCard } from "@/components/ui/FeaturePage";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import type { RunStatus } from "@/types/api";

export interface RunCapabilities {
  modes: string[];
  max_targets: number;
  max_threads: number;
  installed: boolean;
}
interface Check { host: string; ok: boolean; code: number; ttfb_ms: number; error?: string }
interface Report {
  mode: string; id: string; list_name: string; checks: Check[]; threads: number;
  started_at: number; total: number; done: number; status: RunStatus; error?: string;
}
const statusText = {running:"Выполняется", done:"Завершён", cancelled:"Отменён", error:"Прерван"};
const errorText = (e:unknown) => e instanceof Error ? e.message : String(e);
export function CheckResults({ report }: { report: Report }) {
  return <Card title={report.list_name} className={compactCard}
    sub={`${statusText[report.status]} · ${report.done}/${report.total} доменов · потоков: ${report.threads}`}>
    {report.error && <p role="alert" className="mb-2 text-sm text-bad">{report.error === "interrupted" ? "Процесс панели был остановлен." : report.error}</p>}
    <TableWrap><table className={tableCls}><thead><tr>
      <th className={thBase}>Домен</th><th className={thBase}>HTTPS</th><th className={thBase}>До первого байта</th>
    </tr></thead><tbody>{report.checks.map(c => <tr key={c.host}>
      <td className={tdCls}>{c.host}</td><td className={tdCls}><span className={c.ok ? "text-ok" : "text-bad"}>{c.code ? `HTTP ${c.code}` : c.error || "Ошибка"}</span></td>
      <td className={tdCls}>{c.code ? `${c.ttfb_ms} мс` : "—"}</td>
    </tr>)}</tbody></table></TableWrap>
  </Card>;
}
export function CurrentRuns({ caps }: { caps: RunCapabilities }) {
  const { lists, pendingTargets, setPendingTargets } = useStore();
  const [text,setText] = useState(() => pendingTargets?.join("\n") ?? "");
  const [list,setList] = useState("");
  const [threads,setThreads] = useState("2");
  const [history,setHistory] = useState<Report[]>([]);
  const [selected,setSelected] = useState("");
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState("");
  const [loaded,setLoaded] = useState(false);
  const [retry,setRetry] = useState(0);
  const active = history.find(r => r.status === "running");
  const report = history.find(r => r.id === selected) ?? active ?? history[0];
  useEffect(() => { if(pendingTargets) setPendingTargets(null); }, [pendingTargets, setPendingTargets]);
  useEffect(() => {
    if(!caps.installed) return;
    const ctrl = new AbortController();
    void api<Report[]>("GET","/api/runs",undefined,{signal:ctrl.signal}).then(r => {
      if(!ctrl.signal.aborted) {setHistory(r.filter(v => v.mode === "current_https")); setLoaded(true); setError("");}
    }).catch(e => {if(!ctrl.signal.aborted) setError(errorText(e));});
    return () => ctrl.abort();
  }, [caps.installed, retry]);
  useEffect(() => {
    if(!active) return;
    const ctrl = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const next=await api<Report>("GET", `/api/runs/${active.id}`, undefined, {signal:ctrl.signal});
        if(ctrl.signal.aborted) return;
        setHistory(rows=>rows.map(row=>row.id===next.id ? next : row));
        if(next.status !== "running") return;
      } catch(e) { if(ctrl.signal.aborted) return; setError(errorText(e)); }
      timer=setTimeout(poll,1000);
    };
    timer=setTimeout(poll,250);
    return () => {ctrl.abort(); clearTimeout(timer);};
  }, [active?.id]);
  const submit = async (work:()=>Promise<void>) => {
    setBusy(true); setError("");
    try {await work();} catch(e) {setError(errorText(e));} finally {setBusy(false);}
  };
  const n = Number(threads);
  const validThreads = Number.isInteger(n) && n >= 1 && n <= caps.max_threads;
  const start = () => submit(async () => {
    const source=list ? {list_id:list} : {targets:text.split(/[\s,;]+/).filter(Boolean)};
    const next=await api<Report>("POST","/api/runs",{mode:"current_https", ...source, threads:n});
    setHistory(rows=>[next,...rows].slice(0,30));setSelected(next.id);
  });
  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="Проверка текущей конфигурации" description="Роутер отправляет HTTPS HEAD на порт 443 каждого выбранного домена. В результатах сохраняются HTTP-код и время до первого байта." />
    {!caps.installed ? <p role="status">Для выполнения прогонов установите пакет nfqws2-strategy-runs.</p> : <>
      <Card title="Параметры прогона" className={compactCard}>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Источник доменов"><Select value={list} disabled={!!active||busy} onChange={e=>setList(e.target.value)}>
            <option value="">Ввести домены</option>{lists.map(l=><option key={l.id} value={l.id}>{l.name}</option>)}
          </Select></Field>
          <Field label="Потоков"><Input type="number" min={1} max={caps.max_threads} value={threads} onChange={e=>setThreads(e.target.value)}/></Field>
        </div>
        {!list && <Field className="mt-3" label={`Домены, до ${caps.max_targets} за прогон`}><Textarea value={text} placeholder="example.org" disabled={!!active||busy} onChange={e=>setText(e.target.value)}/></Field>}
        <div className="mt-3 flex flex-wrap gap-2">{active ? <>
          <Button disabled={!validThreads||busy||active.threads===n} onClick={()=>void submit(async()=>{await api("POST",`/api/runs/${active.id}/threads`,{threads:n});})}>Изменить число потоков</Button>
          <Button variant="danger" disabled={busy} onClick={()=>void submit(async()=>{await api("POST",`/api/runs/${active.id}/cancel`,{});})}>Отменить прогон</Button>
        </> : <Button variant="primary" disabled={!loaded||!validThreads||busy||(!list&&!text.trim())} onClick={()=>void start()}>Запустить проверку</Button>}</div>
      </Card>
      {error && <div role="alert" className="text-sm text-bad">{error} {!loaded && <Button onClick={()=>setRetry(v=>v+1)}>Повторить</Button>}</div>}
      {history.length>1 && <Field label="Сохранённые прогоны"><Select value={report?.id||""} onChange={e=>setSelected(e.target.value)}>
        {history.map(r=><option key={r.id} value={r.id}>{new Date(r.started_at*1000).toLocaleString()} · {r.list_name} · {statusText[r.status]}</option>)}
      </Select></Field>}
      {report && <CheckResults report={report}/>}
    </>}
  </div>;
}

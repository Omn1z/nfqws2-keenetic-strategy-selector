import { useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { kb } from "@/lib/format";
import { usePoll } from "@/lib/hooks";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { VerdictBadge } from "@/components/ui/Badge";
import { Field, Input } from "@/components/ui/form";
import { Args, EmptyRow, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import { SourceSelector } from "@/components/SourceSelector";
import type { SourceSelectorHandle } from "@/components/SourceSelector";
import type { BlockCheck as BC, TargetSource } from "@/types/api";

export default function BlockCheck() {
  const { lists, geo } = useStore();
  const srcRef = useRef<SourceSelectorHandle>(null);
  const [threads, setThreads] = useState("4");
  const [bc, setBc] = useState<BC | null>(null);
  const [running, setRunning] = useState(false);

  usePoll(async () => {
    if (!bc) return;
    try {
      const r = await api<BC>("GET", `/api/blockcheck/${bc.id}`);
      setBc(r);
      if (r.status !== "running") {
        setRunning(false);
        const blocked = r.targets.filter((t) => t.blocked).length;
        toast(r.status === "cancelled" ? "Проверка отменена" : `Проверка завершена: заблокировано ${blocked} из ${r.total}`, "ok");
      }
    } catch (e) { setRunning(false); toast((e as Error).message, "err"); }
  }, 1000, running);

  const start = async () => {
    if (!srcRef.current) return;
    let target: TargetSource;
    try { target = await srcRef.current.resolve(); } catch (e) { toast((e as Error).message, "err"); return; }
    try { const r = await api<BC>("POST", "/api/blockcheck", { ...target, threads: parseInt(threads, 10) || 4 }); setBc(r); setRunning(true); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const cancel = async () => { setRunning(false); if (bc) { try { await api("POST", `/api/blockcheck/${bc.id}/cancel`); } catch { /* already stopping */ } } };

  const targets = bc?.targets ?? [];
  const pct = bc?.total ? Math.round((bc.done * 100) / bc.total) : 0;

  return (
    <>
      <Card title="BlockCheck" sub="проверка блокировки без обхода">
        <p className="mb-3 text-xs text-muted">Проверяет доступность доменов/IP напрямую: тестовое соединение исключается из основного сервиса nfqws2 и не обходится — видно, что реально блокирует провайдер (RST, таймаут, обрыв на ~16 КБ).</p>
        <SourceSelector ref={srcRef} lists={lists} geo={geo} />
        <div className="mb-1.5 flex flex-wrap items-end gap-4">
          <Field label="Потоков" className="w-28 shrink-0"><Input type="number" min={1} max={8} value={threads} onChange={(e) => setThreads(e.target.value)} /></Field>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2.5">
          <Button variant="primary" onClick={start} disabled={running}>▶ Проверить</Button>
          {running && <Button variant="danger" onClick={cancel}>■ Отменить</Button>}
          {bc && <span className="text-xs text-muted">{bc.status}</span>}
        </div>
        {running && bc && (
          <div className="mt-2">
            <div className="h-2 overflow-hidden rounded-full bg-line"><div className="h-full rounded-full bg-gradient-to-r from-accent to-[#5cb3ff] transition-[width]" style={{ width: `${pct}%` }} /></div>
            <span className="text-xs text-muted">{bc.done}/{bc.total} целей · {bc.status}</span>
          </div>
        )}
      </Card>
      <Card title="Результаты проверки" sub="заблокированные сверху">
        <TableWrap>
          <table className={tableCls}>
            <thead><tr><th className={thBase}>Цель</th><th className={thBase}>Статус</th><th className={thBase}>Задержка</th><th className={thBase}>Скорость</th><th className={thBase}>Код</th></tr></thead>
            <tbody>
              {targets.length === 0 && <EmptyRow colSpan={5}>Запустите проверку.</EmptyRow>}
              {[...targets].sort((a, b) => Number(b.blocked) - Number(a.blocked)).map((t, i) => (
                <tr key={t.host + i} className="hover:bg-line-soft">
                  <td className={tdCls}>{t.host}</td>
                  <td className={tdCls}><VerdictBadge v={t.verdict} />{t.err && <Args>{t.err}</Args>}</td>
                  <td className={cn(tdCls, "tabular-nums")}>{t.ttfb_ms ? `${t.ttfb_ms} мс` : "—"}</td>
                  <td className={cn(tdCls, "tabular-nums")}>{t.speed_bps ? `${kb(t.speed_bps)} КБ/с` : "—"}</td>
                  <td className={cn(tdCls, "tabular-nums")}>{t.code || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Card>
    </>
  );
}

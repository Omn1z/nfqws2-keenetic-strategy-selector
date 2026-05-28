import { useEffect, useState } from "react";
import { api, exportStrategy } from "@/lib/api";
import { cn } from "@/lib/cn";
import { kb } from "@/lib/format";
import { applyStrategyToConfig } from "@/lib/actions";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DnsBadge } from "@/components/ui/Badge";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { Pager, pageSlice } from "@/components/ui/Pager";
import { Args, EmptyRow, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import type { List } from "@/types/api";

export default function Lists() {
  const { lists, reloadLists, geo } = useStore();
  const [sel, setSel] = useState<List | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState("20");
  const [gFile, setGFile] = useState("");
  const [gCat, setGCat] = useState("");
  const [gLimit, setGLimit] = useState("50");

  const select = async (id: string) => { try { setSel(await api<List>("GET", `/api/lists/${id}`)); setPage(1); } catch (e) { toast((e as Error).message, "err"); } };
  const newList = () => setSel({ id: "", name: "", domains: [], ips: [], created_at: 0, updated_at: 0 });
  const patch = (p: Partial<List>) => setSel((s) => (s ? { ...s, ...p } : s));

  const save = async () => {
    if (!sel) return;
    try {
      const out = await api<List>("POST", "/api/lists", {
        id: sel.id, name: sel.name.trim(), domains: sel.domains, ips: sel.ips,
        base_strategy_ids: sel.base_strategy_ids ?? [], successful_strategies: sel.successful_strategies ?? [],
      });
      setSel(out); await reloadLists(); toast("Список сохранён", "ok");
    } catch (e) { toast((e as Error).message, "err"); }
  };
  const del = async (id: string, name: string) => {
    if (!confirm(`Удалить список «${name || "без имени"}»?`)) return;
    try { await api("DELETE", `/api/lists/${id}`); if (sel?.id === id) setSel(null); await reloadLists(); toast("Список удалён", "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
  };

  const cats = geo.find((g) => g.name === gFile)?.categories ?? [];
  useEffect(() => { if (!gFile && geo[0]) setGFile(geo[0].name); }, [geo, gFile]);
  useEffect(() => { if (cats[0] && !cats.some((c) => c.name === gCat)) setGCat(cats[0].name); }, [gFile, cats, gCat]);
  const geoAdd = async () => {
    if (!sel?.id) { toast("Сначала сохраните список", "err"); return; }
    if (!gCat) { toast("Нет категорий", "err"); return; }
    try {
      const out = await api<List>("POST", "/api/geo/import", { geo: gFile, category: gCat, limit: parseInt(gLimit, 10) || 0, list_id: sel.id });
      setSel(out); await reloadLists(); toast(`Добавлено: ${out.domains.length} дом. / ${out.ips.length} IP`, "ok");
    } catch (e) { toast((e as Error).message, "err"); }
  };

  const saved = sel?.successful_strategies ?? [];

  return (
    <div className="flex items-start gap-5 max-[860px]:flex-col">
      <aside className="w-[270px] shrink-0 max-[860px]:w-full">
        <Button variant="primary" className="mb-3 w-full" onClick={newList}>+ Новый список</Button>
        <ul className="m-0 list-none p-0">
          {lists.map((l) => (
            <li key={l.id} className={cn("mb-2.5 flex items-center gap-2 rounded-[10px] border bg-panel p-3 transition hover:-translate-y-px hover:border-accent hover:shadow-sm", sel?.id === l.id ? "border-accent bg-accent-w" : "border-line")}>
              <div className="min-w-0 flex-1 cursor-pointer" onClick={() => select(l.id)}>
                <div className="font-semibold">{l.name || "(без имени)"}</div>
                <div className="mt-0.5 text-xs text-muted">{l.domains?.length ?? 0} дом. · {l.ips?.length ?? 0} IP · {l.successful_strategies?.length ?? 0} рабочих</div>
              </div>
              <button className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-lg leading-none text-muted transition hover:bg-bad-bg hover:text-bad" onClick={() => del(l.id, l.name)}>×</button>
            </li>
          ))}
        </ul>
      </aside>

      <div className="min-w-0 flex-1">
        {!sel && <p className="py-8 text-center text-muted">Выберите список слева или создайте новый.</p>}
        {sel && (
          <>
            <Card title="Список" head={sel.id ? <Button mini variant="danger" onClick={() => del(sel.id, sel.name)}>Удалить список</Button> : undefined}>
              <Field label="Название"><Input value={sel.name} placeholder="Мой список" onChange={(e) => patch({ name: e.target.value })} /></Field>
              <div className="flex flex-wrap gap-4">
                <Field label="Домены" hint="по одному в строке" className="min-w-[200px] flex-1">
                  <Textarea rows={7} value={sel.domains.join("\n")} placeholder={"rutracker.org\nx.com"} onChange={(e) => patch({ domains: e.target.value.split("\n") })} />
                </Field>
                <Field label="IP / CIDR" hint="по одному в строке" className="min-w-[200px] flex-1">
                  <Textarea rows={7} value={sel.ips.join("\n")} placeholder="1.2.3.0/24" onChange={(e) => patch({ ips: e.target.value.split("\n") })} />
                </Field>
              </div>
              {geo.length > 0 && (
                <div className="mt-3 flex flex-wrap items-end gap-2.5">
                  <Field label="Добавить из GeoSite/GeoIP" className="min-w-[200px] flex-1"><Select value={gFile} onChange={(e) => setGFile(e.target.value)}>{geo.map((f) => <option key={f.name} value={f.name}>{f.name} [{f.kind}]</option>)}</Select></Field>
                  <Field label="Категория" className="min-w-[200px] flex-1"><Select value={gCat} onChange={(e) => setGCat(e.target.value)}>{cats.map((c) => <option key={c.name} value={c.name}>{c.name} ({c.count})</option>)}</Select></Field>
                  <Field label="Лимит" className="w-28 shrink-0"><Input type="number" min={0} value={gLimit} onChange={(e) => setGLimit(e.target.value)} /></Field>
                  <Button onClick={geoAdd}>Добавить в список</Button>
                </div>
              )}
              <div className="mt-2 flex gap-2.5"><Button variant="primary" onClick={save}>Сохранить</Button></div>
            </Card>

            <Card title="Рабочие стратегии списка" sub="по скорости">
              <TableWrap scrollable>
                <table className={tableCls}>
                  <thead><tr><th className={thBase}>Стратегия</th><th className={thBase}>DNS</th><th className={thBase}>Задержка</th><th className={thBase}>Скорость</th><th className={thBase}>Коэф.</th><th className={thBase} /></tr></thead>
                  <tbody>
                    {saved.length === 0 && <EmptyRow colSpan={6}>Пока нет рабочих стратегий — запустите прогон на этом списке.</EmptyRow>}
                    {pageSlice(saved, page, pageSize).map((s, i) => (
                      <tr key={s.strategy_id + i} className="hover:bg-line-soft">
                        <td className={tdCls}>{s.name || s.strategy_id}<Args>{s.args}</Args></td>
                        <td className={tdCls}><DnsBadge name={s.dns} id={s.dns_id} /></td>
                        <td className={cn(tdCls, "tabular-nums")}>{s.avg_ttfb_ms} мс</td>
                        <td className={cn(tdCls, "tabular-nums")}>{kb(s.avg_speed_bps)} КБ/с</td>
                        <td className={cn(tdCls, "tabular-nums")}>{Math.round(s.coefficient)}</td>
                        <td className={cn(tdCls, "flex flex-wrap gap-1.5")}>
                          <Button mini onClick={() => applyStrategyToConfig(s.args)}>Применить</Button>
                          <Button mini title="Экспорт (ZIP)" onClick={() => exportStrategy(s.name || s.strategy_id, "", s.args).catch((e) => toast((e as Error).message, "err"))}>⤓</Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
              <Pager total={saved.length} page={page} setPage={setPage} pageSize={pageSize} setPageSize={setPageSize} />
            </Card>
          </>
        )}
      </div>
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import { api, exportStrategy } from "@/lib/api";
import { cn } from "@/lib/cn";
import { kb } from "@/lib/format";
import { applyStrategyToConfig } from "@/lib/actions";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DnsBadge } from "@/components/ui/Badge";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { PageHeader, compactCard } from "@/components/ui/FeaturePage";
import { Pager, pageSlice } from "@/components/ui/Pager";
import { EmptyRow, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import type { List, SavedStrategy } from "@/types/api";
import { entryCount, ListsCatalog, ListsSummary, listSavePayload, visibleLists, type ListFilter } from "./presentation";

export function SavedListStrategyRow({ strategy: s, disabled, onExport }: { strategy: SavedStrategy; disabled: boolean; onExport: (strategy: SavedStrategy) => void }) {
  return <tr className="hover:bg-line-soft">
    <th scope="row" className={cn(tdCls, "min-w-[230px] max-w-[430px] text-left text-xs font-normal [overflow-wrap:anywhere]")}>
      <span className="font-medium">{s.name || s.strategy_id}</span>
      <span className="mt-1 block font-mono text-[10px] text-muted">{s.strategy_id}</span>
      <details className="mt-1"><summary className="cursor-pointer text-[11px] text-ink-soft">Аргументы целиком</summary><pre className="mt-2 whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-muted [overflow-wrap:anywhere]">{s.args}</pre></details>
    </th>
    <td className={tdCls}><DnsBadge name={s.dns} id={s.dns_id} /></td>
    <td className={cn(tdCls, "whitespace-nowrap tabular-nums")}>{s.avg_ttfb_ms} мс</td>
    <td className={cn(tdCls, "whitespace-nowrap tabular-nums")}>{kb(s.avg_speed_bps)} КБ/с</td>
    <td className={cn(tdCls, "tabular-nums")}>{Math.round(s.coefficient)}</td>
    <td className={tdCls}><div className="flex flex-wrap gap-1.5">
      <Button mini disabled={disabled} onClick={() => applyStrategyToConfig(s.args)}>Применить</Button>
      <Button mini title="Экспорт (ZIP)" aria-label={`Экспортировать ${s.name || s.strategy_id} в ZIP`} disabled={disabled} onClick={() => onExport(s)}>ZIP ↓</Button>
    </div></td>
  </tr>;
}

export default function Lists() {
  const { lists, reloadLists, geo } = useStore();
  const [sel, setSel] = useState<List | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState("20");
  const [stratQ, setStratQ] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<ListFilter>("all");
  const [gFile, setGFile] = useState("");
  const [gCat, setGCat] = useState("");
  const [gLimit, setGLimit] = useState("50");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const pending = useRef(false);

  const perform = async (key: string, operation: () => Promise<void>) => {
    if (pending.current) return;
    pending.current = true; setBusy(key); setError("");
    try { await operation(); }
    catch (cause) { const message = (cause as Error).message; setError(message); toast(message, "err"); }
    finally { pending.current = false; setBusy(null); }
  };
  const select = async (id: string) => perform(`select:${id}`, async () => { setSel(await api<List>("GET", `/api/lists/${id}`)); setPage(1); });
  const newList = () => { if (!pending.current) { setSel({ id: "", name: "", domains: [], ips: [], created_at: 0, updated_at: 0 }); setPage(1); setError(""); } };
  const patch = (value: Partial<List>) => setSel(current => current ? { ...current, ...value } : current);

  const save = async () => {
    if (!sel) return;
    await perform("save", async () => {
      const out = await api<List>("POST", "/api/lists", listSavePayload(sel));
      setSel(out); await reloadLists(); toast("Список сохранён", "ok");
    });
  };
  const del = async (id: string, name: string) => perform(`delete:${id}`, async () => {
    if (!(await confirmDialog({ title: `Удалить список «${name || "без имени"}»?`, confirmLabel: "Удалить", danger: true }))) return;
    await api("DELETE", `/api/lists/${id}`); if (sel?.id === id) setSel(null); await reloadLists(); toast("Список удалён", "ok");
  });

  const cats = geo.find(file => file.name === gFile)?.categories ?? [];
  useEffect(() => { if (!gFile && geo[0]) setGFile(geo[0].name); }, [geo, gFile]);
  useEffect(() => { if (cats[0] && !cats.some(category => category.name === gCat)) setGCat(cats[0].name); }, [gFile, cats, gCat]);
  const geoAdd = async () => {
    if (!sel?.id) { toast("Сначала сохраните список", "err"); return; }
    if (!gCat) { toast("Нет категорий", "err"); return; }
    await perform("geo", async () => {
      const out = await api<List>("POST", "/api/geo/import", { geo: gFile, category: gCat, limit: parseInt(gLimit, 10) || 0, list_id: sel.id });
      setSel(out); await reloadLists(); toast(`Добавлено: ${out.domains.length} дом. / ${out.ips.length} IP`, "ok");
    });
  };

  const sq = stratQ.trim().toLowerCase();
  const saved = (sel?.successful_strategies ?? []).filter(strategy => !sq || `${strategy.name} ${strategy.args} ${strategy.dns ?? ""}`.toLowerCase().includes(sq));
  const visible = visibleLists(lists, query, filter);
  const disabled = busy !== null;
  const filtered = !!query.trim() || filter !== "all";

  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="Списки доменов и IP" description="Наборы целей для прогонов и сохранённые рабочие стратегии." actions={<Button variant="primary" disabled={disabled} onClick={newList}>Новый список</Button>} />
    <ListsSummary lists={lists} selected={sel} />
    {error && <p role="alert" className="rounded-lg border border-line bg-bad-bg p-3 text-xs text-bad [overflow-wrap:anywhere]">{error}</p>}
    <div className="grid min-w-0 items-start gap-4 xl:grid-cols-[270px_minmax(0,1fr)]">
      <Card title="Каталог списков" sub={`${visible.length} из ${lists.length}`} className={compactCard}>
        <div className="mb-3 flex min-w-0 flex-col gap-3">
          <Field label="Поиск"><Input aria-label="Поиск списков" value={query} placeholder="Название, домен или IP…" onChange={event => setQuery(event.target.value)} /></Field>
          <Field label="Показывать"><Select aria-label="Фильтр списков" value={filter} onChange={event => setFilter(event.target.value as ListFilter)}><option value="all">Все списки</option><option value="domains">С доменами</option><option value="ips">С IP / CIDR</option><option value="strategies">С сохранёнными стратегиями</option></Select></Field>
          {filtered && <Button mini variant="ghost" onClick={() => { setQuery(""); setFilter("all"); }}>Сбросить фильтры</Button>}
        </div>
        <ListsCatalog lists={visible} selectedId={sel?.id} busy={busy} filtered={filtered} onSelect={id => { void select(id); }} onDelete={(id, name) => { void del(id, name); }} />
      </Card>
      <div className="flex min-w-0 flex-col gap-4">
        {!sel && <Card title="Редактор списка" className={compactCard}><p className="py-6 text-center text-xs text-muted">Выберите список в каталоге или создайте новый.</p></Card>}
        {sel && <>
          <Card title={sel.id ? "Редактор списка" : "Новый список"} sub={sel.id || "Черновик"} className={compactCard} head={sel.id ? <Button mini variant="danger" disabled={disabled} onClick={() => del(sel.id, sel.name)}>Удалить список</Button> : undefined}>
            <fieldset disabled={disabled} className="flex min-w-0 flex-col gap-3">
              <Field label="Название списка"><Input value={sel.name} placeholder="Мой список" onChange={event => patch({ name: event.target.value })} /></Field>
              <div className="grid min-w-0 gap-3 md:grid-cols-2">
                <Field label={<>Домены <span className="font-normal text-muted">· {entryCount(sel.domains)}</span></>} hint="по одному в строке"><Textarea rows={8} value={(sel.domains ?? []).join("\n")} placeholder={"rutracker.org\nx.com"} onChange={event => patch({ domains: event.target.value.split("\n") })} /></Field>
                <Field label={<>IP / CIDR <span className="font-normal text-muted">· {entryCount(sel.ips)}</span></>} hint="по одному в строке"><Textarea rows={8} value={(sel.ips ?? []).join("\n")} placeholder="1.2.3.0/24" onChange={event => patch({ ips: event.target.value.split("\n") })} /></Field>
              </div>
              {geo.length > 0 && <section aria-label="Добавление целей из GeoSite и GeoIP" className="rounded-lg border border-line p-3">
                <h3 className="mb-3 text-xs font-medium">Добавить из GeoSite / GeoIP</h3>
                <div className="grid min-w-0 items-end gap-3 sm:grid-cols-2">
                  <Field label="Файл"><Select value={gFile} onChange={event => setGFile(event.target.value)}>{geo.map(file => <option key={file.name} value={file.name}>{file.name} [{file.kind}]</option>)}</Select></Field>
                  <Field label="Категория"><Select value={gCat} onChange={event => setGCat(event.target.value)}>{cats.map(category => <option key={category.name} value={category.name}>{category.name} ({category.count})</option>)}</Select></Field>
                  <Field label="Лимит" className="w-28"><Input type="number" min={0} value={gLimit} onChange={event => setGLimit(event.target.value)} /></Field>
                  <Button onClick={geoAdd}>{busy === "geo" ? "Добавление…" : "Добавить в список"}</Button>
                </div>
              </section>}
              <div className="flex flex-wrap items-center gap-3 border-t border-line-soft pt-3"><Button variant="primary" onClick={save}>{busy === "save" ? "Сохранение…" : "Сохранить список"}</Button><span className="text-[11px] text-muted">Счётчики доменов и IP показывают текущий черновик.</span></div>
            </fieldset>
          </Card>
          <Card title="Рабочие стратегии списка" sub="по скорости" className={compactCard} head={<Input aria-label="Поиск рабочих стратегий списка" value={stratQ} onChange={event => { setStratQ(event.target.value); setPage(1); }} placeholder="Стратегия / args / DNS" className="h-8 w-full py-1 sm:w-56" />}>
            <TableWrap scrollable><table className={cn(tableCls, "min-w-[720px]")}>
              <thead><tr>{["Стратегия", "DNS", "Задержка", "Скорость", "Коэф.", "Действия"].map(label => <th key={label} scope="col" className={thBase}>{label}</th>)}</tr></thead>
              <tbody>
                {!saved.length && <EmptyRow colSpan={6}>{sel.successful_strategies?.length ? "Нет рабочих стратегий под выбранный поиск." : "Пока нет рабочих стратегий — запустите прогон на этом списке."}</EmptyRow>}
                {pageSlice(saved, page, pageSize).map((strategy, index) => <SavedListStrategyRow key={strategy.strategy_id + index} strategy={strategy} disabled={disabled} onExport={item => { void perform("export", () => exportStrategy(item.name || item.strategy_id, "", item.args)); }} />)}
              </tbody>
            </table></TableWrap>
            <Pager total={saved.length} page={page} setPage={setPage} pageSize={pageSize} setPageSize={setPageSize} />
          </Card>
        </>}
      </div>
    </div>
  </div>;
}

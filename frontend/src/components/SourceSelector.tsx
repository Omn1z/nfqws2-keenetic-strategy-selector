import { useEffect, useImperativeHandle, useState } from "react";
import type { Ref } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import type { GeoFile, List, TargetSource } from "@/types/api";

export interface SourceSelectorHandle {
  resolve: () => Promise<TargetSource>;
}

type Mode = "list" | "geo" | "text";

interface Props {
  lists: List[];
  geo: GeoFile[];
  initialText?: string;
  ref?: Ref<SourceSelectorHandle>;
}

/** Segmented "Список / GeoSite-GeoIP / Текст" picker. The parent holds a ref and
 *  calls `await ref.current.resolve()` to get {list_id} | {targets}. */
export function SourceSelector({ lists, geo, initialText, ref }: Props) {
  const [mode, setMode] = useState<Mode>(initialText ? "text" : "list");
  const [listId, setListId] = useState("");
  const [geoFile, setGeoFile] = useState("");
  const [geoCat, setGeoCat] = useState("");
  const [geoLimit, setGeoLimit] = useState("50");
  const [text, setText] = useState(initialText ?? "");

  useEffect(() => { if (!listId && lists[0]) setListId(lists[0].id); }, [lists, listId]);
  useEffect(() => { if (!geoFile && geo[0]) setGeoFile(geo[0].name); }, [geo, geoFile]);
  const cats = geo.find((g) => g.name === geoFile)?.categories ?? [];
  useEffect(() => { if (cats[0] && !cats.some((c) => c.name === geoCat)) setGeoCat(cats[0].name); }, [geoFile, cats, geoCat]);

  useImperativeHandle(ref, () => ({
    async resolve(): Promise<TargetSource> {
      if (mode === "list") {
        if (!listId) throw new Error("Нет списков — создайте список во вкладке «Списки»");
        return { list_id: listId };
      }
      if (mode === "geo") {
        if (!geoFile || !geoCat) throw new Error("Загрузите GeoSite/GeoIP и выберите категорию");
        const r = await api<{ targets: string[] }>("POST", "/api/geo/resolve", { geo: geoFile, category: geoCat, limit: parseInt(geoLimit, 10) || 0 });
        if (!r.targets?.length) throw new Error("Категория пустая");
        return { targets: r.targets };
      }
      const targets = text.split("\n").map((s) => s.trim()).filter(Boolean);
      if (!targets.length) throw new Error("Введите домены или IP");
      return { targets };
    },
  }), [mode, listId, geoFile, geoCat, geoLimit, text]);

  const seg = (m: Mode, label: string) => (
    <button
      type="button"
      onClick={() => setMode(m)}
      className={cn("border-r border-line px-3.5 py-1.5 text-[13px] outline-none transition last:border-r-0 focus-visible:relative focus-visible:ring-2 focus-visible:ring-ring/40", mode === m ? "bg-accent text-white" : "bg-panel text-ink-soft hover:bg-line-soft")}
    >
      {label}
    </button>
  );

  return (
    <div className="mb-1">
      <div className="mb-3 inline-flex overflow-hidden rounded-lg border border-line">
        {seg("list", "Список")}
        {seg("geo", "GeoSite/GeoIP")}
        {seg("text", "Текст")}
      </div>
      {mode === "list" && (
        <Field label="Список">
          <Select value={listId} onChange={(e) => setListId(e.target.value)}>
            {lists.map((l) => <option key={l.id} value={l.id}>{l.name || l.id} ({l.domains?.length ?? 0} дом. / {l.ips?.length ?? 0} IP)</option>)}
          </Select>
        </Field>
      )}
      {mode === "geo" && (
        <div className="flex flex-wrap items-end gap-2.5">
          <Field label="Файл" className="min-w-[220px] flex-1">
            <Select value={geoFile} onChange={(e) => setGeoFile(e.target.value)}>{geo.map((f) => <option key={f.name} value={f.name}>{f.name} [{f.kind}]</option>)}</Select>
          </Field>
          <Field label="Категория" className="min-w-[220px] flex-1">
            <Select value={geoCat} onChange={(e) => setGeoCat(e.target.value)}>{cats.map((c) => <option key={c.name} value={c.name}>{c.name} ({c.count})</option>)}</Select>
          </Field>
          <Field label="Лимит" className="w-28 shrink-0"><Input type="number" min={0} value={geoLimit} onChange={(e) => setGeoLimit(e.target.value)} /></Field>
        </div>
      )}
      {mode === "text" && (
        <Field label="Домены / IP" hint="по одному в строке">
          <Textarea rows={5} value={text} placeholder={"rutracker.org\n1.2.3.4"} onChange={(e) => setText(e.target.value)} />
        </Field>
      )}
    </div>
  );
}

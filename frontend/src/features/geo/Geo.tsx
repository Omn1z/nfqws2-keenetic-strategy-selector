import { useState } from "react";
import { api, uploadForm } from "@/lib/api";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Dropzone } from "@/components/ui/Dropzone";
import { Field, Input, Select } from "@/components/ui/form";
import type { GeoFile, List } from "@/types/api";

function GeoFileCard({ file, lists, onChanged }: { file: GeoFile; lists: List[]; onChanged: () => void }) {
  const cats = file.categories ?? [];
  const [cat, setCat] = useState(cats[0]?.name ?? "");
  const [limit, setLimit] = useState("25");
  const [listId, setListId] = useState("");
  const [newName, setNewName] = useState("");

  const del = async () => {
    if (!confirm(`Удалить geo-файл «${file.name}»?`)) return;
    try { await api("DELETE", `/api/geo/${encodeURIComponent(file.name)}`); onChanged(); } catch (e) { toast((e as Error).message, "err"); }
  };
  const imp = async () => {
    if (!cat) { toast("Нет категорий в файле", "err"); return; }
    try {
      const list = await api<List>("POST", "/api/geo/import", { geo: file.name, category: cat, limit: parseInt(limit, 10) || 0, list_id: listId, list_name: newName.trim() });
      toast(`Импортировано в «${list.name}» (${list.domains.length} дом. / ${list.ips.length} IP)`, "ok");
      onChanged();
    } catch (e) { toast((e as Error).message, "err"); }
  };

  return (
    <Card>
      <div className="mb-3.5 flex items-center gap-2.5">
        <h2 className="text-[15px] font-semibold">{file.name}</h2>
        <Badge>{file.kind}</Badge>
        <span className="text-xs text-muted">{cats.length} категорий</span>
        <Button mini variant="danger" className="ml-auto" onClick={del}>Удалить</Button>
      </div>
      <div className="flex flex-wrap items-end gap-2.5">
        <Field label="Категория" className="min-w-[200px] flex-1"><Select value={cat} onChange={(e) => setCat(e.target.value)}>{cats.map((c) => <option key={c.name} value={c.name}>{c.name} ({c.count})</option>)}</Select></Field>
        <Field label="Лимит" className="w-24 shrink-0"><Input type="number" min={0} value={limit} onChange={(e) => setLimit(e.target.value)} /></Field>
        <Field label="В список" className="min-w-[180px] flex-1"><Select value={listId} onChange={(e) => setListId(e.target.value)}><option value="">— новый список —</option>{lists.map((l) => <option key={l.id} value={l.id}>{l.name || l.id}</option>)}</Select></Field>
        {!listId && <Field label="Имя нового" className="min-w-[180px] flex-1"><Input value={newName} placeholder={`${file.name}:категория`} onChange={(e) => setNewName(e.target.value)} /></Field>}
        <Button variant="primary" onClick={imp}>Импортировать</Button>
      </div>
    </Card>
  );
}

export default function Geo() {
  const { geo, reloadGeo, lists, reloadLists } = useStore();
  const [kind, setKind] = useState("geosite");
  const [status, setStatus] = useState("");

  const upload = async (files: FileList) => {
    const file = files[0];
    if (!file) return;
    setStatus(`Загрузка: ${file.name}`);
    const fd = new FormData();
    fd.append("file", file);
    fd.append("kind", kind);
    try { const d = await uploadForm<{ name: string }>("/api/geo", fd); setStatus(`✓ ${d.name}`); toast(`Загружено: ${d.name}`, "ok"); await reloadGeo(); }
    catch (e) { setStatus(""); toast((e as Error).message, "err"); }
  };
  const onChanged = async () => { await reloadGeo(); await reloadLists(); };

  return (
    <>
      <Card title="GeoSite / GeoIP">
        <p className="mb-3 text-xs text-muted">Загрузите <code>geosite.dat</code> / <code>geoip.dat</code> (формат v2ray) или текстовый список (домен/IP в строке). Затем импортируйте категорию в тестовый список.</p>
        <div className="flex items-stretch gap-3.5">
          <Field label="Тип" className="w-32 shrink-0"><Select value={kind} onChange={(e) => setKind(e.target.value)}><option value="geosite">geosite.dat</option><option value="geoip">geoip.dat</option><option value="text">текст</option></Select></Field>
          <div className="flex-1">
            <Dropzone onFiles={upload}>
              <svg className="mx-auto mb-2 text-accent" viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 16V4m0 0 4 4m-4-4L8 8M5 16v2a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-2" /></svg>
              <div className="text-[13.5px]"><b className="text-ink">Перетащите файл</b> или нажмите</div>
              <div className="mt-1.5 min-h-[16px] text-[12.5px] font-semibold text-accent-d">{status}</div>
            </Dropzone>
          </div>
        </div>
      </Card>
      {geo.map((f) => <GeoFileCard key={f.name} file={f} lists={lists} onChanged={onChanged} />)}
    </>
  );
}

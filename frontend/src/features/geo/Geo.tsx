import { useEffect, useState } from "react";
import { api, uploadForm } from "@/lib/api";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Switch } from "@/components/ui/Switch";
import { Dropzone } from "@/components/ui/Dropzone";
import { Field, Input, Select } from "@/components/ui/form";
import type { GeoAutoConfig, GeoFile, List } from "@/types/api";

function fmtAgo(ts: number): string {
  if (!ts) return "никогда";
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}

function fmtSize(n: number): string {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function GeoAutoPanel({ onChanged }: { onChanged: () => void }) {
  const [cfg, setCfg] = useState<GeoAutoConfig | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try { setCfg(await api<GeoAutoConfig>("GET", "/api/geo/auto")); } catch (e) { toast((e as Error).message, "err"); }
  };
  useEffect(() => { void load(); }, []);

  if (!cfg) return null;

  const save = async (patch: Partial<GeoAutoConfig>) => {
    const next = { ...cfg, ...patch };
    setCfg(next);
    try { setCfg(await api<GeoAutoConfig>("POST", "/api/geo/auto", next)); toast("Сохранено", "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const fetchNow = async () => {
    setBusy(true);
    try {
      const next = await api<GeoAutoConfig>("POST", "/api/geo/fetch-now", {});
      setCfg(next);
      if (next.last_error) toast(next.last_error, "err"); else toast("Скачано", "ok");
      onChanged();
    } catch (e) { toast((e as Error).message, "err"); }
    finally { setBusy(false); }
  };

  return (
    <Card title="Авто-обновление" sub="периодически тянет свежие geosite.dat / geoip.dat с upstream-релизов">
      <div className="mb-3 flex flex-wrap items-center gap-4">
        <Switch checked={cfg.enabled} onChange={(v) => save({ enabled: v })} label="Включено" />
        <Field label="Интервал (часов)" className="w-28">
          <Input type="number" min={1} value={cfg.interval_hours} onChange={(e) => setCfg({ ...cfg, interval_hours: parseInt(e.target.value, 10) || 24 })} onBlur={() => save({})} />
        </Field>
        <Button onClick={fetchNow} disabled={busy} variant="primary">{busy ? "Скачиваю…" : "Обновить сейчас"}</Button>
      </div>
      <Field label="geosite.dat URL"><Input value={cfg.geosite_url} onChange={(e) => setCfg({ ...cfg, geosite_url: e.target.value })} onBlur={() => save({})} /></Field>
      <Field label="geoip.dat URL"><Input value={cfg.geoip_url} onChange={(e) => setCfg({ ...cfg, geoip_url: e.target.value })} onBlur={() => save({})} /></Field>
      <div className="mt-2 grid grid-cols-1 gap-1 text-[12px] text-muted sm:grid-cols-2">
        <div>Последнее обновление: <b className="text-ink">{fmtAgo(cfg.last_fetched_at)}</b></div>
        <div>geosite.dat: <b className="text-ink">{fmtSize(cfg.last_geosite_len)}</b> ({fmtAgo(cfg.last_geosite_at)})</div>
        <div>geoip.dat: <b className="text-ink">{fmtSize(cfg.last_geoip_len)}</b> ({fmtAgo(cfg.last_geoip_at)})</div>
        {cfg.last_error && <div className="text-danger">Ошибка: {cfg.last_error}</div>}
      </div>
    </Card>
  );
}

function GeoFileCard({ file, lists, onChanged }: { file: GeoFile; lists: List[]; onChanged: () => void }) {
  const cats = file.categories ?? [];
  const [cat, setCat] = useState(cats[0]?.name ?? "");
  const [limit, setLimit] = useState("25");
  const [listId, setListId] = useState("");
  const [newName, setNewName] = useState("");

  const del = async () => {
    if (!(await confirmDialog({ title: `Удалить geo-файл «${file.name}»?`, confirmLabel: "Удалить", danger: true }))) return;
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
      <GeoAutoPanel onChanged={reloadGeo} />
      <Card title="GeoSite / GeoIP">
        <p className="mb-3 text-xs text-muted">Загрузите <code>geosite.dat</code> / <code>geoip.dat</code> (формат v2ray) или текстовый список (домен/IP в строке). Затем импортируйте категорию в тестовый список.</p>
        <div className="flex flex-col gap-3.5 sm:flex-row sm:items-stretch">
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

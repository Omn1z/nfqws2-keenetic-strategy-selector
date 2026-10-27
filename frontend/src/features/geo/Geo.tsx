import { useEffect, useRef, useState } from "react";
import { api, uploadForm } from "@/lib/api";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Switch } from "@/components/ui/Switch";
import { Dropzone } from "@/components/ui/Dropzone";
import { Field, Input, Select } from "@/components/ui/form";
import { Skeleton } from "@/components/ui/Skeleton";
import { PageHeader, StatsStrip, compactCard } from "@/components/ui/FeaturePage";
import type { GeoAutoConfig, GeoFile, List } from "@/types/api";
import { geoImportPayload, geoSummary, retainedGeoCategory } from "./geoView";
import { createGeoAutoRequests, mergeGeoAutoDraft } from "./geoAutoRequests";

function fmtAgo(ts: number): string {
  if (!ts) return "никогда";
  const d = new Date(ts * 1000);
  return d.toLocaleString("ru-RU");
}

function fmtSize(n: number): string {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function GeoAutoPanel({ onChanged, onSnapshot }: { onChanged: () => void | Promise<void>; onSnapshot: (cfg: GeoAutoConfig) => void }) {
  const [cfg, setCfg] = useState<GeoAutoConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const fetching = useRef(false);
  const draft = useRef<GeoAutoConfig | null>(null);
  const queue = useRef<ReturnType<typeof createGeoAutoRequests> | null>(null);
  if (!queue.current) queue.current = createGeoAutoRequests({
    save: next => api<GeoAutoConfig>("POST", "/api/geo/auto", next),
    fetchNow: () => api<GeoAutoConfig>("POST", "/api/geo/fetch-now", {}),
    onAcknowledged: (next, requested) => {
      draft.current = mergeGeoAutoDraft(draft.current, next, requested);
      setCfg(draft.current); setError(""); onSnapshot(next);
    },
  });
  const edit = (patch: Partial<GeoAutoConfig>) => {
    if (!draft.current) return null;
    const next = { ...draft.current, ...patch };
    draft.current = next; setCfg(next);
    return next;
  };

  const load = async () => {
    setLoading(true); setError("");
    try { queue.current!.observe(await api<GeoAutoConfig>("GET", "/api/geo/auto")); }
    catch (e) { setError((e as Error).message); toast((e as Error).message, "err"); }
    finally { setLoading(false); }
  };
  useEffect(() => { void load(); }, []);

  if (!cfg) return <Card title="Авто-обновление баз" className={compactCard}>
    {loading ? <div className="flex flex-col gap-3"><Skeleton className="h-8 w-full" /><Skeleton className="h-8 w-full" /><Skeleton className="h-8 w-full" /></div> : <><p role="alert" className="mb-3 text-xs text-bad [overflow-wrap:anywhere]">Не удалось загрузить настройки: {error}</p><Button mini onClick={() => { void load(); }}>Повторить загрузку</Button></>}
  </Card>;

  const save = async (patch: Partial<GeoAutoConfig>) => {
    const next = edit(patch);
    if (!next) return;
    setError("");
    try { await queue.current!.save(next); toast("Сохранено", "ok"); }
    catch (e) { setError((e as Error).message); toast((e as Error).message, "err"); }
  };
  const fetchNow = async () => {
    if (fetching.current) return;
    const requested = draft.current;
    if (!requested) return;
    fetching.current = true;
    setBusy(true);
    setError("");
    try {
      const next = await queue.current!.fetch(requested);
      if (next.last_error) toast(next.last_error, "err"); else toast("Скачано", "ok");
      await onChanged();
    } catch (e) { setError((e as Error).message); toast((e as Error).message, "err"); }
    finally { fetching.current = false; setBusy(false); }
  };

  return (
    <Card title="Авто-обновление баз" className={compactCard} head={<Switch checked={cfg.enabled} disabled={busy} onChange={(v) => { void save({ enabled: v }); }} label="Включено" />}>
      <p className="mb-3 text-xs leading-relaxed text-muted">Свежие geosite.dat / geoip.dat с upstream-релизов. URL и интервал сохраняются при выходе из поля.</p>
      <fieldset disabled={busy} className="flex min-w-0 flex-col gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Интервал (часов)" className="min-w-0 flex-1 sm:max-w-40">
          <Input type="number" min={1} value={cfg.interval_hours} onChange={(e) => edit({ interval_hours: parseInt(e.target.value, 10) || 24 })} onBlur={() => { void save({}); }} />
        </Field>
        <Button onClick={fetchNow} disabled={busy} variant="primary" className="sm:ml-auto">{busy ? "Скачиваю…" : "Обновить сейчас"}</Button>
      </div>
      <Field label="geosite.dat URL"><Input value={cfg.geosite_url} onChange={(e) => edit({ geosite_url: e.target.value })} onBlur={() => { void save({}); }} /></Field>
      <Field label="geoip.dat URL"><Input value={cfg.geoip_url} onChange={(e) => edit({ geoip_url: e.target.value })} onBlur={() => { void save({}); }} /></Field>
      </fieldset>
      {error && <p role="alert" className="mt-3 text-xs text-bad [overflow-wrap:anywhere]">{error}</p>}
      <div className="mt-3 grid grid-cols-1 gap-2 border-t border-line-soft pt-3 text-[11px] leading-relaxed text-muted [overflow-wrap:anywhere] sm:grid-cols-2">
        <div>Последняя попытка обновления: <b className="text-ink">{fmtAgo(cfg.last_fetched_at)}</b></div>
        <div>geosite.dat: <b className="text-ink">{fmtSize(cfg.last_geosite_len)}</b> ({fmtAgo(cfg.last_geosite_at)})</div>
        <div>geoip.dat: <b className="text-ink">{fmtSize(cfg.last_geoip_len)}</b> ({fmtAgo(cfg.last_geoip_at)})</div>
        {cfg.last_error && <div className="text-bad sm:col-span-2">Ошибка: {cfg.last_error}</div>}
      </div>
    </Card>
  );
}

function GeoFileCard({ file, lists, onChanged }: { file: GeoFile; lists: List[]; onChanged: () => Promise<void> }) {
  const cats = file.categories ?? [];
  const [cat, setCat] = useState(cats[0]?.name ?? "");
  const [limit, setLimit] = useState("25");
  const [listId, setListId] = useState("");
  const [newName, setNewName] = useState("");
  const [busy, setBusy] = useState<"import" | "delete" | null>(null);
  const pending = useRef(false);
  useEffect(() => { setCat(current => retainedGeoCategory(current, file.categories ?? [])); }, [file.categories]);
  const listMissing = !!listId && !lists.some(list => list.id === listId);

  const del = async () => {
    if (pending.current) return;
    pending.current = true; setBusy("delete");
    try {
      if (!(await confirmDialog({ title: `Удалить geo-файл «${file.name}»?`, confirmLabel: "Удалить", danger: true }))) return;
      await api("DELETE", `/api/geo/${encodeURIComponent(file.name)}`); await onChanged();
    } catch (e) { toast((e as Error).message, "err"); }
    finally { pending.current = false; setBusy(null); }
  };
  const imp = async () => {
    if (!cat) { toast("Нет категорий в файле", "err"); return; }
    if (pending.current || listMissing) return;
    pending.current = true; setBusy("import");
    try {
      const list = await api<List>("POST", "/api/geo/import", geoImportPayload(file.name, cat, limit, listId, newName));
      toast(`Импортировано в «${list.name}» (${list.domains.length} дом. / ${list.ips.length} IP)`, "ok");
      await onChanged();
    } catch (e) { toast((e as Error).message, "err"); }
    finally { pending.current = false; setBusy(null); }
  };

  return (
    <Card className={compactCard}>
      <div className="mb-3 flex flex-wrap items-center gap-2.5 border-b border-line-soft pb-3">
        <h3 className="min-w-0 max-w-full font-mono text-sm font-semibold [overflow-wrap:anywhere]">{file.name}</h3>
        <Badge>{file.kind}</Badge>
        <span className="text-xs text-muted">{cats.length} категорий</span>
        <Button mini variant="danger" className="ml-auto" onClick={del} disabled={busy !== null}>{busy === "delete" ? "Удаление…" : "Удалить файл"}</Button>
      </div>
      <fieldset disabled={busy !== null} className={cn("grid min-w-0 items-end gap-3 sm:grid-cols-2", listId ? "xl:grid-cols-[minmax(0,1.5fr)_100px_minmax(0,1fr)_auto]" : "xl:grid-cols-[minmax(0,1.5fr)_100px_minmax(0,1fr)_minmax(0,1fr)_auto]")}>
        <Field label="Категория"><Select value={cat} onChange={(e) => setCat(e.target.value)}><option value="">{cats.length ? "Выберите категорию" : "Нет категорий"}</option>{cats.map((c) => <option key={c.name} value={c.name}>{c.name} ({c.count})</option>)}</Select></Field>
        <Field label="Лимит (0 = все)"><Input type="number" min={0} step={1} value={limit} onChange={(e) => setLimit(e.target.value)} /></Field>
        <Field label="Целевой список"><Select value={listId} onChange={(e) => setListId(e.target.value)}><option value="">— новый список —</option>{listMissing && <option value={listId} disabled>Недоступный список: {listId}</option>}{lists.map((l) => <option key={l.id} value={l.id}>{l.name || l.id}</option>)}</Select></Field>
        {!listId && <Field label="Имя нового списка"><Input value={newName} placeholder={`${file.name}:категория`} onChange={(e) => setNewName(e.target.value)} /></Field>}
        <Button variant="primary" onClick={imp} disabled={busy !== null || !cat || listMissing}>{busy === "import" ? "Импорт…" : "Импортировать в список"}</Button>
      </fieldset>
    </Card>
  );
}

export default function Geo() {
  const { geo, reloadGeo, lists, reloadLists } = useStore();
  const [kind, setKind] = useState("geosite");
  const [status, setStatus] = useState("");
  const [uploading, setUploading] = useState(false);
  const uploadPending = useRef(false);
  const [autoConfig, setAutoConfig] = useState<GeoAutoConfig | null>(null);

  const upload = async (files: FileList) => {
    const file = files[0];
    if (!file || uploadPending.current) return;
    uploadPending.current = true; setUploading(true);
    setStatus(`Загрузка: ${file.name}`);
    const fd = new FormData();
    fd.append("file", file);
    fd.append("kind", kind);
    try { const d = await uploadForm<{ name: string }>("/api/geo", fd); setStatus(`✓ ${d.name}`); toast(`Загружено: ${d.name}`, "ok"); await reloadGeo(); }
    catch (e) { setStatus(""); toast((e as Error).message, "err"); }
    finally { uploadPending.current = false; setUploading(false); }
  };
  const onChanged = async () => { await reloadGeo(); await reloadLists(); };
  const summary = geoSummary(geo);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader title="GeoSite / GeoIP" description="Базы доменов и IP-адресов: обновление, категории и импорт в тестовые списки." />
      <StatsStrip label="Сводка GeoSite и GeoIP" items={[
        { label: "GeoSite", value: summary.geosite, hint: "Категории доменов" },
        { label: "GeoIP", value: summary.geoip, hint: "Категории IP / CIDR" },
        { label: "Авто-обновление", value: autoConfig ? autoConfig.enabled ? "Включено" : "Выключено" : "—", hint: autoConfig ? `Интервал: ${autoConfig.interval_hours} ч` : "Загрузка настроек" },
        { label: "Последняя попытка", value: autoConfig?.last_fetched_at ? new Date(autoConfig.last_fetched_at * 1000).toLocaleDateString("ru-RU") : "—", hint: autoConfig ? autoConfig.last_error ? "Есть ошибка обновления" : fmtAgo(autoConfig.last_fetched_at) : "Нет данных", tone: autoConfig?.last_error ? "bad" : "neutral" },
        { label: "Установлено баз", value: summary.files, hint: `Текстовых категорий: ${summary.text} · списков для импорта: ${lists.length}` },
      ]} />
      <div className="grid min-w-0 items-start gap-4 xl:grid-cols-2">
      <GeoAutoPanel onChanged={reloadGeo} onSnapshot={setAutoConfig} />
      <Card title="Загрузка файла правил" sub="v2ray / текст" className={compactCard}>
        <p className="mb-3 text-xs text-muted">Загрузите <code>geosite.dat</code> / <code>geoip.dat</code> (формат v2ray) или текстовый список (домен/IP в строке). Затем импортируйте категорию в тестовый список.</p>
        <fieldset disabled={uploading} className="flex min-w-0 flex-col gap-3">
          <Field label="Тип загружаемого файла"><Select value={kind} onChange={(e) => setKind(e.target.value)}><option value="geosite">geosite.dat</option><option value="geoip">geoip.dat</option><option value="text">текст</option></Select></Field>
          <div className="min-w-0">
            <Dropzone onFiles={upload}>
              <svg className="mx-auto mb-2 text-accent" viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 16V4m0 0 4 4m-4-4L8 8M5 16v2a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-2" /></svg>
              <div className="text-xs"><b className="text-ink">Перетащите файл</b> или нажмите</div>
              <div role="status" className="mt-1.5 min-h-4 text-xs font-medium text-ink-soft [overflow-wrap:anywhere]">{status}</div>
            </Dropzone>
          </div>
        </fieldset>
      </Card>
      </div>
      <section aria-label="Установленные базы правил" className="flex min-w-0 flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="text-sm font-semibold">Установленные базы и импорт категорий</h2><span className="text-xs text-muted">Файлов: {geo.length}</span></div>
        {!geo.length && <Card className={compactCard}><p className="py-5 text-center text-xs text-muted">Нет установленных geo-файлов. Загрузите базу или запустите обновление.</p></Card>}
        {geo.map((f) => <GeoFileCard key={f.name} file={f} lists={lists} onChanged={onChanged} />)}
      </section>
    </div>
  );
}

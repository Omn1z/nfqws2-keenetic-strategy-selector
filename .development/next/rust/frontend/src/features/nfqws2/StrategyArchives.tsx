import { useEffect, useRef, useState } from "react";
import { api, downloadFile, uploadForm } from "@/lib/api";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Dropzone } from "@/components/ui/Dropzone";
import { Input, Select } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { human } from "@/lib/format";
import { filesChanged } from "./FileExplorer";

type Snapshot = { id: string; name: string; size: number; created_at: string };
type Preview = { digest: string; files: { path: string; size: number; exists: boolean; protected_list: boolean }[]; conflicts: string[]; protected_lists: string[]; removed?: string[]; warnings: string[] };
type Source = { file: File; snapshot?: never } | { snapshot: string; file?: never };
const endpoint = "/api/nfqws2/strategy";

export function StrategyArchives() {
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [source, setSource] = useState<Source | null>(null);
  const [listChoice, setListChoice] = useState("");
  const [importError, setImportError] = useState("");
  const revision = useRef(0);
  const load = async () => { try { const d = await api<{ snapshots: Snapshot[] }>("GET", `${endpoint}/snapshots`); setSnapshots(d.snapshots ?? []); } catch (e) { toast((e as Error).message, "err"); } };
  useEffect(() => { void load(); return () => { revision.current++; }; }, []);
  const formFor = (s: Source) => { const f = new FormData(); if (s.file) f.append("file", s.file); else f.append("snapshot", s.snapshot); return f; };
  const inspect = async (s: Source) => {
    if (busy) return;
    const rev = ++revision.current;
    setBusy(true); setPreview(null); setSource(null); setListChoice(""); setImportError("");
    try { const d = await uploadForm<Preview>(`${endpoint}/preview`, formFor(s)); if (rev === revision.current) { setPreview(d); setSource(s); } }
    catch (e) { toast((e as Error).message, "err"); }
    finally { if (rev === revision.current) setBusy(false); }
  };
  const snapshot = async () => {
    if (busy) return;
    setBusy(true);
    try { await api("POST", `${endpoint}/snapshots`, { name: name.trim() || "Перед сменой стратегии" }); setName(""); await load(); toast("Стратегия и её файлы сохранены в архив", "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
    finally { setBusy(false); }
  };
  const apply = async () => {
    if (!source || !preview || busy || (preview.protected_lists.length > 0 && !listChoice)) return;
    const replace = preview.conflicts.filter(p => listChoice !== "keep" || !preview.protected_lists.includes(p));
    const description = [replace.length ? `Будут заменены: ${replace.join(", ")}.` : "Будут добавлены файлы из архива.", preview.removed?.length ? `Восстановление снимка удалит добавленные позже файлы: ${preview.removed.join(", ")}.` : "", "Перед импортом текущая стратегия автоматически сохранится в отдельный архив. Изменённые списки движок может перечитать автоматически. Новую стратегию примените кнопкой «Перезапустить» после проверки конфига."].filter(Boolean).join("\n\n");
    if (!(await confirmDialog({ title: source.snapshot ? "Восстановить стратегию?" : "Импортировать стратегию?", body: description, confirmLabel: "Применить файлы", danger: replace.length > 0 || !!preview.removed?.length }))) return;
    setBusy(true); setImportError("");
    try {
      const form = formFor(source); form.append("digest", preview.digest); form.append("overwrite", "true"); form.append("lists", listChoice || "keep");
      await uploadForm(`${endpoint}/import`, form);
      filesChanged(); setPreview(null); setSource(null); await load(); toast("Файлы импортированы. Проверьте конфиг и перезапустите NFQWS2.", "ok");
    } catch (e) { setImportError((e as Error).message); toast((e as Error).message, "err"); }
    finally { setBusy(false); }
  };
  const remove = async (s: Snapshot) => {
    if (busy) return;
    if (!(await confirmDialog({ title: `Удалить архив «${s.name}»?`, confirmLabel: "Удалить", danger: true }))) return;
    setBusy(true);
    try { await api("DELETE", `${endpoint}/snapshot?id=${encodeURIComponent(s.id)}`); if (source?.snapshot === s.id) { setSource(null); setPreview(null); } await load(); }
    catch (e) { toast((e as Error).message, "err"); }
    finally { setBusy(false); }
  };
  return <>
    <Card title="Экспорт и импорт стратегии" sub="ZIP: nfqws2.conf, lists/, blobs/, lua/ и scripts/">
      <div className="mb-4 flex flex-wrap items-center gap-3"><Button variant="primary" disabled={busy} onClick={() => void downloadFile(`${endpoint}/export`, "nfqws2-strategy.zip").catch(e => toast(e.message, "err"))}>Экспорт стратегии</Button><span className="text-xs text-muted">Импорт принимает и архив с одним конфигом.</span></div>
      <Dropzone accept=".zip" onFiles={list => { if (list[0]) void inspect({ file: list[0] }); }}><div>{busy ? "Обработка…" : "Перетащите ZIP или выберите архив для импорта"}</div><div className="mt-1 text-xs text-muted">Сначала просмотр содержимого, затем подтверждение замены.</div></Dropzone>
      {preview && source && <div className="mt-4 rounded border border-line p-3">
        <p className="mb-2 text-sm font-medium">{source.file?.name ?? snapshots.find(s => s.id === source.snapshot)?.name ?? "Сохранённая стратегия"}</p>
        <ul className="max-h-60 overflow-auto font-mono text-xs">{preview.files.map(f => <li key={f.path} className="flex justify-between gap-3 py-1"><span className="break-all">{f.path} {f.exists ? "· уже есть" : "· новый"}{f.protected_list ? " · пользовательский список" : ""}</span><span className="shrink-0 text-muted">{human(f.size)}</span></li>)}</ul>
        {!!preview.warnings?.length && <ul className="mt-3 text-xs text-warn">{preview.warnings.map(w => <li key={w}>{w}</li>)}</ul>}
        {preview.protected_lists.length > 0 && <label className="mt-4 block text-sm">В архиве есть {preview.protected_lists.join(", ")}. Какие списки использовать?
          <Select className="mt-2" value={listChoice} onChange={e => setListChoice(e.target.value)}><option value="">Выберите действие</option><option value="keep">Оставить мои текущие списки</option><option value="replace">Применить списки из архива</option></Select>
        </label>}
        {importError && <p className="mt-3 text-xs text-bad" role="alert">{importError} Проверьте содержимое заново перед повторной попыткой.</p>}
        <div className="mt-3 flex flex-wrap gap-2"><Button variant="primary" disabled={busy || (preview.protected_lists.length > 0 && !listChoice)} onClick={apply}>Импортировать</Button><Button disabled={busy} onClick={() => void inspect(source)}>Проверить заново</Button><Button disabled={busy} onClick={() => { setPreview(null); setSource(null); setImportError(""); }}>Отмена</Button></div>
      </div>}
    </Card>
    <Card title="Сохранённые стратегии" sub="Сохраните текущую стратегию перед экспериментами; её можно восстановить целиком.">
      <div className="mb-4 flex gap-2"><Input placeholder="Название архива" value={name} onChange={e => setName(e.target.value)} maxLength={80} /><Button onClick={snapshot} disabled={busy}>Архивировать текущую</Button></div>
      <div className="space-y-2">{snapshots.length === 0 && <p className="text-sm text-muted">Сохранённых стратегий пока нет.</p>}{snapshots.map(s => <div key={s.id} className="flex flex-wrap items-center gap-2 rounded border border-line p-3"><div className="min-w-0 flex-1"><p className="break-words text-sm">{s.name}</p><p className="text-xs text-muted">{new Date(s.created_at).toLocaleString()} · {human(s.size)}</p></div><Button mini disabled={busy} onClick={() => void inspect({ snapshot: s.id })}>Восстановить</Button><Button mini disabled={busy} onClick={() => void downloadFile(`${endpoint}/snapshot?id=${encodeURIComponent(s.id)}`, s.id).catch(e => toast(e.message, "err"))}>Скачать</Button><Button mini disabled={busy} onClick={() => void remove(s)}>Удалить</Button></div>)}</div>
    </Card>
  </>;
}

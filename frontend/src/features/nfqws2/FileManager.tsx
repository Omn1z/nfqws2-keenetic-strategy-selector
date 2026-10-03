import { useEffect, useRef, useState } from "react";
import { api, downloadFile, uploadForm } from "@/lib/api";
import { cn } from "@/lib/cn";
import { human } from "@/lib/format";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Dropzone } from "@/components/ui/Dropzone";
import { Input } from "@/components/ui/form";
import { CodeEditor } from "./CodeEditor";
import { ListCategories } from "./ListCategories";
import { listCategories, listCategory } from "./listCategory";
import type { ListCategory } from "./listCategory";
import { dedupSubdomains } from "./dedupSubdomains";
import type { Nfqws2File, Nfqws2Kind } from "@/types/api";

const DEFAULT_EXT: Record<Nfqws2Kind, string> = { conf: "conf", list: "list", lua: "lua", bypass: "list" };
const SIZE_WARN = 512 * 1024;

interface Props {
  kind: Nfqws2Kind;
  /** Offer to apply (SIGHUP reload) the live engine after a save. */
  reload: () => Promise<void>;
  applyTitle?: string;
  applyBody?: string;
  applyConfirmLabel?: string;
  allowCreate?: boolean;
  allowUpload?: boolean;
}

/** Reusable file manager for a single nfqws2 file kind (conf / lua / list):
 *  list on the left, monospace editor on the right, with create / upload /
 *  download / delete and (for lists) dedup / clear. */
export function FileManager({
  kind,
  reload,
  applyTitle = "Применить изменения?",
  applyBody = "Перезагрузить конфиг nfqws2 (reload, без обрыва очереди).",
  applyConfirmLabel = "Применить",
  allowCreate = true,
  allowUpload = true,
}: Props) {
  const [files, setFiles] = useState<Nfqws2File[]>([]);
  const [category, setCategory] = useState<ListCategory>("current");
  const [sel, setSel] = useState("");
  const [content, setContent] = useState("");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [newName, setNewName] = useState("");
  const [remoteChanged, setRemoteChanged] = useState(false);
  const firstLoad = useRef(true);
  const openSequence = useRef(0);
  const filesRevision = useRef(0);

  const cur = files.find((f) => f.name === sel);
  const visibleFiles = kind === "list" ? files.filter((file) => listCategory(file.name) === category) : files;
  const selectedElsewhere = kind === "list" && !!sel && listCategory(sel) !== category;

  const loadFiles = async (keep?: string) => {
    try {
      const d = await api<{ files: Nfqws2File[] }>("GET", `/api/nfqws2/files?kind=${kind}`);
      const list = d.files ?? [];
      setFiles(list);
      const want = keep ?? sel;
      if (firstLoad.current && list[0] && !want) {
        firstLoad.current = false;
        const initial = kind === "list" ? list.find((file) => listCategory(file.name) === "current") ?? list[0] : list[0];
        void open(initial.name);
      }
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };
  useEffect(() => { void loadFiles(); }, [kind]);

  useEffect(() => {
    const changed = (event: Event) => { if ((event as CustomEvent).detail?.source === `editor:${kind}`) return; filesRevision.current++; void loadFiles(sel); if (sel) setRemoteChanged(true); };
    window.addEventListener("nfqws2-files-changed", changed);
    return () => window.removeEventListener("nfqws2-files-changed", changed);
  }, [kind, sel]);

  const open = async (name: string) => {
    if (busy || name === sel && !remoteChanged) return;
    if (dirty && !(await confirmDialog({ title: "Несохранённые изменения", body: "Загрузить файл с роутера и потерять правки?", confirmLabel: "Открыть", danger: true }))) return;
    const request = ++openSequence.current;
    const fileRevision = filesRevision.current;
    setBusy(true);
    try {
      const d = await api<{ content: string }>("GET", `/api/nfqws2/file?kind=${kind}&name=${encodeURIComponent(name)}`);
      if (request !== openSequence.current) return;
      setSel(name);
      if (kind === "list") setCategory(listCategory(name));
      setContent(d.content ?? "");
      setDirty(false);
      setRemoteChanged(fileRevision !== filesRevision.current);
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      if (request === openSequence.current) setBusy(false);
    }
  };

  const save = async () => {
    if (!sel || busy) return;
    if (remoteChanged && !(await confirmDialog({ title: "Файл на роутере мог измениться", body: `Заменить ${sel} вашим несохранённым черновиком?`, confirmLabel: "Заменить", danger: true }))) return;
    setBusy(true);
    let saved = false;
    try {
      await api("POST", "/api/nfqws2/file", { kind, name: sel, content });
      saved = true;
      setDirty(false);
      setRemoteChanged(false);
      window.dispatchEvent(new CustomEvent("nfqws2-files-changed", { detail: { source: `editor:${kind}` } }));
      await loadFiles(sel);
      if (kind === "bypass") {
        await reload();
        toast(`Сохранён и применён ${sel}`, "ok");
      } else {
        toast(`Сохранён ${sel}`, "ok");
        if (await confirmDialog({ title: applyTitle, body: applyBody, confirmLabel: applyConfirmLabel, cancelLabel: "Позже" })) await reload();
      }
    } catch (e) {
      toast(saved && kind === "bypass" ? `Список сохранён, но bypass не применён: ${(e as Error).message}` : (e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  const create = async () => {
    if (busy) return;
    const stem = newName.trim();
    if (!stem) return;
    const name = `${stem}.${DEFAULT_EXT[kind]}`;
    setBusy(true);
    try {
      await api("POST", "/api/nfqws2/file/create", { kind, name });
      window.dispatchEvent(new CustomEvent("nfqws2-files-changed", { detail: { source: `editor:${kind}` } }));
      setNewName("");
      await loadFiles(name);
      if (kind === "list") setCategory(listCategory(name));
      await open(name);
      toast(`Создан ${name}`, "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  const upload = async (fl: FileList) => {
    setBusy(true);
    let ok = 0;
    let last = "";
    try {
      for (const file of Array.from(fl)) {
        const fd = new FormData();
        fd.append("kind", kind);
        fd.append("file", file);
        try {
          await uploadForm("/api/nfqws2/file/upload", fd);
          ok++;
          last = file.name.replace(/\.gz$/i, "");
        } catch (e) {
          toast(`${file.name}: ${(e as Error).message}`, "err");
        }
      }
      if (ok) {
        toast(`Загружено: ${ok}`, "ok");
        await loadFiles(last);
        if (kind === "list" && last) setCategory(listCategory(last));
        if (last) await open(last);
      }
    } finally {
      setBusy(false);
    }
  };

  const download = () => {
    if (!sel) return;
    downloadFile(`/api/nfqws2/file/download?kind=${kind}&name=${encodeURIComponent(sel)}`, sel).catch((e) => toast((e as Error).message, "err"));
  };

  const del = async () => {
    if (busy || !cur || cur.protected) return;
    if (!(await confirmDialog({ title: `Удалить ${cur.name}?`, confirmLabel: "Удалить", danger: true }))) return;
    setBusy(true);
    try {
      await api("DELETE", `/api/nfqws2/file?kind=${kind}&name=${encodeURIComponent(cur.name)}`);
      window.dispatchEvent(new CustomEvent("nfqws2-files-changed", { detail: { source: `editor:${kind}` } }));
      toast(`Удалён ${cur.name}`, "ok");
      setSel(""); setContent(""); setDirty(false);
      await loadFiles("");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  const dedup = () => {
    const seen = new Set<string>();
    let removed = 0;
    const out = content.split("\n").filter((line) => {
      const t = line.trim();
      if (!t || t.startsWith("#")) return true; // keep blanks + comments
      const key = t.toLowerCase();
      if (seen.has(key)) { removed++; return false; }
      seen.add(key);
      return true;
    });
    setContent(out.join("\n"));
    setDirty(true);
    toast(removed ? `Удалено дубликатов: ${removed}` : "Дубликатов не найдено", removed ? "ok" : "warn");
  };

  const dedupCoveredSubdomains = () => {
    if (busy || kind !== "list") return;
    const result = dedupSubdomains(content);
    if (result.skipped) {
      toast("Дедуп не выполнен: в файле слишком длинная строка или нестандартные разделители. Содержимое сохранено без изменений.", "warn");
      return;
    }
    if (result.content === content) {
      toast("Поддомены, уже покрытые родительскими доменами, не найдены", "warn");
      return;
    }
    setContent(result.content);
    setDirty(true);
    toast(`Удалено поддоменов: ${result.removed}. Нажмите «Сохранить», чтобы записать изменения.`, "ok");
  };

  const clear = async () => {
    if (!(await confirmDialog({ title: `Очистить ${sel}?`, body: "Содержимое будет стёрто (вступит в силу после «Сохранить»).", confirmLabel: "Очистить", danger: true }))) return;
    setContent(""); setDirty(true);
  };

  const setBody = (v: string) => { setContent(v); setDirty(true); };
  const tooBig = content.length > SIZE_WARN;

  return (
    <div className="flex flex-col gap-5 lg:flex-row lg:items-start">
      <aside className="w-full shrink-0 lg:w-[260px]">
        {kind === "list" && <div className="mb-3">
          <ListCategories value={category} onChange={setCategory} disabled={busy} counts={{ current: files.filter((file) => listCategory(file.name) === "current").length, original: files.filter((file) => listCategory(file.name) === "original").length }} />
          <p className="mt-1.5 text-[11px] leading-4 text-muted">{category === "original" ? "Файлы .list-opkg, поставленные пакетом." : "Основные списки и остальные файлы без суффикса .list-opkg."}</p>
        </div>}
        {!allowUpload && kind !== "bypass" && <p className="mb-2 text-xs text-muted">Загрузка файлов доступна на вкладке «Файлы».</p>}
        {allowUpload && (
          <Dropzone multiple onFiles={upload}>
            <div className="text-[13px] font-medium">Загрузить файл</div>
            <div className="mt-0.5 text-xs text-muted">перетащите или нажмите · .gz распакуется</div>
          </Dropzone>
        )}
        <ul className="m-0 mt-3 list-none p-0">
          {visibleFiles.map((f) => (
            <li key={f.name} className="mb-2">
              <button type="button" disabled={busy} onClick={() => void open(f.name)} aria-current={sel === f.name ? "true" : undefined}
              className={cn(
                "flex w-full min-w-0 cursor-pointer items-center gap-2 rounded-md border p-2.5 text-left outline-none transition-[color,background-color,border-color] hover:bg-line-soft focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
                sel === f.name ? "border-ring/50 bg-line-soft" : "border-border bg-panel",
              )}
              >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5 font-mono text-[12.5px] font-semibold">
                  <span className="truncate">{f.name}</span>
                  {f.protected && <span title="Защищён от удаления">🔒</span>}
                </div>
                <div className="mt-0.5 flex items-center gap-1.5 text-xs text-muted">
                  {human(f.size)}
                  {f.gz && <Badge kind="neutral">gz</Badge>}
                </div>
              </div>
              </button>
            </li>
          ))}
          {visibleFiles.length === 0 && <li className="px-1 py-2 text-xs text-muted">{kind === "list" ? `В категории «${listCategories.find((item) => item.id === category)?.label}» файлов нет.` : "Файлов нет."}</li>}
        </ul>
        {selectedElsewhere && <p className="mb-3 text-xs leading-5 text-muted">Открытый файл остаётся в редакторе. <button type="button" onClick={() => setCategory(listCategory(sel))} className="rounded-sm text-foreground underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring">Показать его в списке</button></p>}
        {allowCreate && (
          <div className="mt-2 flex gap-2">
            <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder={`имя без .${DEFAULT_EXT[kind]}`} onKeyDown={(e) => { if (e.key === "Enter") void create(); }} className="h-9 py-1 text-xs" />
            <Button onClick={create} disabled={busy || !newName.trim()} title="Создать файл">＋</Button>
          </div>
        )}
      </aside>

      <div className="min-w-0 flex-1">
        {!sel && <p className="py-10 text-center text-muted">Выберите файл слева, загрузите или создайте новый.</p>}
        {sel && (
          <Card
            title={<span className="font-mono text-sm">{sel}{dirty && <span className="ml-1.5 text-warn">●</span>}</span>}
            head={
              <div className="flex gap-1.5">
                <Button mini onClick={download} title="Скачать файл">⤓ Скачать</Button>
                {!cur?.protected && <Button mini variant="danger" disabled={busy} onClick={del}>Удалить</Button>}
              </div>
            }
          >
            {remoteChanged && <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-warn"><span>Файлы на роутере изменились. Открытый черновик сохранён.</span><Button mini disabled={busy} onClick={() => void open(sel)}>Загрузить заново</Button></div>}
            {cur?.gz && <p className="mb-2 text-xs text-muted">Файл хранится сжатым (.gz). Показан распакованным; при сохранении запишется как обычный текст.</p>}
            {sel === "auto.list" && <p className="mb-2 text-xs text-warn">Обновляется автоподбором — ваши правки движок может перезаписать.</p>}
            {kind === "lua" && <p className="mb-2 text-xs text-warn">Это логика обхода DPI. Ошибка в скрипте может остановить nfqws2 — правьте осторожно.</p>}
            {tooBig && <p className="mb-2 text-xs text-warn">Большой файл ({human(content.length)}) — редактирование может тормозить.</p>}
            <CodeEditor key={`${kind}/${sel}`} value={content} onChange={setBody} kind={kind === "lua" ? "lua" : kind === "conf" ? "conf" : "text"} label={sel} readOnly={busy} onSave={() => { if (dirty && !busy) void save(); }} />
            <div className="mt-2.5 flex flex-wrap items-center gap-2">
              <Button variant="primary" onClick={save} disabled={busy || !dirty}>{busy ? "Сохранение…" : "Сохранить"}</Button>
              {(kind === "list" || kind === "bypass") && <Button disabled={busy} onClick={dedup} title="Удалить повторяющиеся строки">Дедуп</Button>}
              {kind === "list" && <Button disabled={busy} onClick={dedupCoveredSubdomains} title="example.com + sub.example.com → example.com. Удаляет поддомены, уже покрытые доменами в этом списке.">Дедуп поддоменов</Button>}
              {(kind === "list" || kind === "bypass") && <Button disabled={busy} variant="ghost" onClick={clear}>Очистить</Button>}
              {!dirty && <span className="text-xs text-muted">сохранено</span>}
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}

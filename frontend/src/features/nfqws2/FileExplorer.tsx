import { useEffect, useMemo, useRef, useState } from "react";
import type { DragEvent, InputHTMLAttributes } from "react";
import { ContextMenu } from "@base-ui/react/context-menu";
import { Menu } from "@base-ui/react/menu";
import { api, ApiHTTPError, downloadFile, uploadForm } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { Button, buttonVariants } from "@/components/ui/Button";
import { Input } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { human } from "@/lib/format";
import { CodeEditor } from "./CodeEditor";
import { ExplorerIcon } from "./ExplorerIcon";
import { acceptsFolders, assetSections, breadcrumbs, filesFromDrop, filesFromPicker, folderEntries, folderName, formatModifiedTime, knownFolders, parentFolder, physicalFolder, uploadPath } from "./fileExplorerModel";
import type { Asset, ExplorerEntry, IncomingFile } from "./fileExplorerModel";
import { listCategory, type ListCategory } from "./listCategory";
import { ListCategories } from "./ListCategories";

export const filesChanged = () => window.dispatchEvent(new Event("nfqws2-files-changed"));
const menuPopupClass = "min-w-48 max-w-[min(24rem,calc(100vw-2rem))] rounded-md bg-popover p-1 text-sm text-popover-foreground shadow-lg ring-1 ring-foreground/10 outline-none";
const menuItemClass = "flex min-h-8 cursor-default items-center gap-2 rounded-sm px-2 py-1.5 outline-none data-[highlighted]:bg-line-soft data-[disabled]:pointer-events-none data-[disabled]:opacity-40";
const fileKind = (f: Asset) => ({ conf: "Конфиг", list: "Список", blob: "Блоб", lua: "Lua", script: "Скрипт" }[f.kind] ?? "Файл");
const directoryInputProps = { webkitdirectory: "", directory: "" } as InputHTMLAttributes<HTMLInputElement>;
const entryColumns = "grid grid-cols-[minmax(0,1fr)_4.5rem_2.25rem] gap-2 lg:grid-cols-[minmax(0,1fr)_9.5rem_4.5rem_2.25rem] xl:grid-cols-[minmax(0,1fr)_9.5rem_5rem_4.5rem_2.25rem]";

export function FileExplorer() {
  const [files, setFiles] = useState<Asset[]>([]);
  const [directories, setDirectories] = useState<string[]>([]);
  const [directoryModified, setDirectoryModified] = useState<Record<string, string>>({});
  const [folder, setFolder] = useState("lists");
  const [category, setCategory] = useState<ListCategory>("current");
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(["lists"]));
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [progress, setProgress] = useState("");
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [content, setContent] = useState("");
  const [dirty, setDirty] = useState(false);
  const [stale, setStale] = useState(false);
  const [roots, setRoots] = useState<Record<string, string>>({});
  const [contextEntry, setContextEntry] = useState<ExplorerEntry | null>(null);
  const [menuHandle] = useState(() => Menu.createHandle<ExplorerEntry>());
  const fileInput = useRef<HTMLInputElement>(null);
  const directoryInput = useRef<HTMLInputElement>(null);
  const inputFolder = useRef(folder);
  const readID = useRef(0);
  const loadID = useRef(0);
  const filesRevision = useRef(0);
  const busyRef = useRef(false);
  const mounted = useRef(true);
  const dirtyRef = useRef(dirty); dirtyRef.current = dirty;
  const folders = useMemo(() => knownFolders(files, directories), [files, directories]);
  const folderChildren = useMemo(() => {
    const result = new Map<string, string[]>();
    for (const path of folders) {
      const parent = parentFolder(path);
      const siblings = result.get(parent) ?? [];
      siblings.push(path); result.set(parent, siblings);
    }
    return result;
  }, [folders]);
  const inLists = folder === "lists" || folder.startsWith("lists/");
  const entries = useMemo(() => folderEntries(files, folder, query, directories, directoryModified), [files, folder, query, directories, directoryModified]);
  const categoryCounts = useMemo(() => {
    const counts = { current: 0, original: 0 };
    if (inLists) for (const entry of entries) if (entry.type === "file") counts[listCategory(entry.path)]++;
    return counts;
  }, [entries, inLists]);
  const visible = useMemo(() => entries
    .filter(entry => !inLists || entry.type === "folder" || listCategory(entry.path) === category)
    .map(entry => ({ ...entry, modified: formatModifiedTime(entry.modifiedAt) })), [entries, inLists, category]);
  const currentPath = physicalFolder(folder, roots);

  const load = async () => {
    const id = ++loadID.current;
    setLoading(true);
    try {
      const data = await api<{ files: Asset[]; directories?: string[]; directory_modified?: Record<string, string>; roots: Record<string, string> }>("GET", "/api/nfqws2/assets");
      if (!mounted.current || id !== loadID.current) return;
      setFiles(data.files ?? []); setDirectories(data.directories ?? []); setDirectoryModified(data.directory_modified ?? {}); setRoots(data.roots ?? {}); setLoadError("");
    } catch (e) {
      if (mounted.current && id === loadID.current) setLoadError((e as Error).message);
    } finally { if (mounted.current && id === loadID.current) setLoading(false); }
  };
  useEffect(() => {
    mounted.current = true;
    void load();
    const changed = () => { filesRevision.current++; void load(); setStale(true); };
    window.addEventListener("nfqws2-files-changed", changed);
    return () => { mounted.current = false; window.removeEventListener("nfqws2-files-changed", changed); readID.current++; loadID.current++; };
  }, []);
  const begin = (message: string) => {
    if (busyRef.current) return false;
    busyRef.current = true; setBusy(true); setProgress(message); return true;
  };
  const finish = () => { busyRef.current = false; if (mounted.current) { setBusy(false); setProgress(""); } };
  const navigate = (path: string) => {
    setFolder(path); setQuery(""); setDropTarget(null);
    setExpanded(previous => new Set([...previous, ...breadcrumbs(path).map(crumb => crumb.path)]));
  };
  const chooseUpload = (path: string, directory = false) => {
    if (busyRef.current || !path) return;
    inputFolder.current = path;
    (directory ? directoryInput : fileInput).current?.click();
  };
  const open = async (f: Asset) => {
    if (!begin("Открытие файла…")) return;
    try {
      if (dirtyRef.current && !(await confirmDialog({ title: "Несохранённые правки", body: "Открыть файл и сбросить правки?", confirmLabel: "Открыть" }))) return;
      const id = ++readID.current;
      const revision = filesRevision.current;
      const text = f.editable ? await api<string>("GET", `/api/nfqws2/assets/file?path=${encodeURIComponent(f.path)}`, undefined, { responseType: "text" }) : "";
      if (!mounted.current || id !== readID.current) return;
      setSelected(f); setContent(text); setDirty(false); setStale(revision !== filesRevision.current);
    } catch (e) { if (mounted.current) toast((e as Error).message, "err"); }
    finally { finish(); }
  };
  const put = (file: File, path: string, overwrite = false) => {
    const form = new FormData(); form.append("file", file); form.append("path", path); form.append("overwrite", String(overwrite));
    return uploadForm("/api/nfqws2/assets/file", form);
  };
  const upload = async (incoming: IncomingFile[] | Promise<IncomingFile[]>, target: string) => {
    if (!begin("Подготовка файлов…")) return;
    let count = 0;
    try {
      const items = await incoming;
      if (!items.length) { toast("В выбранной папке нет файлов для загрузки", "err"); return; }
      if (items.length > 1024) throw new Error("За одну загрузку можно добавить не более 1024 файлов");
      if (dirtyRef.current && !(await confirmDialog({ title: "Есть несохранённые правки", body: "Продолжить загрузку файлов? Черновик останется в редакторе.", confirmLabel: "Продолжить" }))) return;
      for (let index = 0; index < items.length; index++) {
        if (!mounted.current) break;
        const { file, relativePath } = items[index];
        setProgress(`Загрузка ${index + 1} из ${items.length}: ${relativePath}`);
        try {
          const path = uploadPath(target, relativePath);
          if (file.size > 16 * 1024 * 1024) throw new Error("Файл превышает предел 16 МиБ");
          try { await put(file, path); }
          catch (e) {
            if (!(e instanceof ApiHTTPError) || e.status !== 409) throw e;
            if (!mounted.current) break;
            if (!(await confirmDialog({ title: `Заменить ${path}?`, body: "Файл с таким именем уже существует на роутере.", confirmLabel: "Заменить", danger: true }))) continue;
            await put(file, path, true);
          }
          count++;
        } catch (e) { toast(`${relativePath}: ${(e as Error).message}`, "err"); }
      }
      if (count) { filesChanged(); toast(`Загружено файлов: ${count}`, "ok"); }
    } catch (e) { toast((e as Error).message, "err"); }
    finally { finish(); }
  };
  const save = async () => {
    if (!selected || !dirty || !begin("Сохранение файла…")) return;
    try {
      if (stale && !(await confirmDialog({ title: "Файлы на роутере изменились", body: "Заменить выбранный файл вашим черновиком?", confirmLabel: "Заменить", danger: true }))) return;
      await put(new File([content], selected.path.split("/").pop()!), selected.path, true);
      setDirty(false); filesChanged(); setStale(false); toast("Файл сохранён. Для смены стратегии перезапустите NFQWS2.", "ok");
    } catch (e) { toast((e as Error).message, "err"); }
    finally { finish(); }
  };
  const remove = async (f: Asset) => {
    if (f.protected || !begin("Удаление файла…")) return;
    try {
      if (!(await confirmDialog({ title: `Удалить ${f.path}?`, body: `${selected?.path === f.path && dirtyRef.current ? "Несохранённые правки этого файла тоже будут удалены. " : ""}Если стратегия использует этот файл, её нужно изменить перед следующим запуском.`, confirmLabel: "Удалить", danger: true }))) return;
      await api("DELETE", `/api/nfqws2/assets/file?path=${encodeURIComponent(f.path)}`);
      if (selected?.path === f.path) { readID.current++; setSelected(null); setDirty(false); }
      filesChanged(); toast("Файл удалён", "ok");
    } catch (e) { toast((e as Error).message, "err"); }
    finally { finish(); }
  };
  const download = (f: Asset) => void downloadFile(`/api/nfqws2/assets/file?path=${encodeURIComponent(f.path)}`, f.path.split("/").pop()!).catch(e => toast(e.message, "err"));
  const closeEditor = async () => {
    if (!begin("Закрытие редактора…")) return;
    try {
      if (dirtyRef.current && !(await confirmDialog({ title: "Несохранённые правки", body: "Закрыть редактор и сбросить правки?", confirmLabel: "Закрыть" }))) return;
      readID.current++; setSelected(null); setDirty(false);
    } finally { finish(); }
  };
  const dragOver = (event: DragEvent, target: string) => {
    if (!Array.from(event.dataTransfer.types).includes("Files")) return;
    event.preventDefault(); event.stopPropagation();
    event.dataTransfer.dropEffect = target && !busyRef.current ? "copy" : "none";
    if (target && !busyRef.current) setDropTarget(target);
  };
  const drop = (event: DragEvent, target: string) => {
    event.preventDefault(); event.stopPropagation(); setDropTarget(null);
    if (!target || busyRef.current) return;
    void upload(filesFromDrop(event.dataTransfer), target);
  };
  const menuActions = (entry: ExplorerEntry | null) => entry?.type === "file" ? <>
    <Menu.Item className={menuItemClass} disabled={busy} onClick={() => void open(entry.asset)}><ExplorerIcon name="file" />{entry.asset.editable ? "Открыть в редакторе" : "Сведения о файле"}</Menu.Item>
    <Menu.Item className={menuItemClass} disabled={busy} onClick={() => download(entry.asset)}><ExplorerIcon name="download" />Скачать</Menu.Item>
    <Menu.Separator className="my-1 h-px bg-border" />
    <Menu.Item className={cn(menuItemClass, "text-destructive")} disabled={busy || entry.asset.protected} onClick={() => void remove(entry.asset)}><ExplorerIcon name={entry.asset.protected ? "lock" : "trash"} />{entry.asset.protected ? "Активный конфиг защищён" : "Удалить…"}</Menu.Item>
  </> : <>
    {entry?.type === "folder" && <Menu.Item className={menuItemClass} onClick={() => navigate(entry.path)}><ExplorerIcon name="folder" />Открыть папку</Menu.Item>}
    <Menu.Item className={menuItemClass} disabled={busy || !(entry?.path ?? folder)} onClick={() => chooseUpload(entry?.path ?? folder)}><ExplorerIcon name="upload" />Загрузить файлы сюда</Menu.Item>
    <Menu.Item className={menuItemClass} disabled={loading} onClick={() => void load()}><ExplorerIcon name="refresh" />Обновить</Menu.Item>
  </>;
  const renderTree = (path: string, depth = 0) => {
    const children = folderChildren.get(path) ?? [];
    const isExpanded = expanded.has(path);
    return <div key={path}>
      <div className={cn("flex items-center rounded-md", folder === path && "bg-line-soft", dropTarget === path && "ring-1 ring-ring bg-line-soft")}
        style={{ paddingLeft: depth * 12 }} onDragOver={e => dragOver(e, path)} onDrop={e => drop(e, path)}>
        <button type="button" disabled={!children.length} aria-label={`${isExpanded ? "Свернуть" : "Развернуть"} ${folderName(path)}`} aria-expanded={children.length ? isExpanded : undefined}
          onClick={() => setExpanded(previous => { const next = new Set(previous); if (next.has(path)) next.delete(path); else next.add(path); return next; })}
          className="flex size-6 shrink-0 items-center justify-center rounded-sm outline-none hover:bg-rhea-input/50 focus-visible:ring-2 focus-visible:ring-ring disabled:invisible">
          <ExplorerIcon name="chevron" className={cn("size-3 transition-transform", isExpanded && "rotate-90")} />
        </button>
        <button type="button" onClick={() => navigate(path)} title={physicalFolder(path, roots)} aria-current={folder === path ? "page" : undefined}
          className="flex min-w-0 flex-1 items-center gap-2 rounded-md py-2 pr-2 text-left text-xs outline-none hover:bg-line-soft focus-visible:ring-2 focus-visible:ring-ring">
          <ExplorerIcon name="folder" className="size-4 shrink-0 text-muted-foreground" /><span className="truncate">{folderName(path)}</span>
        </button>
      </div>
      {isExpanded && children.map(child => renderTree(child, depth + 1))}
    </div>;
  };

  return <Card title="File Explorer" sub="Конфиги, списки, блобы и скрипты NFQWS2">
    <input ref={fileInput} type="file" multiple hidden onChange={e => { if (e.target.files) void upload(filesFromPicker(e.target.files), inputFolder.current); e.target.value = ""; }} />
    <input ref={directoryInput} type="file" multiple hidden {...directoryInputProps} onChange={e => { if (e.target.files) void upload(filesFromPicker(e.target.files), inputFolder.current); e.target.value = ""; }} />
    <div className="overflow-hidden rounded-lg border border-border bg-background" onDragLeave={e => { if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDropTarget(null); }}>
      <div className="flex min-w-0 items-center gap-2 border-b border-border p-2">
        <Button variant="ghost" disabled={!folder} onClick={() => navigate(parentFolder(folder))} title="На уровень вверх" aria-label="На уровень вверх" className="size-8 shrink-0 p-0"><ExplorerIcon name="up" /></Button>
        <nav aria-label="Путь к папке" className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto whitespace-nowrap text-xs">
          {breadcrumbs(folder).map((crumb, index, items) => <span key={crumb.path} className="flex items-center gap-1">
            {index > 0 && <ExplorerIcon name="chevron" className="size-3 text-muted-foreground" />}
            <button type="button" aria-current={index === items.length - 1 ? "page" : undefined} onClick={() => navigate(crumb.path)} className="rounded px-1.5 py-1.5 outline-none hover:bg-line-soft focus-visible:ring-2 focus-visible:ring-ring">{crumb.name}</button>
          </span>)}
        </nav>
        <Button variant="ghost" disabled={loading} onClick={() => void load()} aria-label="Обновить файлы" title="Обновить файлы" className="size-8 shrink-0 p-0"><ExplorerIcon name="refresh" className={cn("size-4", loading && "animate-spin")} /></Button>
      </div>
      <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
        <Button disabled={busy || !folder} onClick={() => chooseUpload(folder)}><ExplorerIcon name="upload" />Загрузить файлы</Button>
        <Button variant="ghost" disabled={busy || !acceptsFolders(folder)} onClick={() => chooseUpload(folder, true)} title="Загрузить папку с сохранением вложенных файлов"><ExplorerIcon name="folder" />Загрузить папку</Button>
        <div className="relative min-w-36 flex-1 sm:ml-auto sm:max-w-64"><ExplorerIcon name="search" className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" /><Input aria-label="Поиск файлов в папке" value={query} disabled={!folder} onChange={e => setQuery(e.target.value)} placeholder="Поиск в папке…" className="pl-8" /></div>
      </div>
      {inLists && <div className="border-b border-border px-3 py-2">
        <ListCategories value={category} counts={categoryCounts} disabled={busy} onChange={value => { setCategory(value); setContextEntry(null); }} />
      </div>}
      <div className="grid min-w-0 md:grid-cols-[176px_minmax(0,1fr)]">
        <nav aria-label="Папки NFQWS2" className="hidden max-h-[480px] overflow-auto border-r border-border bg-card/40 p-2 md:block">
          <p className="px-2 pb-2 pt-1 text-[11px] font-medium text-muted-foreground">NFQWS2</p>
          {assetSections.map(section => renderTree(section.path))}
        </nav>
        <div className="min-w-0">
          <div className="flex gap-1 overflow-x-auto border-b border-border p-2 md:hidden">{assetSections.map(section => <Button key={section.path} mini variant={folder.split("/")[0] === section.path ? "default" : "ghost"} onClick={() => navigate(section.path)} className="shrink-0"><ExplorerIcon name="folder" />{section.name}</Button>)}</div>
          <ContextMenu.Root disabled={busy}>
            <ContextMenu.Trigger className="relative min-h-64 outline-none" onPointerDownCapture={e => { if (!(e.target as HTMLElement).closest("[data-explorer-entry]")) setContextEntry(null); }} onContextMenuCapture={e => { if (!(e.target as HTMLElement).closest("[data-explorer-entry]")) setContextEntry(null); }}
              onDragOver={e => dragOver(e, folder)} onDrop={e => drop(e, folder)} onDragLeave={e => { if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDropTarget(null); }}>
              <div className={cn(entryColumns, "border-b border-border px-3 py-2 text-[11px] text-muted-foreground")}><span>Имя</span><span className="hidden lg:block" title="Дата и время изменения в часовом поясе браузера">Изменён</span><span className="hidden xl:block">Тип</span><span className="text-right">Размер</span><span /></div>
              <div className={cn("max-h-[400px] min-h-52 overflow-auto", dropTarget === folder && "bg-line-soft/50 ring-1 ring-inset ring-ring")}>
                {loadError ? <div className="p-5 text-sm text-destructive">{loadError}<Button mini className="mt-3 block" onClick={() => void load()}>Повторить</Button></div> : loading && !files.length && !directories.length ? <p className="p-6 text-center text-sm text-muted-foreground">Загрузка файлов…</p> : !visible.length ? <div className="flex min-h-52 flex-col items-center justify-center gap-2 p-6 text-center text-sm text-muted-foreground"><ExplorerIcon name={query ? "search" : "folder"} className="mb-1 size-7 opacity-60" /><p>{query ? "Файлы не найдены" : "В этой папке пока нет файлов"}</p>{!query && <p className="text-xs">Перетащите файлы сюда или используйте кнопку загрузки.</p>}</div> : visible.map(entry => <div key={`${entry.type}:${entry.path}`} data-explorer-entry={entry.path}
                  onContextMenu={() => setContextEntry(entry)} onPointerDown={() => setContextEntry(entry)}
                  onDragOver={entry.type === "folder" ? e => dragOver(e, entry.path) : undefined} onDrop={entry.type === "folder" ? e => drop(e, entry.path) : undefined}
                  className={cn(entryColumns, "group items-center border-b border-border/50 px-3 py-1 last:border-b-0 hover:bg-line-soft/50", entry.type === "file" && selected?.path === entry.path && "bg-line-soft", dropTarget === entry.path && "bg-line-soft ring-1 ring-inset ring-ring")}>
                  <button type="button" disabled={busy} onClick={() => entry.type === "folder" ? navigate(entry.path) : void open(entry.asset)} title={entry.name} className="flex min-w-0 items-center gap-2.5 rounded py-2 text-left text-xs outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60">
                    <ExplorerIcon name={entry.type === "folder" ? "folder" : entry.asset.kind === "blob" ? "blob" : entry.asset.kind === "lua" || entry.asset.kind === "script" ? "code" : "file"} className="size-4 shrink-0 text-muted-foreground" />
                    <span className="min-w-0"><span className={cn("block truncate", entry.type === "file" && "font-mono")}>{entry.name}</span><time dateTime={entry.modified.dateTime} title={entry.modified.title} className="mt-1 block truncate text-[11px] tabular-nums text-muted-foreground lg:hidden"><span className="sr-only">Изменён: </span>{entry.modified.label}</time></span>{entry.type === "file" && entry.asset.protected && <span title="Активный конфиг: удаление запрещено"><ExplorerIcon name="lock" className="size-3 text-muted-foreground" /></span>}
                  </button>
                  <time dateTime={entry.modified.dateTime} title={entry.modified.title} className="hidden whitespace-nowrap text-xs tabular-nums text-muted-foreground lg:block">{entry.modified.label}</time>
                  <span className="hidden truncate text-xs text-muted-foreground xl:block">{entry.type === "folder" ? "Папка" : fileKind(entry.asset)}</span>
                  <span className="text-right text-xs tabular-nums text-muted-foreground">{entry.type === "file" ? human(entry.asset.size) : "—"}</span>
                  <Menu.Trigger handle={menuHandle} payload={entry} disabled={busy} aria-label={`Действия: ${entry.name}`} title="Действия" className={cn(buttonVariants({ variant: "ghost", size: "mini" }), "size-7 min-h-7 p-0")}><ExplorerIcon name="more" /></Menu.Trigger>
                </div>)}
              </div>
              {dropTarget && <div className="pointer-events-none border-t border-border bg-line-soft px-3 py-2 text-xs">Загрузить в {physicalFolder(dropTarget, roots) || folderName(dropTarget)}</div>}
            </ContextMenu.Trigger>
            <ContextMenu.Portal><ContextMenu.Positioner className="z-[60]" sideOffset={4}><ContextMenu.Popup className={menuPopupClass}>{menuActions(contextEntry)}</ContextMenu.Popup></ContextMenu.Positioner></ContextMenu.Portal>
          </ContextMenu.Root>
        </div>
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 border-t border-border px-3 py-2 text-[11px] text-muted-foreground" role="status">
        <span className="min-w-0 break-all">{busy ? progress : `${query ? "Найдено" : "Элементов"}: ${visible.length}`}</span><span className="min-w-0 flex-1 truncate text-right font-mono" title={currentPath}>{currentPath || "Выберите папку для загрузки файлов"}</span>
      </div>
    </div>
    <Menu.Root handle={menuHandle}>{({ payload }) => <Menu.Portal><Menu.Positioner className="z-[60]" side="bottom" align="end" sideOffset={4}><Menu.Popup className={menuPopupClass}>{menuActions(payload ?? null)}</Menu.Popup></Menu.Positioner></Menu.Portal>}</Menu.Root>
    <p className="mt-2 text-xs text-muted-foreground">Перетаскивайте файлы в открытую папку или на папку в списке. ПКМ или ··· — действия с файлом. Даты — в часовом поясе браузера; у папок показано время изменения самого каталога.</p>
    {selected && <section aria-label={`Редактор ${selected.path}`} className="mt-5 min-w-0 border-t border-border pt-4">
      <div className="mb-3 flex min-w-0 items-center gap-2"><ExplorerIcon name="file" /><span className="min-w-0 flex-1 break-all font-mono text-xs">{selected.path}{dirty ? " ●" : ""}</span><Button mini variant="ghost" disabled={busy} onClick={() => download(selected)} aria-label="Скачать открытый файл" title="Скачать файл"><ExplorerIcon name="download" /></Button><Button mini variant="ghost" disabled={busy} onClick={() => void closeEditor()} aria-label="Закрыть редактор" title="Закрыть редактор"><ExplorerIcon name="close" /></Button></div>
      {selected.editable ? <><CodeEditor key={selected.path} value={content} onChange={value => { setContent(value); setDirty(true); }} readOnly={busy} onSave={() => void save()} kind={selected.path.endsWith(".lua") ? "lua" : selected.kind === "conf" || selected.kind === "script" ? "conf" : "text"} />
        <div className="mt-2 flex gap-2"><Button variant="primary" disabled={busy || !dirty} onClick={() => void save()}>Сохранить</Button><Button disabled={busy} onClick={() => void open(selected)}>Перечитать</Button></div>
        {stale && <p className="mt-2 text-xs text-warn">Состав файлов изменился. Перед сохранением можно перечитать файл.</p>}
      </> : <div className="rounded-md border border-border p-4 text-sm text-muted-foreground">Бинарный или сжатый файл · {human(selected.size)}. Его можно скачать, заменить загрузкой или удалить через меню.</div>}
    </section>}
  </Card>;
}

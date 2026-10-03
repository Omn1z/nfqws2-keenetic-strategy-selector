export type Asset = { path: string; kind: string; size: number; editable: boolean; protected: boolean; modified_at?: string };
export type FolderEntry = { type: "folder"; path: string; name: string; modifiedAt?: string };
export type FileEntry = { type: "file"; path: string; name: string; asset: Asset; modifiedAt?: string };
export type ExplorerEntry = FolderEntry | FileEntry;
export type IncomingFile = { file: File; relativePath: string };

// Intl instances are reused for every row and render. Omitting timeZone follows
// the browser's local zone; an explicit zone also makes formatting testable.
export function createModifiedTimeFormatter(timeZone?: string) {
  const options: Intl.DateTimeFormatOptions = { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone };
  const compact = new Intl.DateTimeFormat("ru", options);
  const full = new Intl.DateTimeFormat("ru", { ...options, second: "2-digit", timeZoneName: "short" });
  const zone = compact.resolvedOptions().timeZone;
  return (value?: string): { label: string; title: string; dateTime?: string } => {
    const missing = { label: "—", title: "Время изменения неизвестно" };
    // Accept only timestamped instants: Date.parse also accepts ambiguous local
    // dates and normalizes nonexistent dates such as February 30.
    if (typeof value !== "string") return missing;
    const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.exec(value);
    if (!parts) return missing;
    const [, year, month, day, hour, minute, second] = parts.map(Number);
    if (year < 100 || month < 1 || month > 12 || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate() || hour > 23 || minute > 59 || second > 59) return missing;
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return missing;
    return { label: compact.format(date), title: `${full.format(date)} · ${zone} (время браузера)`, dateTime: date.toISOString() };
  };
}
export const formatModifiedTime = createModifiedTimeFormatter();

export const assetSections = [
  { path: "configs", name: "Конфиги", root: "conf" },
  { path: "lists", name: "Списки", root: "list" },
  { path: "blobs", name: "Блобы", root: "blob" },
  { path: "lua", name: "Lua", root: "lua" },
  { path: "scripts", name: "Скрипты", root: "script" },
] as const;

const collator = new Intl.Collator("ru", { numeric: true, sensitivity: "base" });
const virtualPath = (asset: Asset) => asset.path === "nfqws2.conf" ? "configs/nfqws2.conf" : asset.path;
export const parentFolder = (folder: string) => folder.includes("/") ? folder.slice(0, folder.lastIndexOf("/")) : "";
export const folderName = (folder: string) => assetSections.find(s => s.path === folder)?.name ?? folder.split("/").pop() ?? "NFQWS2";
export const acceptsFolders = (folder: string) => ["lists", "blobs", "lua"].includes(folder.split("/")[0]);

export function knownFolders(files: Asset[], directories: string[] = []): string[] {
  const result = new Set<string>(assetSections.map(s => s.path));
  for (const directory of [...directories, ...files.map(f => parentFolder(virtualPath(f)))]) {
    const parts = directory.split("/");
    if (!assetSections.some(s => s.path === parts[0])) continue;
    for (let end = 1; end <= parts.length; end++) result.add(parts.slice(0, end).join("/"));
  }
  return [...result].sort(collator.compare);
}

export function folderEntries(files: Asset[], folder: string, query = "", directories: string[] = [], directoryModified: Record<string, string> = {}): ExplorerEntry[] {
  if (!folder) return assetSections.map(s => ({ type: "folder", path: s.path, name: s.name, modifiedAt: directoryModified[s.path] }));
  const prefix = `${folder}/`;
  const search = query.trim().toLocaleLowerCase();
  const children: ExplorerEntry[] = search ? [] : knownFolders(files, directories)
    .filter(path => parentFolder(path) === folder)
    .map(path => ({ type: "folder", path, name: folderName(path), modifiedAt: directoryModified[path] }));
  for (const asset of files) {
    const path = virtualPath(asset);
    if (!path.startsWith(prefix)) continue;
    const relative = path.slice(prefix.length);
    if (search ? !relative.toLocaleLowerCase().includes(search) : relative.includes("/")) continue;
    children.push({ type: "file", path: asset.path, name: relative, asset, modifiedAt: asset.modified_at });
  }
  return children.sort((a, b) => a.type !== b.type ? a.type === "folder" ? -1 : 1 : collator.compare(a.name, b.name));
}

export function breadcrumbs(folder: string): { path: string; name: string }[] {
  return [{ path: "", name: "NFQWS2" }, ...folder.split("/").filter(Boolean).map((_, index, parts) => {
    const path = parts.slice(0, index + 1).join("/");
    return { path, name: folderName(path) };
  })];
}

export function physicalFolder(folder: string, roots: Record<string, string>): string {
  const [section, ...parts] = folder.split("/");
  const key = assetSections.find(s => s.path === section)?.root;
  return key && roots[key] ? [roots[key].replace(/\/$/, ""), ...parts].join("/") : "";
}

// Match the server's archive-relative namespace without normalizing traversal or
// silently flattening a dropped directory. The server remains the authority.
export function uploadPath(folder: string, relativePath: string): string {
  if (!folder || !assetSections.some(s => s.path === folder.split("/")[0])) throw new Error("Сначала откройте папку для загрузки");
  const path = folder === "configs" && relativePath === "nfqws2.conf" ? relativePath : `${folder}/${relativePath}`;
  const parts = path.split("/");
  if (path.length > 512 || parts.length > 10 || parts.some(part => !/^[a-zA-Z0-9_-][a-zA-Z0-9_.-]*$/.test(part) || part.endsWith(".") || part.length > 180)) {
    throw new Error(`Недопустимый путь «${relativePath}». Используйте латиницу, цифры, дефис, точку и подчёркивание; не более 10 уровней`);
  }
  if (folder === "configs" && relativePath !== "nfqws2.conf" && (relativePath.includes("/") || !/\.(?:conf|conf-old|conf-opkg|apk-new)$/.test(relativePath))) {
    throw new Error("В Конфиги можно загружать только файлы .conf, .conf-old, .conf-opkg и .apk-new без вложенных папок");
  }
  if (folder === "scripts" && (relativePath.includes("/") || !relativePath.endsWith(".sh"))) {
    throw new Error("В Скрипты можно загружать только файлы .sh без вложенных папок");
  }
  if (!["configs", "scripts"].includes(folder) && !acceptsFolders(folder)) throw new Error("Этот раздел не поддерживает вложенные папки");
  return path;
}

export function filesFromPicker(files: FileList | File[]): IncomingFile[] {
  return Array.from(files).map(file => ({ file, relativePath: file.webkitRelativePath || file.name }));
}

export async function filesFromDrop(data: DataTransfer): Promise<IncomingFile[]> {
  // Read handles and fallback files while the drop event still grants access.
  const entries = Array.from(data.items ?? []).filter(item => item.kind === "file").map(item => ({
    entry: item.webkitGetAsEntry?.(), file: item.getAsFile(),
  }));
  const fallback = filesFromPicker(data.files);
  if (!entries.some(item => item.entry)) return fallback;
  const result: IncomingFile[] = [];
  const add = (file: File, relativePath: string) => {
    if (result.length >= 1024) throw new Error("За одну загрузку можно добавить не более 1024 файлов");
    result.push({ file, relativePath });
  };
  const visit = async (entry: FileSystemEntry, prefix: string, depth: number): Promise<void> => {
    if (depth > 10) throw new Error("Слишком глубокая структура папок: максимум 10 уровней");
    const relativePath = prefix + entry.name;
    if (entry.isFile) {
      const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject));
      add(file, relativePath);
    } else if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader();
      for (;;) {
        const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => reader.readEntries(resolve, reject));
        if (!batch.length) break;
        for (const child of batch) await visit(child, relativePath + "/", depth + 1);
      }
    }
  };
  for (const { entry, file } of entries) {
    if (entry) await visit(entry, "", 1);
    else if (file) add(file, file.name);
  }
  return result;
}

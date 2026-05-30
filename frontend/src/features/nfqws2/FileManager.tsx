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
import { Input, Textarea } from "@/components/ui/form";
import type { Nfqws2File, Nfqws2Kind } from "@/types/api";

const DEFAULT_EXT: Record<Nfqws2Kind, string> = { conf: "conf", list: "list", lua: "lua" };
const SIZE_WARN = 512 * 1024;

interface Props {
  kind: Nfqws2Kind;
  /** Offer to apply (SIGHUP reload) the live engine after a save. */
  reload: () => Promise<void>;
}

/** Reusable file manager for a single nfqws2 file kind (conf / lua / list):
 *  list on the left, monospace editor on the right, with create / upload /
 *  download / delete and (for lists) dedup / clear. */
export function FileManager({ kind, reload }: Props) {
  const [files, setFiles] = useState<Nfqws2File[]>([]);
  const [sel, setSel] = useState("");
  const [content, setContent] = useState("");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [newName, setNewName] = useState("");
  const firstLoad = useRef(true);

  const cur = files.find((f) => f.name === sel);

  const loadFiles = async (keep?: string) => {
    try {
      const d = await api<{ files: Nfqws2File[] }>("GET", `/api/nfqws2/files?kind=${kind}`);
      const list = d.files ?? [];
      setFiles(list);
      const want = keep ?? sel;
      if (firstLoad.current && list[0] && !want) {
        firstLoad.current = false;
        void open(list[0].name);
      }
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };
  useEffect(() => { void loadFiles(); }, [kind]);

  const open = async (name: string) => {
    if (dirty && name !== sel && !(await confirmDialog({ title: "Несохранённые изменения", body: "Открыть другой файл и потерять правки?", confirmLabel: "Открыть", danger: true }))) return;
    try {
      const d = await api<{ content: string }>("GET", `/api/nfqws2/file?kind=${kind}&name=${encodeURIComponent(name)}`);
      setSel(name);
      setContent(d.content ?? "");
      setDirty(false);
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  const save = async () => {
    if (!sel) return;
    setBusy(true);
    try {
      await api("POST", "/api/nfqws2/file", { kind, name: sel, content });
      setDirty(false);
      toast(`Сохранён ${sel}`, "ok");
      await loadFiles(sel);
      if (await confirmDialog({ title: "Применить изменения?", body: "Перезагрузить конфиг nfqws2 (reload, без обрыва очереди).", confirmLabel: "Применить", cancelLabel: "Позже" })) await reload();
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  const create = async () => {
    const stem = newName.trim();
    if (!stem) return;
    const name = `${stem}.${DEFAULT_EXT[kind]}`;
    try {
      await api("POST", "/api/nfqws2/file/create", { kind, name });
      setNewName("");
      await loadFiles(name);
      await open(name);
      toast(`Создан ${name}`, "ok");
    } catch (e) {
      toast((e as Error).message, "err");
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
    if (!cur || cur.protected) return;
    if (!(await confirmDialog({ title: `Удалить ${cur.name}?`, confirmLabel: "Удалить", danger: true }))) return;
    try {
      await api("DELETE", `/api/nfqws2/file?kind=${kind}&name=${encodeURIComponent(cur.name)}`);
      toast(`Удалён ${cur.name}`, "ok");
      setSel(""); setContent(""); setDirty(false);
      await loadFiles("");
    } catch (e) {
      toast((e as Error).message, "err");
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

  const clear = async () => {
    if (!(await confirmDialog({ title: `Очистить ${sel}?`, body: "Содержимое будет стёрто (вступит в силу после «Сохранить»).", confirmLabel: "Очистить", danger: true }))) return;
    setContent(""); setDirty(true);
  };

  const setBody = (v: string) => { setContent(v); setDirty(true); };
  const tooBig = content.length > SIZE_WARN;

  return (
    <div className="flex flex-col gap-5 lg:flex-row lg:items-start">
      <aside className="w-full shrink-0 lg:w-[260px]">
        <Dropzone multiple onFiles={upload}>
          <div className="text-[13px] font-medium">Загрузить файл</div>
          <div className="mt-0.5 text-xs text-muted">перетащите или нажмите · .gz распакуется</div>
        </Dropzone>
        <ul className="m-0 mt-3 list-none p-0">
          {files.map((f) => (
            <li
              key={f.name}
              onClick={() => open(f.name)}
              className={cn(
                "mb-2 flex cursor-pointer items-center gap-2 rounded-[10px] border p-2.5 transition hover:-translate-y-px hover:border-accent hover:shadow-sm",
                sel === f.name ? "border-accent bg-accent-w" : "border-line bg-panel",
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
            </li>
          ))}
          {files.length === 0 && <li className="px-1 py-2 text-xs text-muted">Файлов нет.</li>}
        </ul>
        <div className="mt-2 flex gap-2">
          <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder={`имя без .${DEFAULT_EXT[kind]}`} onKeyDown={(e) => { if (e.key === "Enter") void create(); }} className="h-9 py-1 text-xs" />
          <Button onClick={create} disabled={!newName.trim()} title="Создать файл">＋</Button>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        {!sel && <p className="py-10 text-center text-muted">Выберите файл слева, загрузите или создайте новый.</p>}
        {sel && (
          <Card
            title={<span className="font-mono text-sm">{sel}{dirty && <span className="ml-1.5 text-warn">●</span>}</span>}
            head={
              <div className="flex gap-1.5">
                <Button mini onClick={download} title="Скачать файл">⤓ Скачать</Button>
                {!cur?.protected && <Button mini variant="danger" onClick={del}>Удалить</Button>}
              </div>
            }
          >
            {cur?.gz && <p className="mb-2 text-xs text-muted">Файл хранится сжатым (.gz). Показан распакованным; при сохранении запишется как обычный текст.</p>}
            {sel === "auto.list" && <p className="mb-2 text-xs text-warn">Обновляется автоподбором — ваши правки движок может перезаписать.</p>}
            {kind === "lua" && <p className="mb-2 text-xs text-warn">Это логика обхода DPI. Ошибка в скрипте может остановить nfqws2 — правьте осторожно.</p>}
            {tooBig && <p className="mb-2 text-xs text-warn">Большой файл ({human(content.length)}) — редактирование может тормозить.</p>}
            <Textarea rows={22} value={content} spellCheck={false} onChange={(e) => setBody(e.target.value)} />
            <div className="mt-2.5 flex flex-wrap items-center gap-2">
              <Button variant="primary" onClick={save} disabled={busy || !dirty}>{busy ? "Сохранение…" : "Сохранить"}</Button>
              {kind === "list" && <Button onClick={dedup} title="Удалить повторяющиеся строки">Дедуп</Button>}
              {kind === "list" && <Button variant="ghost" onClick={clear}>Очистить</Button>}
              {!dirty && <span className="text-xs text-muted">сохранено</span>}
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}

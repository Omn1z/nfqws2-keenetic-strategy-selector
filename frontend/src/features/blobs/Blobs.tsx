import { useState } from "react";
import { api, downloadFile, uploadForm } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Dropzone } from "@/components/ui/Dropzone";
import { EmptyRow, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";

export default function Blobs() {
  const { blobs, reloadBlobs } = useStore();
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [status, setStatus] = useState("");

  const all = [...blobs.custom.map((n) => ({ name: n, custom: true })), ...blobs.system.map((n) => ({ name: n, custom: false }))];
  const toggle = (n: string) => setSel((s) => { const x = new Set(s); if (x.has(n)) x.delete(n); else x.add(n); return x; });
  const toggleAll = () => setSel((s) => (s.size === all.length ? new Set() : new Set(all.map((b) => b.name))));
  const selCustom = () => [...sel].filter((n) => blobs.custom.includes(n));

  const upload = async (files: FileList) => {
    const arr = Array.from(files);
    if (!arr.length) return;
    const existing = new Set(blobs.custom.map((n) => n.toLowerCase()));
    const dups: string[] = [];
    const queue = arr.filter((f) => {
      if (/\.zip$/i.test(f.name)) return true;
      if (existing.has(f.name.toLowerCase())) { dups.push(f.name); return false; }
      return true;
    });
    if (dups.length) toast(`Пропущены дубликаты (${dups.length}): ${dups.join(", ")}`, "warn");
    if (!queue.length) { setStatus(`дубликаты пропущены: ${dups.length}`); return; }
    let ok = 0;
    for (const file of queue) {
      setStatus(`Загрузка: ${file.name}`);
      const zip = /\.zip$/i.test(file.name);
      const fd = new FormData();
      fd.append("file", file);
      try { const d = await uploadForm<{ imported?: number }>(zip ? "/api/blobs/zip" : "/api/blobs", fd); ok += zip ? (d.imported ?? 0) : 1; }
      catch (e) { toast(`${file.name}: ${(e as Error).message}`, "err"); }
    }
    setStatus(`✓ загружено: ${ok}${dups.length ? ` · пропущено дубликатов: ${dups.length}` : ""}`);
    if (ok) toast(`Блобы загружены: ${ok}`, "ok");
    await reloadBlobs();
    setSel(new Set());
  };
  const del = async (name: string) => {
    if (!confirm(`Удалить блоб «${name}»?`)) return;
    try { await api("DELETE", `/api/blobs/${encodeURIComponent(name)}`); toast("Блоб удалён", "ok"); await reloadBlobs(); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const exportSel = () => {
    const names = [...sel];
    if (!names.length) { toast("Выберите блобы для экспорта", "err"); return; }
    downloadFile("/api/blobs/export", "blobs.zip", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ names }) }).catch((e) => toast((e as Error).message, "err"));
  };
  const delSel = async () => {
    const names = selCustom();
    if (!names.length) { toast("Выберите пользовательские блобы", "err"); return; }
    if (!confirm(`Удалить выбранные блобы (${names.length})?`)) return;
    for (const n of names) { try { await api("DELETE", `/api/blobs/${encodeURIComponent(n)}`); } catch (e) { toast(`${n}: ${(e as Error).message}`, "err"); } }
    toast(`Удалено: ${names.length}`, "ok");
    await reloadBlobs();
    setSel(new Set());
  };

  const cb = "h-4 w-4 accent-[var(--c-accent)]";
  return (
    <>
      <Card title="Загрузка блобов">
        <p className="mb-3 text-xs text-muted">Свой блоб используется в стратегии так: <code>--blob=имя:@/путь</code>. Можно загрузить несколько файлов сразу или ZIP-архив.</p>
        <Dropzone multiple onFiles={upload}>
          <svg className="mx-auto mb-2 text-accent" viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 16V4m0 0 4 4m-4-4L8 8M5 16v2a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-2" /></svg>
          <div className="text-[13.5px]"><b className="text-ink">Перетащите файлы или ZIP</b> или нажмите, чтобы выбрать</div>
          <div className="mt-1.5 min-h-[16px] text-[12.5px] font-semibold text-accent-d">{status}</div>
        </Dropzone>
      </Card>
      <Card
        title="Список блобов"
        head={<div className="flex gap-2"><Button mini onClick={exportSel}>Экспорт выбранных (ZIP)</Button>{selCustom().length > 0 && <Button mini variant="danger" onClick={delSel}>Удалить выбранные</Button>}</div>}
      >
        <TableWrap>
          <table className={tableCls}>
            <thead><tr><th className={cn(thBase, "w-8")}><input type="checkbox" className={cb} checked={all.length > 0 && sel.size === all.length} onChange={toggleAll} /></th><th className={thBase}>Имя</th><th className={thBase}>Тип</th><th className={thBase} /></tr></thead>
            <tbody>
              {all.length === 0 && <EmptyRow colSpan={4}>Нет блобов.</EmptyRow>}
              {all.map((b) => (
                <tr key={b.name} className="hover:bg-line-soft">
                  <td className={tdCls}><input type="checkbox" className={cb} checked={sel.has(b.name)} onChange={() => toggle(b.name)} /></td>
                  <td className={cn(tdCls, "font-mono")}>{b.name}</td>
                  <td className={tdCls}>{b.custom ? "свой" : "системный"}</td>
                  <td className={tdCls}>{b.custom && <Button mini variant="danger" onClick={() => del(b.name)}>×</Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Card>
    </>
  );
}

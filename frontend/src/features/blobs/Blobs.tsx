import { useEffect, useState } from "react";
import { api, downloadFile, uploadForm } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import { Dropzone } from "@/components/ui/Dropzone";
import { Field, Input, Select } from "@/components/ui/form";
import { EmptyRow, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import type { BlobCapture, BlobCaptureStart, ClientHelloCandidate, Device, InstallResult } from "@/types/api";

const blobName = (sni: string, fallback = "site") => `clienthello_${(sni || fallback).replace(/[^\w.-]+/g, "_")}.bin`;

const ALPN_OPTS = [
  { v: "h2,http/1.1", l: "h2 + http/1.1" },
  { v: "h2", l: "только h2" },
  { v: "http/1.1", l: "только http/1.1" },
  { v: "", l: "без ALPN" },
];
const VER_OPTS = [
  { v: "0", l: "авто (1.2–1.3)" },
  { v: "771", l: "TLS 1.2" },
  { v: "772", l: "TLS 1.3" },
];

// One captured ClientHello: shows its SNI/destination and saves it under an editable name.
function CandidateRow({ c, index, onSave }: { c: ClientHelloCandidate; index: number; onSave: (i: number, name: string) => void }) {
  const [name, setName] = useState(blobName(c.sni, c.dst_ip));
  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-line-soft py-2 first:border-t-0">
      <span className="font-mono text-[13px] font-semibold">{c.sni || "(без SNI)"}</span>
      <span className="text-xs text-muted">→ {c.dst_ip}:{c.dst_port} · {c.size} Б</span>
      <Input className="ml-auto w-56" value={name} onChange={(e) => setName(e.target.value)} />
      <Button mini onClick={() => onSave(index, name)}>Сохранить</Button>
    </div>
  );
}

export default function Blobs() {
  const { blobs, reloadBlobs } = useStore();
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [status, setStatus] = useState("");

  const [mode, setMode] = useState<"capture" | "generate">("capture");
  const [genSni, setGenSni] = useState("");
  const [genAlpn, setGenAlpn] = useState(ALPN_OPTS[0].v);
  const [genVer, setGenVer] = useState(VER_OPTS[0].v);
  const [genName, setGenName] = useState("");
  const [generating, setGenerating] = useState(false);

  const [devices, setDevices] = useState<Device[]>([]);
  const [capIP, setCapIP] = useState("");
  const [capSecs, setCapSecs] = useState(20);
  const [cap, setCap] = useState<BlobCapture | null>(null);
  const [capturing, setCapturing] = useState(false);
  const [installShow, setInstallShow] = useState(false);
  const [installing, setInstalling] = useState(false);

  usePoll(async () => {
    try { const v = await api<{ devices: Device[] }>("GET", "/api/devices"); setDevices(v.devices ?? []); } catch { /* ignore */ }
  }, 15000);
  useEffect(() => { if (!capIP && devices.length) setCapIP(devices[0].ip); }, [capIP, devices]);

  usePoll(async () => {
    if (!cap) return;
    try {
      const c = await api<BlobCapture>("GET", `/api/blobcap/${cap.id}`);
      setCap(c);
      if (c.status !== "running") {
        setCapturing(false);
        const n = (c.candidates ?? []).length;
        toast(c.status === "error" ? `Захват: ${c.error}` : `Поймано ClientHello: ${n}`, c.status === "error" ? "err" : n ? "ok" : "warn");
      }
    } catch (e) { setCapturing(false); toast((e as Error).message, "err"); }
  }, 1000, capturing);

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

  // Delete is reversible (moves to the trash), so no confirm — restore from «Корзина».
  const del = async (name: string) => {
    try { await api("DELETE", `/api/blobs/${encodeURIComponent(name)}`); toast(`«${name}» в корзине`, "ok"); await reloadBlobs(); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const delSel = async () => {
    const names = selCustom();
    if (!names.length) { toast("Выберите пользовательские блобы", "err"); return; }
    for (const n of names) { try { await api("DELETE", `/api/blobs/${encodeURIComponent(n)}`); } catch (e) { toast(`${n}: ${(e as Error).message}`, "err"); } }
    toast(`В корзину: ${names.length}`, "ok");
    await reloadBlobs();
    setSel(new Set());
  };
  const exportSel = () => {
    const names = [...sel];
    if (!names.length) { toast("Выберите блобы для экспорта", "err"); return; }
    downloadFile("/api/blobs/export", "blobs.zip", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ names }) }).catch((e) => toast((e as Error).message, "err"));
  };

  const restore = async (name: string) => {
    try { await api("POST", `/api/blobs/${encodeURIComponent(name)}/restore`); toast(`«${name}» восстановлен`, "ok"); await reloadBlobs(); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const purge = async (name: string) => {
    if (!confirm(`Удалить «${name}» навсегда? Это действие необратимо.`)) return;
    try { await api("DELETE", `/api/blobs/trash/${encodeURIComponent(name)}`); toast("Удалено навсегда", "ok"); await reloadBlobs(); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const emptyTrash = async () => {
    if (!confirm(`Очистить корзину (${blobs.trash.length})? Это действие необратимо.`)) return;
    try { await api("POST", "/api/blobs/trash/empty"); toast("Корзина очищена", "ok"); await reloadBlobs(); }
    catch (e) { toast((e as Error).message, "err"); }
  };

  const doGenerate = async () => {
    const sni = genSni.trim();
    if (!sni) { toast("Укажите домен (SNI)", "err"); return; }
    const name = genName.trim() || blobName(sni);
    setGenerating(true);
    try {
      await api("POST", "/api/blobs/generate", { sni, alpn: genAlpn ? genAlpn.split(",") : [], min_version: Number(genVer), name });
      toast(`Блоб «${name}» создан`, "ok");
      setGenSni(""); setGenName("");
      await reloadBlobs();
    } catch (e) { toast((e as Error).message, "err"); }
    finally { setGenerating(false); }
  };

  const beginCapture = async (ip: string) => {
    if (!ip) { toast("Выберите устройство", "err"); return; }
    try {
      const r = await api<BlobCaptureStart>("POST", `/api/devices/${encodeURIComponent(ip)}/blobcap`, { seconds: capSecs });
      if ("need_install" in r) { setInstallShow(true); return; }
      setCap(r); setCapturing(true); toast(`Захват ClientHello на ${ip} (${r.seconds} с)`, "ok");
    } catch (e) { toast((e as Error).message, "err"); }
  };
  const confirmInstall = async () => {
    setInstalling(true);
    try {
      const r = await api<InstallResult>("POST", "/api/system/install", { package: "tcpdump" });
      if (!r.ok) { toast(`Не удалось установить tcpdump: ${r.error ?? ""}`, "err"); return; }
      toast("tcpdump установлен", "ok"); setInstallShow(false); await beginCapture(capIP);
    } catch (e) { toast((e as Error).message, "err"); }
    finally { setInstalling(false); }
  };
  const saveCandidate = async (index: number, name: string) => {
    if (!cap) return;
    const nm = name.trim();
    if (!nm) { toast("Укажите имя блоба", "err"); return; }
    try { await api("POST", `/api/blobcap/${cap.id}/save`, { index, name: nm }); toast(`Блоб «${nm}» сохранён`, "ok"); await reloadBlobs(); }
    catch (e) { toast((e as Error).message, "err"); }
  };

  const cb = "h-4 w-4 accent-[var(--c-accent)]";
  const seg = (m: "capture" | "generate", label: string) => (
    <button onClick={() => setMode(m)} className={cn("rounded-md px-3 py-1.5 text-[13px] font-semibold transition", mode === m ? "bg-accent text-white" : "text-ink-soft hover:bg-line-soft")}>{label}</button>
  );

  return (
    <>
      <Card title="Создать блоб" sub="TLS ClientHello">
        <p className="mb-3 text-xs text-muted">
          Блоб — это сырой <code>ClientHello</code>, который движок подставляет как фейковый пакет. Снимите настоящий с трафика устройства или сгенерируйте по домену.
        </p>
        <div className="mb-3 inline-flex rounded-lg border border-line p-0.5">{seg("capture", "Снять с трафика")}{seg("generate", "Сгенерировать")}</div>

        {mode === "capture" ? (
          <>
            <div className="flex flex-wrap items-end gap-3">
              <Field label="Устройство" className="min-w-[200px] flex-1">
                <Select value={capIP} onChange={(e) => setCapIP(e.target.value)}>
                  {!devices.length && <option value="">нет устройств</option>}
                  {devices.map((d) => <option key={d.ip} value={d.ip}>{d.ip}{d.mac ? ` · ${d.mac}` : ""}</option>)}
                </Select>
              </Field>
              <Field label="Длительность" className="w-36">
                <Select value={String(capSecs)} onChange={(e) => setCapSecs(Number(e.target.value))}>
                  <option value="10">10 секунд</option>
                  <option value="20">20 секунд</option>
                  <option value="30">30 секунд</option>
                </Select>
              </Field>
              <Button onClick={() => beginCapture(capIP)} disabled={capturing || installing}>{capturing ? "Захват…" : "Начать захват"}</Button>
            </div>
            <p className="mt-2 text-xs text-muted">Запустите захват и откройте нужный сайт на выбранном устройстве — поймаем его ClientHello.</p>
            {cap && (
              <div className="mt-3 rounded-lg border border-line bg-input p-3">
                <div className="mb-2 flex flex-wrap items-center gap-3 text-xs text-ink-soft">
                  <span className="font-mono">{cap.ip} · {cap.iface}</span>
                  <span>{capturing ? "идёт захват…" : cap.status === "error" ? `ошибка: ${cap.error}` : `готово · ${(cap.elapsed_ms / 1000).toFixed(1)} с`}</span>
                  <Button mini variant="ghost" className="ml-auto" onClick={() => { setCap(null); setCapturing(false); }}>Закрыть</Button>
                </div>
                {capturing && (
                  <div className="mb-2 h-2 overflow-hidden rounded-full bg-line">
                    <div className="h-full rounded-full bg-gradient-to-r from-accent to-[#5cb3ff] transition-[width]" style={{ width: `${Math.min(100, (Date.now() / 1000 - cap.started_at) / cap.seconds * 100)}%` }} />
                  </div>
                )}
                {!capturing && cap.status === "done" && (cap.candidates ?? []).length === 0 && (
                  <p className="text-xs text-muted">Ничего не поймано. Откройте нужный сайт на устройстве и повторите захват.</p>
                )}
                {(cap.candidates ?? []).map((c, i) => <CandidateRow key={i} c={c} index={i} onSave={saveCandidate} />)}
              </div>
            )}
          </>
        ) : (
          <div className="flex flex-wrap items-end gap-3">
            <Field label="Домен (SNI)" className="min-w-[200px] flex-1"><Input value={genSni} onChange={(e) => setGenSni(e.target.value)} placeholder="www.google.com" /></Field>
            <Field label="ALPN" className="w-44"><Select value={genAlpn} onChange={(e) => setGenAlpn(e.target.value)}>{ALPN_OPTS.map((o) => <option key={o.v} value={o.v}>{o.l}</option>)}</Select></Field>
            <Field label="Версия TLS" className="w-40"><Select value={genVer} onChange={(e) => setGenVer(e.target.value)}>{VER_OPTS.map((o) => <option key={o.v} value={o.v}>{o.l}</option>)}</Select></Field>
            <Field label="Имя блоба" className="min-w-[180px] flex-1"><Input value={genName} onChange={(e) => setGenName(e.target.value)} placeholder={blobName(genSni)} /></Field>
            <Button onClick={doGenerate} disabled={generating}>{generating ? "Создание…" : "Создать"}</Button>
          </div>
        )}
      </Card>

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
        head={<div className="flex gap-2"><Button mini onClick={exportSel}>Экспорт выбранных (ZIP)</Button>{selCustom().length > 0 && <Button mini variant="danger" onClick={delSel}>В корзину</Button>}</div>}
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

      {blobs.trash.length > 0 && (
        <Card title="Корзина" sub={`${blobs.trash.length}`} head={<Button mini variant="danger" onClick={emptyTrash}>Очистить корзину</Button>}>
          <p className="mb-3 text-xs text-muted">Удалённые блобы хранятся здесь — можно восстановить или удалить навсегда.</p>
          <TableWrap>
            <table className={tableCls}>
              <thead><tr><th className={thBase}>Имя</th><th className={cn(thBase, "w-44 text-right")} /></tr></thead>
              <tbody>
                {blobs.trash.map((n) => (
                  <tr key={n} className="hover:bg-line-soft">
                    <td className={cn(tdCls, "font-mono")}>{n}</td>
                    <td className={cn(tdCls, "text-right")}>
                      <div className="flex justify-end gap-2">
                        <Button mini onClick={() => restore(n)}>Восстановить</Button>
                        <Button mini variant="danger" onClick={() => purge(n)}>Удалить навсегда</Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        </Card>
      )}

      {installShow && (
        <Modal
          title="Нужен пакет tcpdump"
          onClose={() => { if (!installing) setInstallShow(false); }}
          actions={
            <>
              <Button variant="ghost" onClick={() => setInstallShow(false)} disabled={installing}>Отмена</Button>
              <Button variant="primary" onClick={confirmInstall} disabled={installing}>{installing ? "Установка…" : "Установить"}</Button>
            </>
          }
        >
          <p>Снять ClientHello с трафика можно через <b>tcpdump</b> — на роутере он не установлен. Поставить его через <code>opkg</code> (~1–2 МБ в <code>/opt</code>)?</p>
          <p className="mt-2 text-muted">Установка единоразовая. После неё захват запустится автоматически.</p>
        </Modal>
      )}
    </>
  );
}

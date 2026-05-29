import { useEffect, useRef, useState } from "react";
import type { ChangeEvent } from "react";
import { api, exportStrategy, uploadForm } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Field, Input, Textarea } from "@/components/ui/form";
import { Args, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import type { Strategy } from "@/types/api";

const EMPTY = { id: "", name: "", l7: "tls", args: "" };

export default function Strategies() {
  const { strategies, reloadStrategies, reloadBlobs } = useStore();
  const [form, setForm] = useState(EMPTY);
  const fileRef = useRef<HTMLInputElement>(null);

  const [sni, setSni] = useState("");
  const [sniSaving, setSniSaving] = useState(false);
  useEffect(() => { void (async () => { try { const d = await api<{ domains: string[] }>("GET", "/api/strategies/sni"); setSni((d.domains ?? []).join("\n")); } catch { /* non-fatal */ } })(); }, []);
  const saveSni = async () => {
    setSniSaving(true);
    try {
      const d = await api<{ domains: string[] }>("POST", "/api/strategies/sni", { domains: sni.split("\n").map((s) => s.trim()).filter(Boolean) });
      setSni((d.domains ?? []).join("\n"));
      toast(`SNI-доменов для перебора: ${(d.domains ?? []).length}`, "ok");
    } catch (e) { toast((e as Error).message, "err"); }
    finally { setSniSaving(false); }
  };

  const save = async () => {
    if (!form.args.trim()) { toast("Пустые аргументы", "err"); return; }
    try {
      await api("POST", "/api/strategies", { ...form, name: form.name.trim(), l7: form.l7.trim(), args: form.args.trim(), source: "custom" });
      setForm(EMPTY); await reloadStrategies(); toast("Стратегия сохранена", "ok");
    } catch (e) { toast((e as Error).message, "err"); }
  };
  const del = async (id: string) => {
    if (!(await confirmDialog({ title: "Удалить стратегию?", confirmLabel: "Удалить", danger: true }))) return;
    try { await api("DELETE", `/api/strategies/${id}`); await reloadStrategies(); } catch (e) { toast((e as Error).message, "err"); }
  };
  const onImport = async (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]; if (!f) return;
    const fd = new FormData(); fd.append("file", f);
    try { const d = await uploadForm<Strategy>("/api/strategies/import", fd); await reloadStrategies(); await reloadBlobs(); toast(`Импортирована стратегия: ${d.name || d.id}`, "ok"); }
    catch (err) { toast((err as Error).message, "err"); }
    e.target.value = "";
  };

  return (
    <>
      <Card
        title="Каталог стратегий"
        head={<><Button mini onClick={() => fileRef.current?.click()}>Импорт стратегии (ZIP)</Button><input ref={fileRef} type="file" accept=".zip" hidden onChange={onImport} /></>}
      >
        <TableWrap scrollable>
          <table className={tableCls}>
            <thead><tr><th className={thBase}>ID</th><th className={thBase}>Название</th><th className={thBase}>L7</th><th className={thBase}>Args</th><th className={thBase}>Источник</th><th className={thBase} /></tr></thead>
            <tbody>
              {strategies.map((s) => {
                const custom = s.source === "custom";
                return (
                  <tr key={s.id} className="hover:bg-line-soft">
                    <td className={cn(tdCls, "font-mono")}>{s.id}</td>
                    <td className={tdCls}>{s.name}</td>
                    <td className={tdCls}>{s.l7}</td>
                    <td className={tdCls}><Args>{s.args}</Args></td>
                    <td className={tdCls}>{s.source}</td>
                    <td className={tdCls}>
                      <div className="flex flex-wrap gap-1.5">
                        <Button mini title="Экспорт (ZIP)" onClick={() => exportStrategy(s.name || s.id, s.l7 || "", s.args).catch((e) => toast((e as Error).message, "err"))}>⤓</Button>
                        {custom && (
                          <>
                            <Button mini onClick={() => setForm({ id: s.id, name: s.name || "", l7: s.l7 || "tls", args: s.args || "" })}>Изм.</Button>
                            <Button mini variant="danger" title="Удалить" aria-label="Удалить стратегию" onClick={() => del(s.id)}>×</Button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      </Card>
      <Card title="SNI-перебор" sub="для стратегий c sni=">
        <p className="mb-2 text-xs text-muted">
          Домены по одному в строке. В прогоне каждая стратегия с <code>sni=</code> (фейк‑hello) перебирается по этим доменам — каждый отдельным проходом, затем её собственный SNI. Пусто = только встроенные SNI.
        </p>
        <Textarea rows={4} value={sni} onChange={(e) => setSni(e.target.value)} placeholder={"www.google.com\nfonts.google.com\ndzen.ru"} />
        <div className="mt-2"><Button variant="primary" onClick={saveSni} disabled={sniSaving}>{sniSaving ? "Сохранение…" : "Сохранить SNI"}</Button></div>
      </Card>

      <Card title={form.id ? "Редактировать стратегию" : "Добавить свою стратегию"}>
        <div className="flex flex-wrap gap-4">
          <Field label="Название" className="min-w-[200px] flex-1"><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <Field label="L7" className="w-28 shrink-0"><Input value={form.l7} onChange={(e) => setForm({ ...form, l7: e.target.value })} /></Field>
        </div>
        <Field label="Args" hint="строка аргументов nfqws2 без --new">
          <Textarea rows={3} value={form.args} placeholder="--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=..." onChange={(e) => setForm({ ...form, args: e.target.value })} />
        </Field>
        <div className="mt-2 flex gap-2.5"><Button variant="primary" onClick={save}>Сохранить</Button><Button variant="ghost" onClick={() => setForm(EMPTY)}>Очистить</Button></div>
      </Card>
    </>
  );
}

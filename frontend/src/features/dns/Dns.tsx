import { useState } from "react";
import { api } from "@/lib/api";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DnsBadge } from "@/components/ui/Badge";
import { Field, Input, Select } from "@/components/ui/form";
import { Args, EmptyRow, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import type { DnsType } from "@/types/api";

export default function Dns() {
  const { dns, reloadDns } = useStore();
  const [name, setName] = useState("");
  const [type, setType] = useState<DnsType>("doh");
  const [addr, setAddr] = useState("");

  const save = async () => {
    if (!name.trim() || !addr.trim()) { toast("Заполните название и адрес", "err"); return; }
    try { await api("POST", "/api/dns", { name: name.trim(), type, addr: addr.trim() }); setName(""); setAddr(""); await reloadDns(); toast("DNS добавлен", "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const del = async (id: string, nm: string) => {
    if (!confirm(`Удалить DNS «${nm || id}»?`)) return;
    try { await api("DELETE", `/api/dns/${encodeURIComponent(id)}`); await reloadDns(); toast("DNS удалён", "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
  };
  const reset = async () => {
    if (!confirm("Сбросить список DNS к стандартным? Добавленные вами записи будут удалены.")) return;
    try { await api("POST", "/api/dns/reset"); await reloadDns(); toast("Список DNS сброшен", "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
  };

  return (
    <>
      <Card title="DNS-серверы (DoH / DoT)" head={<Button mini onClick={reset}>Сбросить к стандартным</Button>}>
        <p className="mb-3 text-xs text-muted">Шифрованные DNS для прогонов. <b>DoH</b> — ссылка <code>https://…/dns-query</code>; <b>DoT</b> — <code>host</code> или <code>host:порт</code> (по умолчанию 853).</p>
        <TableWrap>
          <table className={tableCls}>
            <thead><tr><th className={thBase}>Название</th><th className={thBase}>Тип</th><th className={thBase}>Адрес</th><th className={thBase} /></tr></thead>
            <tbody>
              {dns.length === 0 && <EmptyRow colSpan={4}>Список пуст — добавьте DNS ниже или сбросьте к стандартным.</EmptyRow>}
              {dns.map((d) => (
                <tr key={d.id} className="hover:bg-line-soft">
                  <td className={tdCls}>{d.name || d.id}</td>
                  <td className={tdCls}><DnsBadge name={d.type.toUpperCase()} id={d.id} /></td>
                  <td className={tdCls}><Args>{d.addr}</Args></td>
                  <td className={tdCls}><Button mini variant="danger" onClick={() => del(d.id, d.name)}>×</Button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Card>
      <Card title="Добавить DNS">
        <div className="flex flex-wrap items-end gap-4">
          <Field label="Название" className="min-w-[180px] flex-1"><Input value={name} placeholder="Мой DNS" onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Тип" className="w-28 shrink-0"><Select value={type} onChange={(e) => setType(e.target.value as DnsType)}><option value="doh">DoH</option><option value="dot">DoT</option></Select></Field>
          <Field label="Адрес" className="min-w-[220px] flex-[2]"><Input value={addr} placeholder="https://dns.example/dns-query · dns.example[:853]" onChange={(e) => setAddr(e.target.value)} /></Field>
        </div>
        <div className="mt-2"><Button variant="primary" onClick={save}>Добавить</Button></div>
      </Card>
    </>
  );
}

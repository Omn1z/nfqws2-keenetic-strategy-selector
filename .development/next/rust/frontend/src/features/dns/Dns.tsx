import { useRef, useState } from "react";
import { api } from "@/lib/api";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Field, Input, Select } from "@/components/ui/form";
import { PageHeader, compactCard } from "@/components/ui/FeaturePage";
import type { DnsType } from "@/types/api";
import { DnsCatalog, DnsSummary, visibleDnsServers } from "./presentation";

export default function Dns() {
  const { dns, reloadDns } = useStore();
  const [name, setName] = useState("");
  const [type, setType] = useState<DnsType>("doh");
  const [addr, setAddr] = useState("");
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState<"" | DnsType>("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const pending = useRef(false);

  const perform = async (key: string, operation: () => Promise<void>) => {
    if (pending.current) return;
    pending.current = true; setBusy(key); setError("");
    try { await operation(); }
    catch (cause) { const message = (cause as Error).message; setError(message); toast(message, "err"); }
    finally { pending.current = false; setBusy(null); }
  };
  const save = async () => {
    if (!name.trim() || !addr.trim()) { setError("Заполните название и адрес"); toast("Заполните название и адрес", "err"); return; }
    await perform("save", async () => {
      await api("POST", "/api/dns", { name: name.trim(), type, addr: addr.trim() });
      setName(""); setAddr(""); await reloadDns(); toast("DNS добавлен", "ok");
    });
  };
  const del = async (id: string, nm: string) => perform(`delete:${id}`, async () => {
    if (!(await confirmDialog({ title: `Удалить DNS «${nm || id}»?`, confirmLabel: "Удалить", danger: true }))) return;
    await api("DELETE", `/api/dns/${encodeURIComponent(id)}`); await reloadDns(); toast("DNS удалён", "ok");
  });
  const reset = async () => perform("reset", async () => {
    if (!(await confirmDialog({ title: "Сбросить список DNS к стандартным?", body: "Добавленные вами записи будут удалены.", confirmLabel: "Сбросить", danger: true }))) return;
    await api("POST", "/api/dns/reset"); await reloadDns(); toast("Список DNS сброшен", "ok");
  });
  const visible = visibleDnsServers(dns, query, protocol);
  const filtered = !!(query.trim() || protocol);

  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="DNS-серверы для прогонов" description="Каталог шифрованных резолверов DoH и DoT для тестирования стратегий." actions={<Button onClick={reset} disabled={busy !== null}>{busy === "reset" ? "Сброс…" : "Сбросить к стандартным"}</Button>} />
    <DnsSummary servers={dns} />
    {error && <p role="alert" className="rounded-lg border border-line bg-bad-bg p-3 text-xs text-bad [overflow-wrap:anywhere]">{error}</p>}
    <Card title="Добавить собственный DNS" sub="Новая запись в каталоге" className={compactCard}>
      <fieldset disabled={busy !== null} className="grid items-end gap-3 sm:grid-cols-[minmax(0,1fr)_110px] xl:grid-cols-[minmax(150px,1fr)_110px_minmax(220px,2fr)_auto]">
        <Field label="Название"><Input value={name} placeholder="Мой DNS" onChange={event => setName(event.target.value)} /></Field>
        <Field label="Тип"><Select value={type} onChange={event => setType(event.target.value as DnsType)}><option value="doh">DoH</option><option value="dot">DoT</option></Select></Field>
        <Field label="Адрес / Endpoint" className="sm:col-span-2 xl:col-span-1"><Input value={addr} placeholder={type === "doh" ? "https://dns.example/dns-query" : "dns.example[:853]"} onChange={event => setAddr(event.target.value)} /></Field>
        <Button variant="primary" onClick={save}>{busy === "save" ? "Добавление…" : "Добавить"}</Button>
      </fieldset>
      <p className="mt-3 text-xs leading-relaxed text-muted"><b>DoH</b> — полный URL <code>https://…/dns-query</code>. <b>DoT</b> — <code>host</code> или <code>host:порт</code>, по умолчанию 853.</p>
    </Card>
    <Card title="Каталог DNS-серверов" sub={`${visible.length} из ${dns.length}`} className={compactCard}>
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <Field label="Поиск" className="min-w-0 flex-1 basis-56"><Input aria-label="Поиск DNS-серверов" value={query} placeholder="Название, ID или адрес…" onChange={event => setQuery(event.target.value)} /></Field>
        <Field label="Протокол" className="w-full sm:w-44"><Select aria-label="Фильтр DNS по протоколу" value={protocol} onChange={event => setProtocol(event.target.value as "" | DnsType)}><option value="">Все протоколы</option><option value="doh">DoH</option><option value="dot">DoT</option></Select></Field>
        {filtered && <Button variant="ghost" onClick={() => { setQuery(""); setProtocol(""); }}>Сбросить фильтры</Button>}
      </div>
      <DnsCatalog servers={visible} busy={busy} filtered={filtered} onDelete={(id, nm) => { void del(id, nm); }} />
    </Card>
  </div>;
}

import { useEffect, useRef, useState } from "react";
import type { ChangeEvent } from "react";
import { api, exportStrategy, uploadForm } from "@/lib/api";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { PageHeader, StatsStrip, compactCard } from "@/components/ui/FeaturePage";
import type { Strategy } from "@/types/api";
import { filterStrategies, StrategyCatalog, strategyL7Options } from "./StrategyCatalog";

const EMPTY = { id: "", name: "", l7: "tls", args: "" };

export default function Strategies() {
  const { strategies, reloadStrategies, reloadBlobs } = useStore();
  const [form, setForm] = useState(EMPTY);
  const [search, setSearch] = useState("");
  const [l7, setL7] = useState("");
  const [source, setSource] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const pending = useRef<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const editorRef = useRef<HTMLDivElement>(null);
  const [sni, setSni] = useState("");
  const [sniLoading, setSniLoading] = useState(true);
  const [sniSaving, setSniSaving] = useState(false);
  const [sniError, setSniError] = useState("");
  const sniPending = useRef(false);

  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const data = await api<{ domains: string[] }>("GET", "/api/strategies/sni");
        if (active) setSni((data.domains ?? []).join("\n"));
      } catch (cause) {
        if (active) setSniError(`Не удалось загрузить SNI: ${(cause as Error).message}`);
      } finally {
        if (active) setSniLoading(false);
      }
    })();
    return () => { active = false; };
  }, []);

  const perform = async (key: string, operation: () => Promise<void>) => {
    if (pending.current) return;
    pending.current = key; setBusy(key); setError("");
    try { await operation(); }
    catch (cause) { const message = (cause as Error).message; setError(message); toast(message, "err"); }
    finally { pending.current = null; setBusy(null); }
  };

  const saveSni = async () => {
    if (sniLoading || sniPending.current) return;
    sniPending.current = true; setSniSaving(true); setSniError("");
    try {
      const data = await api<{ domains: string[] }>("POST", "/api/strategies/sni", { domains: sni.split("\n").map(value => value.trim()).filter(Boolean) });
      setSni((data.domains ?? []).join("\n"));
      toast(`SNI-доменов для перебора: ${(data.domains ?? []).length}`, "ok");
    } catch (cause) { const message = (cause as Error).message; setSniError(message); toast(message, "err"); }
    finally { sniPending.current = false; setSniSaving(false); }
  };

  const save = async () => {
    if (!form.args.trim()) { setError("Пустые аргументы"); toast("Пустые аргументы", "err"); return; }
    await perform("save", async () => {
      await api("POST", "/api/strategies", { ...form, name: form.name.trim(), l7: form.l7.trim(), args: form.args.trim(), source: "custom" });
      setForm(EMPTY); await reloadStrategies(); toast("Стратегия сохранена", "ok");
    });
  };
  const del = async (id: string) => perform(`delete:${id}`, async () => {
    if (!(await confirmDialog({ title: "Удалить стратегию?", confirmLabel: "Удалить", danger: true }))) return;
    await api("DELETE", `/api/strategies/${id}`); await reloadStrategies();
  });
  const onImport = async (event: ChangeEvent<HTMLInputElement>) => {
    const input = event.currentTarget;
    const file = input.files?.[0]; if (!file) return;
    const data = new FormData(); data.append("file", file);
    await perform("import", async () => {
      const strategy = await uploadForm<Strategy>("/api/strategies/import", data);
      await reloadStrategies(); await reloadBlobs(); toast(`Импортирована стратегия: ${strategy.name || strategy.id}`, "ok");
    });
    input.value = "";
  };
  const openEditor = (strategy?: Strategy) => {
    if (pending.current) return;
    setForm(strategy ? { id: strategy.id, name: strategy.name || "", l7: strategy.l7 || "tls", args: strategy.args || "" } : EMPTY);
    editorRef.current?.scrollIntoView({ block: "start" });
    editorRef.current?.querySelector<HTMLInputElement>("input")?.focus({ preventScroll: true });
  };

  const protocols = strategyL7Options(strategies);
  const protocolChoices = [...new Set([...protocols, l7].filter(Boolean))].sort();
  const sources = [...new Set([...strategies.map(strategy => strategy.source), source].filter(Boolean))].sort();
  const visible = filterStrategies(strategies, { search, l7, source });
  const filtered = !!(search.trim() || l7 || source);
  const builtin = strategies.filter(strategy => strategy.source === "builtin").length;
  const custom = strategies.filter(strategy => strategy.source === "custom").length;
  const disabled = busy !== null;

  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="Стратегии обхода" description="Встроенные и свои цепочки аргументов nfqws2 для прогонов." actions={<>
      <Button onClick={() => fileRef.current?.click()} disabled={disabled}>{busy === "import" ? "Импорт…" : "Импорт ZIP"}</Button>
      <Button variant="primary" onClick={() => openEditor()} disabled={disabled}>Добавить стратегию</Button>
    </>} />
    <input ref={fileRef} type="file" accept=".zip" hidden onChange={onImport} disabled={disabled} aria-label="Импорт стратегии из ZIP" />
    <StatsStrip label="Состав каталога стратегий" items={[
      { label: "Всего стратегий", value: strategies.length, hint: "доступны для прогонов" },
      { label: "Встроенные", value: builtin, hint: "builtin" },
      { label: "Свои", value: custom, hint: "custom" },
      { label: "Фильтры L7", value: protocols.length, hint: protocols.length ? protocols.map(value => value.toUpperCase()).join(" · ") : "нет значений" },
    ]} />
    {error && <p role="alert" className="rounded-lg border border-line bg-bad-bg px-3 py-2 text-xs text-bad [overflow-wrap:anywhere]">{error}</p>}

    <Card title="Каталог стратегий" sub={`${visible.length} из ${strategies.length}`} className={compactCard}>
      <div className="mb-3 grid items-end gap-3 sm:grid-cols-2 xl:grid-cols-[minmax(0,1fr)_170px_170px_auto]">
        <Field label="Поиск" className="sm:col-span-2 xl:col-span-1"><Input aria-label="Поиск стратегий" value={search} onChange={event => setSearch(event.target.value)} placeholder="Название, ID или аргументы…" /></Field>
        <Field label="L7"><Select aria-label="Фильтр стратегий по L7" value={l7} onChange={event => setL7(event.target.value)}><option value="">Все протоколы</option>{protocolChoices.map(value => <option key={value} value={value}>{value.toUpperCase()}</option>)}</Select></Field>
        <Field label="Источник"><Select aria-label="Фильтр стратегий по источнику" value={source} onChange={event => setSource(event.target.value)}><option value="">Все источники</option>{sources.map(value => <option key={value} value={value}>{value === "builtin" ? "Встроенные" : value === "custom" ? "Свои" : value}</option>)}</Select></Field>
        {filtered && <Button variant="ghost" onClick={() => { setSearch(""); setL7(""); setSource(""); }}>Сбросить</Button>}
      </div>
      <StrategyCatalog strategies={visible} busy={busy} filtered={filtered} onExport={strategy => { void perform(`export:${strategy.id}`, () => exportStrategy(strategy.name || strategy.id, strategy.l7 || "", strategy.args)); }} onEdit={openEditor} onDelete={id => { void del(id); }} />
    </Card>

    <div className="grid min-w-0 items-start gap-4 xl:grid-cols-2">
      <Card title="SNI-перебор" sub="для стратегий с sni=" className={compactCard} head={<span className="text-[11px] text-muted">В редакторе: {sni.split("\n").filter(value => value.trim()).length}</span>}>
        <p className="mb-3 text-xs leading-relaxed text-ink-soft">В прогоне каждая стратегия с <code>sni=</code> (фейк-hello) перебирается по этим доменам — каждый отдельным проходом, затем её собственный SNI.</p>
        <Field label="Домены по одному в строке"><Textarea rows={5} value={sni} disabled={sniLoading || sniSaving} onChange={event => setSni(event.target.value)} placeholder={"www.google.com\nfonts.google.com\ndzen.ru"} /></Field>
        <p className="mt-2 text-[11px] text-muted">Пустой список — только встроенные SNI из стратегий.</p>
        {sniError && <p role="alert" className="mt-2 text-xs text-bad [overflow-wrap:anywhere]">{sniError}</p>}
        <div className="mt-3 border-t border-line-soft pt-3"><Button variant="primary" onClick={saveSni} disabled={sniLoading || sniSaving}>{sniLoading ? "Загрузка SNI…" : sniSaving ? "Сохранение…" : "Сохранить SNI"}</Button></div>
      </Card>

      <div ref={editorRef} className="min-w-0 scroll-mt-5">
        <Card title={form.id ? "Редактировать стратегию" : "Добавить свою стратегию"} head={<Badge>{form.id ? "Редактирование" : "Новая"}</Badge>} className={compactCard}>
          {form.id && <p className="mb-3 font-mono text-[11px] text-muted [overflow-wrap:anywhere]">ID: {form.id}</p>}
          <fieldset disabled={disabled} className="flex min-w-0 flex-col gap-3">
            <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_100px]">
              <Field label="Название"><Input value={form.name} onChange={event => setForm({ ...form, name: event.target.value })} placeholder="Например, fake + multisplit" /></Field>
              <Field label="L7"><Input value={form.l7} onChange={event => setForm({ ...form, l7: event.target.value })} placeholder="tls" /></Field>
            </div>
            <Field label="Аргументы" hint="nfqws2, без --new"><Textarea rows={5} value={form.args} placeholder="--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=..." onChange={event => setForm({ ...form, args: event.target.value })} /></Field>
            <div className="flex flex-wrap gap-2 border-t border-line-soft pt-3"><Button variant="primary" onClick={save}>{busy === "save" ? "Сохранение…" : "Сохранить"}</Button><Button variant="ghost" onClick={() => setForm(EMPTY)}>Очистить</Button></div>
          </fieldset>
        </Card>
      </div>
    </div>
  </div>;
}

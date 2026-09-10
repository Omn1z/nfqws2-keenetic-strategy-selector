import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Field, Input } from "@/components/ui/form";
import { Modal } from "@/components/ui/Modal";
import type { DnsServer, DnsServerUpstream } from "@/types/api";

export type UpstreamForm = { address: string; bootstrap: string };
export const upstreamForm = (v: DnsServerUpstream): UpstreamForm => ({ address: v.address, bootstrap: (v.bootstrap_ips ?? []).join(", ") });
export const collectUpstream = (v: UpstreamForm): DnsServerUpstream => ({ address: v.address.trim(), bootstrap_ips: v.bootstrap.split(/[\s,;]+/).filter(Boolean) });
const MAX_POOL = 8;
const addressKey = (v: string) => {
  try { return new URL(v.trim()).href; } catch { return v.trim(); }
};

function CatalogPicker({ current, onAdd, onClose }: { current: UpstreamForm[]; onAdd: (items: UpstreamForm[]) => void; onClose: () => void }) {
  const [catalog, setCatalog] = useState<DnsServer[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const occupied = useMemo(() => new Set(current.map((v) => addressKey(v.address))), [current]);
  const slots = MAX_POOL - current.filter((v) => v.address.trim() || v.bootstrap.trim()).length;
  const reload = async () => {
    setLoading(true); setError("");
    try {
      const values = await api<DnsServer[]>("GET", "/api/dns");
      const seen = new Set<string>();
      setCatalog(values.filter((v) => {
        const key = addressKey(v.addr);
        if (v.type !== "doh" || seen.has(key)) return false;
        seen.add(key); return true;
      }));
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { void reload(); }, []);
  const shown = catalog.filter((v) => `${v.name} ${v.addr}`.toLowerCase().includes(search.toLowerCase()));
  const add = () => {
    onAdd(catalog.filter((v) => selected.includes(v.id) && !occupied.has(addressKey(v.addr))).slice(0, slots).map((v) => ({ address: v.addr, bootstrap: "" })));
    onClose();
  };
  return <Modal title="Добавить DoH из списка DNS" onClose={onClose} size="lg" actions={<><Button onClick={onClose}>Отмена</Button><Button variant="primary" disabled={!selected.length} onClick={add}>Добавить выбранные · {selected.length}</Button></>}>
    <p className="mb-3 text-xs text-muted">Можно выбрать несколько серверов. В одном пуле — до {MAX_POOL} DoH. Список берётся из раздела «DNS».</p>
    <Field label="Поиск по названию или адресу"><Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Cloudflare, Google, Xbox…" /></Field>
    {loading && <p className="mt-3 text-xs text-muted">Загрузка списка…</p>}
    {error && <div role="alert" className="mt-3 text-xs text-bad"><p>{error}</p><Button mini className="mt-2" onClick={reload}>Повторить</Button></div>}
    {!loading && !error && <div className="mt-3 max-h-80 space-y-2 overflow-y-auto">
      {!shown.length && <p className="py-3 text-xs text-muted">Подходящих DoH нет. Добавьте адрес вручную или внесите сервер в раздел «DNS».</p>}
      {shown.map((v) => {
        const exists = occupied.has(addressKey(v.addr));
        const checked = selected.includes(v.id);
        return <label key={v.id} className="flex cursor-pointer items-start gap-3 rounded-lg border border-line p-3 text-xs">
          <input type="checkbox" className="mt-0.5 accent-accent" checked={exists || checked} disabled={exists || (!checked && selected.length >= slots)} onChange={(e) => setSelected((old) => e.target.checked ? [...old, v.id] : old.filter((id) => id !== v.id))} />
          <span className="min-w-0"><span className="font-semibold">{v.name || v.addr}</span>{exists && <span className="ml-2 text-muted">уже в пуле</span>}<code className="mt-1 block text-muted [overflow-wrap:anywhere]">{v.addr}</code></span>
        </label>;
      })}
    </div>}
    {selected.length >= slots && slots > 0 && <p className="mt-3 text-xs text-warn">Выбрано максимально допустимое число серверов для этого пула.</p>}
  </Modal>;
}

export function UpstreamPool({ value, onChange }: { value: UpstreamForm[]; onChange: (v: UpstreamForm[]) => void }) {
  const [picking, setPicking] = useState(false);
  const change = (index: number, patch: Partial<UpstreamForm>) => onChange(value.map((v, i) => i === index ? { ...v, ...patch } : v));
  const add = (items: UpstreamForm[]) => {
    const next = value.filter((v) => v.address.trim() || v.bootstrap.trim());
    const existing = new Set(next.map((v) => addressKey(v.address)));
    for (const item of items) {
      const key = addressKey(item.address);
      if (next.length >= MAX_POOL) break;
      if (!existing.has(key)) { existing.add(key); next.push(item); }
    }
    onChange(next.length ? next : [{ address: "", bootstrap: "" }]);
  };
  return <div className="min-w-0">
    <div className="space-y-3">
      {value.map((v, i) => <div key={i} className="rounded-lg border border-line p-3">
        <div className="mb-2 flex items-center justify-between gap-2"><span className="text-xs font-semibold text-ink-soft">DoH {i + 1}</span><Button mini variant="danger" disabled={value.length === 1} onClick={() => onChange(value.filter((_, n) => n !== i))} aria-label={`Удалить DoH ${i + 1}`}>Убрать</Button></div>
        <div className="grid min-w-0 gap-3 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          <Field label="Адрес DNS-over-HTTPS"><Input value={v.address} placeholder="https://dns.example/dns-query" onChange={(e) => change(i, { address: e.target.value })} autoCapitalize="none" spellCheck={false} /></Field>
          <Field label="IP DNS-сервера" hint="необязательно, через запятую"><Input value={v.bootstrap} placeholder="IP для подключения без системного DNS" onChange={(e) => change(i, { bootstrap: e.target.value })} autoCapitalize="none" spellCheck={false} /></Field>
        </div>
      </div>)}
    </div>
    <div className="mt-3 flex flex-wrap items-center gap-2"><Button mini disabled={value.length >= MAX_POOL} onClick={() => onChange([...value, { address: "", bootstrap: "" }])}>Добавить адрес</Button><Button mini disabled={value.filter((v) => v.address.trim() || v.bootstrap.trim()).length >= MAX_POOL} onClick={() => setPicking(true)}>Выбрать из списка DoH</Button><span className="text-xs text-muted">{value.length} / {MAX_POOL}</span></div>
    {picking && <CatalogPicker current={value} onAdd={add} onClose={() => setPicking(false)} />}
  </div>;
}

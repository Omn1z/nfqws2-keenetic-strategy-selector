import { useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { toast } from "@/components/ui/Toast";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field, Input, Select } from "@/components/ui/form";
import { Switch } from "@/components/ui/Switch";
import type { ARPSpoofConfig, ARPSpoofView } from "@/types/api";

const emptyConfig: ARPSpoofConfig = {
  enabled: false,
  mac: "",
  vendor_id: "huawei",
  prefix: "",
  ifaces: [],
  updated_at: 0,
};

const compactTime = (unix: number) => (unix ? new Date(unix * 1000).toLocaleString("ru-RU", { hour12: false }) : "-");

export default function ARPSpoofing() {
  const [view, setView] = useState<ARPSpoofView | null>(null);
  const [form, setForm] = useState<ARPSpoofConfig>(emptyConfig);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  const applyDefaults = (v: ARPSpoofView): ARPSpoofConfig => {
    const vendor = v.vendors.find((x) => x.id === v.config.vendor_id) ?? v.vendors[0];
    const prefix = v.config.prefix || vendor?.prefixes[0] || "";
    return { ...v.config, vendor_id: vendor?.id ?? "custom", prefix, ifaces: [] };
  };

  const load = async () => {
    const v = await api<ARPSpoofView>("GET", "/api/arp-spoofing");
    setView(v);
    if (!dirty) setForm(applyDefaults(v));
  };

  usePoll(async () => {
    try {
      await load();
    } catch {
      /* keep last */
    }
  }, 5000);

  const vendors = view?.vendors ?? [];
  const vendor = vendors.find((x) => x.id === form.vendor_id) ?? vendors[0];
  const prefixes = vendor?.prefixes ?? [];
  const autoIfaces = view?.suggested_ifaces?.length ? view.suggested_ifaces : ["AUTO"];

  const markDirty = (next: ARPSpoofConfig) => {
    setForm({ ...next, ifaces: [] });
    setDirty(true);
  };

  const setVendor = (id: string) => {
    const v = vendors.find((x) => x.id === id);
    markDirty({ ...form, vendor_id: id, prefix: v?.prefixes[0] ?? "", mac: "" });
  };

  const generate = async () => {
    setSaving(true);
    try {
      const r = await api<{ mac: string }>("POST", "/api/arp-spoofing/generate", { prefix: form.prefix });
      markDirty({ ...form, mac: r.mac });
      toast("MAC сгенерирован", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setSaving(false);
    }
  };

  const save = async (next = form) => {
    setSaving(true);
    try {
      const v = await api<ARPSpoofView>("POST", "/api/arp-spoofing/config", { ...next, ifaces: [] });
      setView(v);
      setForm(applyDefaults(v));
      setDirty(false);
      toast(v.config.enabled ? "ARP Spoofing применен" : "ARP Spoofing выключен", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setSaving(false);
    }
  };

  const quickDisable = async () => {
    setSaving(true);
    try {
      const v = await api<ARPSpoofView>("POST", "/api/arp-spoofing/enabled", { enabled: false });
      setView(v);
      setForm(applyDefaults(v));
      setDirty(false);
      toast("ARP Spoofing выключен", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setSaving(false);
    }
  };

  if (!view) return <Card><span className="text-xs text-muted">Загрузка...</span></Card>;

  const toolsOK = view.tools.ip;
  const canSave = !saving && (!form.enabled || form.mac.trim() !== "" || form.prefix.trim() !== "");

  return (
    <Card
      title="ARP Spoofing"
      sub={view.config.mac || "MAC роутера в ARP"}
      head={
        <div className="flex flex-wrap items-center justify-end gap-2">
          <Badge kind={view.active ? "ok" : view.config.enabled ? "bad" : "neutral"}>{view.active ? "активен" : view.config.enabled ? "ошибка" : "выключен"}</Badge>
          <Badge kind="neutral">AUTO {autoIfaces.join(", ")}</Badge>
          <Badge kind={toolsOK ? "ok" : "warn"}>{toolsOK ? "ip link ok" : "нужен ip"}</Badge>
        </div>
      }
    >
      <div className="grid gap-3 lg:grid-cols-[minmax(180px,.8fr)_minmax(150px,.6fr)_minmax(220px,1fr)_auto] lg:items-end">
        <Field label="Вендор">
          <Select value={form.vendor_id} onChange={(e) => setVendor(e.target.value)}>
            {vendors.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
          </Select>
        </Field>
        <Field label="OUI / prefix">
          <Select
            value={form.prefix}
            onChange={(e) => markDirty({ ...form, prefix: e.target.value, vendor_id: vendor?.prefixes.includes(e.target.value) ? form.vendor_id : "custom", mac: "" })}
          >
            {prefixes.length === 0 && <option value="">Ручной</option>}
            {prefixes.map((p) => <option key={p} value={p}>{p}</option>)}
            {!prefixes.includes(form.prefix) && form.prefix && <option value={form.prefix}>{form.prefix}</option>}
          </Select>
        </Field>
        <Field label="ARP MAC">
          <Input value={form.mac} placeholder="64:6E:EA:12:34:56" onChange={(e) => markDirty({ ...form, mac: e.target.value })} />
        </Field>
        <Button onClick={generate} disabled={saving}>Сгенерировать</Button>
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(220px,1fr)_auto] lg:items-end">
        <Field label="Ручной prefix">
          <Input value={form.prefix} placeholder="A4:C6:4F" onChange={(e) => markDirty({ ...form, prefix: e.target.value, vendor_id: "custom", mac: "" })} />
        </Field>
        <div className="flex h-[38px] flex-wrap items-center gap-4">
          <Switch checked={form.enabled} onChange={(enabled) => markDirty({ ...form, enabled })} label="Включено" />
          <Button variant="primary" onClick={() => void save()} disabled={!canSave}>
            {saving ? "Применение..." : "Сохранить"}
          </Button>
          <Button variant="danger" onClick={() => void quickDisable()} disabled={saving || (!view.config.enabled && !form.enabled)}>Снять</Button>
        </div>
      </div>

      <div className="mt-3 grid gap-2 rounded-lg border border-line bg-line-soft px-3 py-2 text-xs text-ink-soft md:grid-cols-3">
        <div><span className="font-semibold text-ink">Режим:</span> AUTO</div>
        <div><span className="font-semibold text-ink">Интерфейсы:</span> {autoIfaces.join(", ")}</div>
        <div><span className="font-semibold text-ink">Применено:</span> {compactTime(view.applied_at)}</div>
      </div>

      {view.last_error && (
        <div className="mt-3 rounded-lg border border-bad/30 bg-bad-bg px-3 py-2 text-xs text-bad [overflow-wrap:anywhere]">{view.last_error}</div>
      )}
    </Card>
  );
}

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { toast } from "@/components/ui/Toast";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field, Input, Select } from "@/components/ui/form";
import { Switch } from "@/components/ui/Switch";
import { EmptyRow, TableWrap, tableCls, tdCls, thBase } from "@/components/ui/Table";
import type { Device, DeviceActivityView, PortForwardPreset, PortForwardProfile, PortForwardRange, PortForwardRule, PortForwardView } from "@/types/api";

interface FormState {
  preset_id: string;
  profile_id: string;
  device_ip: string;
  name: string;
  enabled: boolean;
}

const emptyForm: FormState = { preset_id: "", profile_id: "", device_ip: "", name: "", enabled: true };

const portText = (ports: PortForwardRange[]) => {
  if (!ports?.length) return "-";
  return ports.map((p) => (p.start === p.end ? String(p.start) : `${p.start}-${p.end}`)).join(", ");
};

const findProfile = (preset?: PortForwardPreset, profileID?: string): PortForwardProfile | undefined =>
  preset?.profiles.find((p) => p.id === profileID) ?? preset?.profiles[0];

const defaultName = (preset?: PortForwardPreset, profile?: PortForwardProfile) =>
  preset && profile ? `${preset.name} - ${profile.name}` : "";

const deviceLabel = (d: Device) => [d.ip, d.mac, d.iface].filter(Boolean).join(" / ");

export default function PortForwarding() {
  const [view, setView] = useState<PortForwardView | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [form, setForm] = useState<FormState>(emptyForm);
  const [saving, setSaving] = useState(false);

  const load = async () => {
    const v = await api<PortForwardView>("GET", "/api/port-forwarding");
    setView(v);
    try {
      const d = await api<DeviceActivityView>("GET", "/api/devices");
      setDevices(d.devices ?? []);
    } catch {
      setDevices([]);
    }
  };

  usePoll(async () => {
    try {
      await load();
    } catch {
      /* keep last */
    }
  }, 5000);

  useEffect(() => {
    if (!view || form.preset_id) return;
    const preset = view.presets[0];
    const profile = preset?.profiles[0];
    if (!preset || !profile) return;
    setForm((f) => ({ ...f, preset_id: preset.id, profile_id: profile.id, name: defaultName(preset, profile) }));
  }, [view, form.preset_id]);

  const presets = view?.presets ?? [];
  const preset = presets.find((p) => p.id === form.preset_id);
  const profile = findProfile(preset, form.profile_id);
  const selectedDevice = devices.find((d) => d.ip === form.device_ip);
  const sortedDevices = useMemo(() => [...devices].sort((a, b) => b.total - a.total || a.ip.localeCompare(b.ip)), [devices]);

  const setPreset = (id: string) => {
    const p = presets.find((x) => x.id === id);
    const prof = p?.profiles[0];
    setForm((f) => ({ ...f, preset_id: id, profile_id: prof?.id ?? "", name: defaultName(p, prof) }));
  };

  const setProfile = (id: string) => {
    const prof = findProfile(preset, id);
    setForm((f) => ({ ...f, profile_id: id, name: defaultName(preset, prof) }));
  };

  const addRule = async () => {
    if (!view || !preset || !profile) return;
    if (!selectedDevice) {
      toast("Выберите устройство для Forwarding", "err");
      return;
    }
    setSaving(true);
    try {
      const next = await api<PortForwardView>("POST", "/api/port-forwarding/rules", {
        name: form.name.trim() || defaultName(preset, profile),
        preset_id: preset.id,
        profile_id: profile.id,
        device_ip: selectedDevice.ip,
        device_name: selectedDevice.mac || selectedDevice.ip,
        device_mac: selectedDevice.mac,
        device_iface: selectedDevice.iface,
        enabled: form.enabled,
      });
      setView(next);
      toast("Port Forwarding сохранен", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setSaving(false);
    }
  };

  const toggleRule = async (rule: PortForwardRule, enabled: boolean) => {
    try {
      setView(await api<PortForwardView>("POST", `/api/port-forwarding/rules/${rule.id}/enabled`, { enabled }));
      toast(enabled ? "Правило включено" : "Правило выключено", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  const deleteRule = async (rule: PortForwardRule) => {
    try {
      setView(await api<PortForwardView>("DELETE", `/api/port-forwarding/rules/${rule.id}`));
      toast("Правило удалено", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  const labelFor = (rule: PortForwardRule) => {
    const p = presets.find((x) => x.id === rule.preset_id);
    const prof = findProfile(p, rule.profile_id);
    return [p?.name ?? rule.preset_id, prof?.name ?? rule.profile_id].filter(Boolean).join(" - ");
  };

  if (!view) return <Card><span className="text-xs text-muted">Загрузка...</span></Card>;

  return (
    <>
      <Card
        title="Port Forwarding"
        sub="игровые пресеты"
        head={<Badge kind={view.wan_ifaces?.length ? "ok" : "warn"}>WAN {view.wan_ifaces?.join(", ") || "auto"}</Badge>}
      >
        <div className="grid gap-3 lg:grid-cols-[minmax(220px,1.1fr)_180px_minmax(220px,1fr)]">
          <Field label="Пресет">
            <Select value={form.preset_id} onChange={(e) => setPreset(e.target.value)}>
              {presets.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Select>
          </Field>
          <Field label="Платформа">
            <Select value={profile?.id ?? ""} onChange={(e) => setProfile(e.target.value)}>
              {(preset?.profiles ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Select>
          </Field>
          <Field label="Устройство">
            <Select value={form.device_ip} onChange={(e) => setForm((f) => ({ ...f, device_ip: e.target.value }))}>
              <option value="">Выберите устройство...</option>
              {sortedDevices.map((d) => <option key={`${d.ip}-${d.mac}`} value={d.ip}>{deviceLabel(d)}</option>)}
            </Select>
          </Field>
        </div>

        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(260px,1fr)_auto] lg:items-end">
          <Field label="Имя правила">
            <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </Field>
          <div className="flex h-[38px] items-center gap-4">
            <Switch checked={form.enabled} onChange={(enabled) => setForm((f) => ({ ...f, enabled }))} label="Включено" />
            <Button variant="primary" onClick={addRule} disabled={saving || !selectedDevice || !profile}>
              {saving ? "Сохранение..." : "Добавить"}
            </Button>
          </div>
        </div>

        {profile && (
          <div className="mt-3 grid gap-2 rounded-lg border border-line bg-line-soft px-3 py-2 text-xs text-ink-soft md:grid-cols-2">
            <div><span className="font-semibold text-ink">TCP:</span> <span className="[overflow-wrap:anywhere]">{portText(profile.tcp)}</span></div>
            <div><span className="font-semibold text-ink">UDP:</span> <span className="[overflow-wrap:anywhere]">{portText(profile.udp)}</span></div>
          </div>
        )}
      </Card>

      <Card
        title="Правила"
        sub={`${view.rules.length}`}
        head={<Button mini onClick={() => void load().catch((e) => toast((e as Error).message, "err"))}>Обновить</Button>}
      >
        <TableWrap>
          <table className={tableCls}>
            <thead>
              <tr>
                <th className={thBase}>Статус</th>
                <th className={thBase}>Правило</th>
                <th className={thBase}>Устройство</th>
                <th className={thBase}>TCP</th>
                <th className={thBase}>UDP</th>
                <th className={cn(thBase, "text-right")}>Действия</th>
              </tr>
            </thead>
            <tbody>
              {view.rules.length === 0 && <EmptyRow colSpan={6}>Правил пока нет</EmptyRow>}
              {view.rules.map((rule) => (
                <tr key={rule.id}>
                  <td className={tdCls}>
                    <Switch checked={rule.enabled} onChange={(v) => toggleRule(rule, v)} />
                  </td>
                  <td className={tdCls}>
                    <div className="font-semibold text-ink">{rule.name}</div>
                    <div className="mt-0.5 text-[11px] text-muted">{labelFor(rule)}</div>
                  </td>
                  <td className={tdCls}>
                    <div className="font-mono text-xs text-ink">{rule.device_ip}</div>
                    <div className="mt-0.5 text-[11px] text-muted">{[rule.device_mac, rule.device_iface].filter(Boolean).join(" / ")}</div>
                  </td>
                  <td className={cn(tdCls, "max-w-[260px] text-xs [overflow-wrap:anywhere]")}>{portText(rule.tcp)}</td>
                  <td className={cn(tdCls, "max-w-[260px] text-xs [overflow-wrap:anywhere]")}>{portText(rule.udp)}</td>
                  <td className={cn(tdCls, "text-right")}>
                    <Button mini variant="danger" onClick={() => void deleteRule(rule)}>Удалить</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Card>
    </>
  );
}

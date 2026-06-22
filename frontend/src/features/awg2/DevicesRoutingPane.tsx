import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Input, Select } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";
import type { Device, Awg2Status, AwgZone, AwgRoutingConfig } from "@/types/api";

/** Device-first view of AWG2 routing: lists every LAN device the router can see
 *  (DHCP + ARP) with a one-click chooser of how its traffic is routed:
 *
 *    «По умолч.»      — no per-device zone; the device follows global rules.
 *    «Исключить»      — source-bound direct catch-all.
 *    «<tunnel label>» — source-bound tunnel catch-all via the selected tunnel.
 *
 *  All changes batch into a single `routing/config` save. Apply runs on save so
 *  the firewall hook re-renders without an explicit step.
 */

type DeviceMode = "default" | "exclude" | "custom" | `tunnel:${string}`;

const modeKind = (mode: DeviceMode): "neutral" | "ok" | "warn" | "bad" =>
  mode === "exclude" ? "warn" : mode.startsWith("tunnel:") ? "ok" : "neutral";

// Zone name prefix the device-tab uses for its auto-managed zones, so we can
// detect-and-reuse them on the next save instead of bloating the zone list.
const ZONE_PREFIX = "device:";

// nameFor builds the auto-zone name from an IP — deterministic so a future
// edit finds the same zone instead of creating a duplicate.
const nameFor = (ip: string) => ZONE_PREFIX + ip;

// detectMode looks at the live routing.zones snapshot and figures out what
// state the device is currently in. "default" = nothing tied to it.
const routeOf = (z: AwgZone) => z.route === "direct" || z.mode === "exclude" ? "direct" : "tunnel";
const isCatchAll = (z: AwgZone) => (z.domains ?? []).includes("*") || (z.ips ?? []).some((ip) => ip === "0.0.0.0/0" || ip === "::/0");

function detectMode(zones: AwgZone[], ip: string): DeviceMode {
  // Find auto-managed zone first.
  const auto = zones.find((z) => z.name === nameFor(ip));
  if (auto) {
    if (!auto.enabled) return "default";
    if (routeOf(auto) === "tunnel" && isCatchAll(auto)) return auto.tunnel_id ? `tunnel:${auto.tunnel_id}` : "custom";
    if (routeOf(auto) === "direct" && (auto.domains?.length ?? 0) === 0 && (auto.ips?.length ?? 0) === 0) return "exclude";
    return "custom";
  }
  // Look for any zone (user-named) that owns this IP — treat as custom.
  if (zones.some((z) => (z.source_ips ?? []).includes(ip))) return "custom";
  return "default";
}

// applyMode returns a NEW zones array with the device's mode set as requested.
// Idempotent: re-applying the same mode returns the same array (modulo identity).
function applyMode(zones: AwgZone[], ip: string, mode: DeviceMode, fallbackTunnelID: string): AwgZone[] {
  const name = nameFor(ip);
  const without = zones.filter((z) => z.name !== name);
  if (mode === "default") return without; // drop the auto zone entirely
  if (mode === "custom") {
    // Custom can't be created here — only detected when the user edits a
    // hand-named zone with this IP. So treat as "no change to auto zone".
    return zones;
  }
  const tunnelID = mode.startsWith("tunnel:") ? mode.slice("tunnel:".length) : fallbackTunnelID;
  const z: AwgZone = mode.startsWith("tunnel:")
    ? { name, tunnel_id: tunnelID, mode: "include", route: "tunnel", domains: ["*"], ips: [], source_ips: [ip], enabled: true }
    : { name, mode: "exclude", route: "direct", domains: [], ips: [], source_ips: [ip], enabled: true };
  return [...without, z];
}
const routingFromStatus = (st: Awg2Status): AwgRoutingConfig => ({
  ...st.config.routing,
  mode: st.config.routing?.mode || "zones",
  zones: st.routing_rules || st.config.routing?.zones || [],
});

interface Props {
  st: Awg2Status;
  reload: () => void;
}

export default function DevicesRoutingPane({ st, reload }: Props) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [routing, setRouting] = useState<AwgRoutingConfig>(() => routingFromStatus(st));
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");
  // While an autosave is in flight (or a mode click came within ~1 s of the
  // last upstream poll), skip re-syncing routing from upstream — otherwise
  // an inflight POST + a status-snapshot tick race, and the user sees their
  // click "snap back" before the save lands.
  const lastEditAt = useRef<number>(0);
  const tunnels = useMemo(() => (st.servers || []).filter((s) => s.enabled && (s.imported || s.deployed || s.endpoint)), [st.servers]);
  const defaultTunnelID = tunnels.find((s) => s.connected)?.id || tunnels[0]?.id || st.active_server_id || "";
  const tunnelByID = useMemo(() => new Map(tunnels.map((s) => [s.id, s] as const)), [tunnels]);
  useEffect(() => {
    if (busy) return;
    if (Date.now() - lastEditAt.current < 1500) return;
    setRouting(routingFromStatus(st));
  }, [st, busy]);

  // Live-poll the device list (same data the Devices tab uses).
  useEffect(() => {
    let cancelled = false;
    const fetchOnce = async () => {
      try {
        const v = await api<{ devices: Device[] }>("GET", "/api/devices");
        if (cancelled) return;
        setDevices((v.devices ?? []).filter((d) => d.ip));
      } catch { /* keep last */ }
    };
    void fetchOnce();
    const id = window.setInterval(fetchOnce, 5000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  // Autosave: every mode click immediately POSTs the updated config and (if
  // routing is live) applies + commits, so the user never has to hit a button.
  // Optimistic local update first → API call → toast on error/rollback.
  const onSet = async (ip: string, mode: DeviceMode) => {
    if (busy) return;
    lastEditAt.current = Date.now();
    const next = { ...routing, mode: routing.mode === "off" ? "zones" : routing.mode, zones: applyMode(routing.zones ?? [], ip, mode, defaultTunnelID) };
    setRouting(next);
    setBusy(true);
    try {
      await api("POST", "/api/awg2/routing/rules", next);
      void reload();
    } catch (e) {
      toast((e as Error).message, "err");
      setRouting(routing); // rollback
    } finally {
      setBusy(false);
    }
  };

  const filtered = useMemo(() => {
    const s = search.trim().toLowerCase();
    if (!s) return devices;
    return devices.filter((d) =>
      d.ip.includes(s) ||
      (d.mac ?? "").toLowerCase().includes(s) ||
      (d.hostname ?? "").toLowerCase().includes(s)
    );
  }, [devices, search]);

  return (
    <Card
      title="Устройства AWG2"
      sub="клик на устройство — сразу применяется"
      head={
        <div className="flex flex-wrap items-center gap-2">
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="фильтр: IP, MAC, имя" className="h-8 w-56 text-[12px]" />
          {busy && <span className="text-[11px] text-muted">сохраняем…</span>}
        </div>
      }
    >
      <div className="overflow-x-auto rounded border border-line">
        <table className="w-full text-[11px] md:text-[12px]">
          <thead className="bg-panel-soft text-[10px] uppercase text-muted md:text-[11px]">
            <tr>
              <th className="px-2 py-1.5 text-left">Устройство</th>
              <th className="px-2 py-1.5 text-left">IP / MAC</th>
              <th className="hidden px-2 py-1.5 text-left lg:table-cell">Активность</th>
              <th className="px-2 py-1.5 text-left">Режим</th>
              <th className="hidden px-2 py-1.5 text-right md:table-cell">Текущее</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="px-2 py-6 text-center text-muted">
                  Нет устройств — обнови страницу или подожди пока кто-нибудь подключится.
                </td>
              </tr>
            )}
            {filtered.map((d, i) => {
              const mode = detectMode(routing.zones ?? [], d.ip);
              return (
                <tr key={d.ip + d.mac} className={cn("border-t border-line", i % 2 ? "bg-panel-soft/40" : "")}>
                  <td className="px-2 py-1.5">
                    <div className="font-medium text-ink">{d.hostname || <span className="text-muted">без имени</span>}</div>
                    {d.iface && <div className="text-[10px] text-muted">{d.iface}</div>}
                  </td>
                  <td className="px-2 py-1.5 font-mono">
                    <div>{d.ip}</div>
                    {d.ipv6 && d.ipv6.length > 0 && (
                      <div className="text-[10px] text-muted" title={d.ipv6.join("\n")}>
                        {d.ipv6.length === 1 ? d.ipv6[0] : `${d.ipv6[0]} + ещё ${d.ipv6.length - 1}`}
                      </div>
                    )}
                    <div className="text-[10px] text-muted">{d.mac || "—"}</div>
                  </td>
                  <td className="hidden px-2 py-1.5 text-[11px] text-muted lg:table-cell">
                    {d.established || 0} ESTABL · {d.failing || 0} fail
                  </td>
                  <td className="px-2 py-1.5">
                    <DeviceRouteSelect value={mode} tunnels={tunnels} defaultTunnelID={defaultTunnelID} onChange={(m) => onSet(d.ip, m)} />
                  </td>
                  <td className="hidden px-2 py-1.5 text-right md:table-cell">
                    <Badge kind={modeKind(mode)}>{modeLabel(mode, tunnelByID)}</Badge>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="mt-3 text-[11px] text-muted">
        Каждое назначение создаёт source-bound зону <code>{ZONE_PREFIX}&lt;ip&gt;</code>. Можно увидеть/тонко править в
        вкладке «Маршрутизация» (например, добавить «эти домены — мимо» для устройства, которое в целом через VPN).
        После «Сохранить и применить» firewall-хук переписывается; обычно занимает 1-2 секунды.
        Если нужны разные правила на v4 и v6 — селектор сам подтянет MAC из ARP-кэша на v6.
      </p>
    </Card>
  );
}

function modeLabel(mode: DeviceMode, tunnels: Map<string, { label: string; client_iface?: string }>) {
  if (mode === "default") return "По умолчанию";
  if (mode === "exclude") return "Исключить";
  if (mode === "custom") return "Своя зона";
  const id = mode.slice("tunnel:".length);
  const t = tunnels.get(id);
  return t ? `${t.label}${t.client_iface ? ` · ${t.client_iface}` : ""}` : "Туннель";
}

function DeviceRouteSelect({
  value,
  tunnels,
  defaultTunnelID,
  onChange,
}: {
  value: DeviceMode;
  tunnels: { id: string; label: string; client_iface?: string; connected?: boolean }[];
  defaultTunnelID: string;
  onChange: (m: DeviceMode) => void;
}) {
  const selectValue = value === "custom" ? "custom" : value.startsWith("tunnel:") ? value : value;
  return (
    <Select
      value={selectValue}
      onChange={(e) => {
        const v = e.target.value as DeviceMode;
        if (v === "custom") return;
        if (v === "tunnel:" && defaultTunnelID) onChange(`tunnel:${defaultTunnelID}`);
        else onChange(v);
      }}
      className="h-8 min-w-[180px] py-1 text-[12px]"
    >
      <option value="default">По умолчанию</option>
      <option value="exclude">Исключить</option>
      {tunnels.map((s) => (
        <option key={s.id} value={`tunnel:${s.id}`}>
          {s.label}{s.client_iface ? ` · ${s.client_iface}` : ""}{s.connected ? " · connected" : ""}
        </option>
      ))}
      {value === "custom" && <option value="custom">Своя зона</option>}
    </Select>
  );
}

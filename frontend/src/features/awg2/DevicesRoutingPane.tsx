import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";
import type { Device, Awg2Status, AwgZone, AwgRoutingConfig } from "@/types/api";

/** Device-first view of AWG2 routing: lists every LAN device the router can see
 *  (DHCP + ARP) with a one-click chooser of how its traffic is routed:
 *
 *    «По умолч.»   — no per-device zone; the device follows the global mode.
 *    «Всё через VPN» — creates / activates a source-bound include zone with
 *                       catch-all "*" for this device's IP.
 *    «Всё мимо»     — creates / activates a source-bound exclude zone with no
 *                       domains for this device's IP (firewall: RETURN before
 *                       the global mark, so EVERYTHING from this src goes direct).
 *
 *  All changes batch into a single `routing/config` save. Apply runs on save so
 *  the firewall hook re-renders without an explicit step.
 */

type DeviceMode = "default" | "all-vpn" | "all-direct" | "custom";

const MODE_LABEL: Record<DeviceMode, string> = {
  default:    "По умолчанию",
  "all-vpn":  "Всё через VPN",
  "all-direct": "Всё мимо VPN",
  custom:     "Своя зона",
};

const MODE_KIND: Record<DeviceMode, "neutral" | "ok" | "warn" | "bad"> = {
  default:    "neutral",
  "all-vpn":  "ok",
  "all-direct": "warn",
  custom:     "neutral",
};

// Zone name prefix the device-tab uses for its auto-managed zones, so we can
// detect-and-reuse them on the next save instead of bloating the zone list.
const ZONE_PREFIX = "device:";

// nameFor builds the auto-zone name from an IP — deterministic so a future
// edit finds the same zone instead of creating a duplicate.
const nameFor = (ip: string) => ZONE_PREFIX + ip;

// detectMode looks at the live routing.zones snapshot and figures out what
// state the device is currently in. "default" = nothing tied to it.
function detectMode(zones: AwgZone[], ip: string): DeviceMode {
  // Find auto-managed zone first.
  const auto = zones.find((z) => z.name === nameFor(ip));
  if (auto) {
    if (!auto.enabled) return "default";
    if (auto.mode === "include" && (auto.domains?.includes("*") ?? false)) return "all-vpn";
    if (auto.mode === "exclude" && (auto.domains?.length ?? 0) === 0 && (auto.ips?.length ?? 0) === 0) return "all-direct";
    return "custom";
  }
  // Look for any zone (user-named) that owns this IP — treat as custom.
  if (zones.some((z) => (z.source_ips ?? []).includes(ip))) return "custom";
  return "default";
}

// applyMode returns a NEW zones array with the device's mode set as requested.
// Idempotent: re-applying the same mode returns the same array (modulo identity).
function applyMode(zones: AwgZone[], ip: string, mode: DeviceMode): AwgZone[] {
  const name = nameFor(ip);
  const without = zones.filter((z) => z.name !== name);
  if (mode === "default") return without; // drop the auto zone entirely
  if (mode === "custom") {
    // Custom can't be created here — only detected when the user edits a
    // hand-named zone with this IP. So treat as "no change to auto zone".
    return zones;
  }
  const z: AwgZone = mode === "all-vpn"
    ? { name, mode: "include", domains: ["*"], ips: [], source_ips: [ip], enabled: true }
    : { name, mode: "exclude", domains: [],   ips: [], source_ips: [ip], enabled: true };
  return [...without, z];
}

interface Props {
  st: Awg2Status;
  reload: () => void;
}

export default function DevicesRoutingPane({ st, reload }: Props) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [routing, setRouting] = useState<AwgRoutingConfig>(() => st.config.routing);
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");
  // While an autosave is in flight (or a mode click came within ~1 s of the
  // last upstream poll), skip re-syncing routing from upstream — otherwise
  // an inflight POST + a status-snapshot tick race, and the user sees their
  // click "snap back" before the save lands.
  const lastEditAt = useRef<number>(0);
  useEffect(() => {
    if (busy) return;
    if (Date.now() - lastEditAt.current < 1500) return;
    setRouting(st.config.routing);
  }, [st.config.routing, busy]);

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
    const next = { ...routing, zones: applyMode(routing.zones ?? [], ip, mode) };
    setRouting(next);
    setBusy(true);
    try {
      await api("POST", "/api/awg2/routing/config", next);
      if (next.active) {
        await api("POST", "/api/awg2/routing/apply", {});
        await api("POST", "/api/awg2/routing/commit", {});
      }
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
                    <ModeButtons value={mode} onChange={(m) => onSet(d.ip, m)} />
                  </td>
                  <td className="hidden px-2 py-1.5 text-right md:table-cell">
                    <Badge kind={MODE_KIND[mode]}>{MODE_LABEL[mode]}</Badge>
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

function ModeButtons({ value, onChange }: { value: DeviceMode; onChange: (m: DeviceMode) => void }) {
  // "custom" is read-only — it appears when a user hand-edited a zone with this
  // source. Don't offer a button for it; we don't manufacture custom zones here.
  const opts: { v: Exclude<DeviceMode, "custom">; label: string }[] = [
    { v: "default",    label: "по умолч." },
    { v: "all-vpn",    label: "всё VPN" },
    { v: "all-direct", label: "всё мимо" },
  ];
  return (
    <div className="inline-flex overflow-hidden rounded border border-line">
      {opts.map((o, i) => (
        <button
          key={o.v}
          type="button"
          onClick={() => onChange(o.v)}
          className={cn(
            "px-2 py-1 text-[11px] transition",
            i > 0 && "border-l border-line",
            value === o.v ? "bg-accent text-white" : "bg-panel hover:bg-line-soft",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

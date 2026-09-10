import { useState, useEffect, useMemo } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Field, Input, Textarea } from "@/components/ui/form";
import { Switch } from "@/components/ui/Switch";
import { Modal } from "@/components/ui/Modal";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import type { Awg2ServerSummary, Awg2Status, AwgZone, AwgRoutingConfig, Device } from "@/types/api";

/** RulesTable replaces the old zone-form layout with a pi-hole-style table:
 *  each rule is one row with its priority (= array index), name, match preview,
 *  route badge, sources, enabled toggle, and inline actions (move up/down,
 *  duplicate, edit, delete). Order in the array IS the priority — the first
 *  matching rule wins at lookup time.
 *
 *  The legacy `mode: include|exclude` is migrated to `route: tunnel|direct`
 *  on render; saves always write `route`. */

type Route = "tunnel" | "direct";
const routeOf = (z: AwgZone): Route =>
  z.route === "tunnel" || z.route === "direct"
    ? z.route
    : z.mode === "exclude"
    ? "direct"
    : "tunnel";

const ROUTE_LABEL: Record<Route, string> = { tunnel: "Через VPN", direct: "Мимо VPN" };
const ROUTE_KIND: Record<Route, "ok" | "warn"> = { tunnel: "ok", direct: "warn" };
const tunnelLabel = (s?: Awg2ServerSummary) => s ? `${s.label || s.id}${s.client_iface ? ` · ${s.client_iface}` : ""}` : "туннель не выбран";

const zoneLines = (z: AwgZone) => [...(z.domains || []), ...(z.ips || [])];
const splitRaw = (s: string) => s.split("\n");
const cleanArr = (a: string[]) => (a || []).map((x) => x.trim()).filter(Boolean);
const isIPish = (s: string) =>
  /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(s) ||
  (s.includes(":") && /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(s));

interface Props {
  r: AwgRoutingConfig;
  setR: (r: AwgRoutingConfig | ((p: AwgRoutingConfig) => AwgRoutingConfig)) => void;
  st: Awg2Status;
  reload: () => void;
}

export default function RulesTable({ r, setR, st, reload }: Props) {
  const [editIdx, setEditIdx] = useState<number | null>(null);
  const [copyOpen, setCopyOpen] = useState(false);

  const zones = r.zones || [];
  const tunnels = useMemo(() => (st.servers || []).filter((s) => s.enabled && (s.imported || s.deployed || s.endpoint)), [st.servers]);
  const defaultTunnelID = tunnels.find((s) => s.connected)?.id || tunnels[0]?.id || st.active_server_id || "";
  const tunnelByID = useMemo(() => new Map((st.servers || []).map((s) => [s.id, s] as const)), [st.servers]);

  // persist runs after every rule action so the table behaves like pi-hole's
  // group/list editor: "delete" actually deletes, "up" actually moves, edits
  // immediately reach the firewall hook. No manual "apply" button needed.
  //
  // We always /config → /apply → /commit (unless routing is off — then nothing
  // to apply). The dead-man's switch flow is unnecessary here: the panel is
  // reached via LAN, LAN is always in awgExcludes, so a rule edit can't cut
  // panel access regardless of what the user chose.
  const persist = async (next: AwgRoutingConfig) => {
    try {
      await api("POST", "/api/awg2/routing/rules", next);
      await reload();
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };
  // applyOp builds the next config from `r`, applies it to local state, then
  // persists. Wrapped so every action is one line.
  const applyOp = (op: (zs: AwgZone[]) => AwgZone[]) => {
    const nextZones = op(zones).map((z, i) => ({ ...z, tunnel_id: z.tunnel_id || defaultTunnelID, order: i + 1 }));
    const next: AwgRoutingConfig = { ...r, zones: nextZones };
    setR(next);
    void persist(next);
  };

  const setZ = (i: number, patch: Partial<AwgZone>) => applyOp((zs) => zs.map((z, j) => (j === i ? { ...z, ...patch } : z)));
  const move = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= zones.length) return;
    applyOp((zs) => { const a = [...zs]; [a[i], a[j]] = [a[j], a[i]]; return a; });
  };
  const dup = (i: number) =>
    applyOp((zs) => {
      const clone: AwgZone = { ...zs[i], name: zs[i].name + " (копия)" };
      return [...zs.slice(0, i + 1), clone, ...zs.slice(i + 1)];
    });
  const del = async (i: number) => {
    if (!(await confirmDialog({ title: `Удалить правило «${zones[i].name}»?` }))) return;
    applyOp((zs) => zs.filter((_, j) => j !== i));
  };
  const add = () => {
    const fresh: AwgZone = {
      name: "новое правило",
      tunnel_id: defaultTunnelID,
      route: "tunnel",
      domains: [],
      ips: [],
      source_ips: [],
      enabled: true,
    };
    // Prepend at the top — the FMW priority is top-down, so a freshly-added
    // rule should be the highest-priority by default. Same convention the
    // Trace «↑ VPN / → direct» quick-actions follow.
    applyOp((zs) => [fresh, ...zs]);
    setEditIdx(0); // open the editor for the new top row
  };

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <h3 className="text-[14px] font-semibold">Правила маршрутизации</h3>
        <span className="text-[11px] text-muted">{zones.length} шт. · приоритет сверху вниз</span>
        <div className="ml-auto flex items-center gap-2">
          <Button mini variant="primary" onClick={add}>+ правило</Button>
        </div>
      </div>

      <div className="overflow-x-auto rounded border border-line">
        <table className="w-full text-[11px] md:text-[12px]">
          <thead className="bg-panel-soft text-[10px] uppercase text-muted md:text-[11px]">
            <tr>
              <th className="w-[36px] px-2 py-1.5 text-center">#</th>
              <th className="px-2 py-1.5 text-left">Имя</th>
              <th className="px-2 py-1.5 text-left">Туннель</th>
              <th className="px-2 py-1.5 text-left">Маршрут</th>
              <th className="px-2 py-1.5 text-left">Что матчит</th>
              <th className="hidden px-2 py-1.5 text-left md:table-cell">Источники</th>
              <th className="w-[60px] px-2 py-1.5 text-center">Вкл</th>
              <th className="w-[180px] px-2 py-1.5 text-right">Действия</th>
            </tr>
          </thead>
          <tbody>
            {zones.length === 0 && (
              <tr>
                <td colSpan={8} className="px-2 py-6 text-center text-muted">
                  Правил пока нет. Добавьте первое — например, «всё через VPN» (домен <code>*</code>, маршрут «Через VPN»).
                </td>
              </tr>
            )}
            {zones.map((z, i) => {
              const route = routeOf(z);
              const matches = cleanArr(zoneLines(z));
              const srcs = cleanArr(z.source_ips || []);
              return (
                <tr key={i} className={cn("border-t border-line", i % 2 ? "bg-panel-soft/40" : "")}>
                  <td className="px-2 py-1.5 text-center font-mono tabular-nums text-muted">{i + 1}</td>
                  <td className="px-2 py-1.5">
                    <button type="button" className="text-left font-medium text-ink hover:underline" onClick={() => setEditIdx(i)}>{z.name || "(без имени)"}</button>
                  </td>
                  <td className="px-2 py-1.5 text-[11px] text-ink-soft">{tunnelLabel(tunnelByID.get(z.tunnel_id || defaultTunnelID))}</td>
                  <td className="px-2 py-1.5"><Badge kind={ROUTE_KIND[route]}>{ROUTE_LABEL[route]}</Badge></td>
                  <td className="px-2 py-1.5 font-mono text-[11px]">
                    {matches.length === 0 ? <span className="text-muted">—</span> : (
                      <>
                        <span className="truncate">{matches.slice(0, 2).join(", ")}</span>
                        {matches.length > 2 && <span className="text-muted"> +{matches.length - 2}</span>}
                      </>
                    )}
                  </td>
                  <td className="hidden px-2 py-1.5 font-mono text-[11px] md:table-cell">
                    {srcs.length === 0 ? <span className="text-muted">вся LAN</span> : (
                      <>
                        <span>{srcs.slice(0, 2).join(", ")}</span>
                        {srcs.length > 2 && <span className="text-muted"> +{srcs.length - 2}</span>}
                      </>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-center">
                    <Switch checked={!!z.enabled} onChange={(v) => setZ(i, { enabled: v })} />
                  </td>
                  <td className="px-2 py-1.5">
                    <div className="flex items-center justify-end gap-1">
                      <Button mini variant="ghost" onClick={() => move(i, -1)} disabled={i === 0} title="Выше">▲</Button>
                      <Button mini variant="ghost" onClick={() => move(i, +1)} disabled={i === zones.length - 1} title="Ниже">▼</Button>
                      <Button mini variant="ghost" onClick={() => setEditIdx(i)} title="Изменить">✎</Button>
                      <Button mini variant="ghost" onClick={() => dup(i)} title="Дублировать">⎘</Button>
                      <Button mini variant="danger" onClick={() => void del(i)} title="Удалить">✕</Button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="mt-2 text-[11px] text-muted">
        Приоритет = порядок в таблице. <b>Первое</b> правило, под которое подходит запрос, определяет маршрут.
        В колонке «Что матчит» можно вписывать вперемешку: домены/маски (<code>youtube.com</code>, <code>*ip*</code>,
        <code>regexp:^.*\.foo$</code>, <code>geosite:cn</code>, <code>list:user</code>), IPv4 и подсети (<code>104.18.0.0/16</code>).
        Источники задают, к каким LAN-устройствам правило применяется (пусто = ко всем).
      </p>

      {editIdx !== null && zones[editIdx] && (
        <RuleEditModal
          zone={zones[editIdx]}
          tunnels={tunnels}
          defaultTunnelID={defaultTunnelID}
          onClose={() => setEditIdx(null)}
          onSave={(patch) => { setZ(editIdx, patch); setEditIdx(null); }}
        />
      )}
      {copyOpen && (
        <CopyFromServerModal
          st={st}
          onClose={() => setCopyOpen(false)}
          onCopied={async () => { setCopyOpen(false); await reload(); toast("Правила скопированы", "ok"); }}
        />
      )}
    </div>
  );
}

function RuleEditModal({ zone, tunnels, defaultTunnelID, onClose, onSave }: { zone: AwgZone; tunnels: Awg2ServerSummary[]; defaultTunnelID: string; onClose: () => void; onSave: (patch: Partial<AwgZone>) => void }) {
  const [z, setZ] = useState<AwgZone>({ ...zone, tunnel_id: zone.tunnel_id || defaultTunnelID, route: routeOf(zone) });
  const [devices, setDevices] = useState<Device[]>([]);
  useEffect(() => {
    void (async () => {
      try {
        const v = await api<{ devices: Device[] }>("GET", "/api/devices");
        setDevices((v.devices ?? []).filter((d) => d.ip));
      } catch { /* ignore */ }
    })();
  }, []);
  const matches = (z.domains || []).join("\n") + ((z.ips || []).length ? "\n" + (z.ips || []).join("\n") : "");

  const save = () => {
    const lines = cleanArr(splitRaw(matches));
    const domains = lines.filter((s) => !isIPish(s));
    const ips = lines.filter(isIPish);
    onSave({
      name: z.name,
      tunnel_id: z.tunnel_id || defaultTunnelID,
      route: z.route as Route,
      mode: z.route === "direct" ? "exclude" : "include", // legacy backward compat
      domains,
      ips,
      source_ips: cleanArr(splitRaw((z.source_ips || []).join("\n"))),
      enabled: z.enabled,
    });
  };

  return (
    <Modal title={`Правило: ${z.name || "(без имени)"}`} onClose={onClose} actions={
      <>
        <Button variant="ghost" onClick={onClose}>Отмена</Button>
        <Button variant="primary" onClick={save}>Сохранить</Button>
      </>
    }>
      <div className="space-y-3">
        <Field label="Имя">
          <Input value={z.name} onChange={(e) => setZ({ ...z, name: e.target.value })} placeholder="напр. youtube → VPN" />
        </Field>
        <Field label="Туннель">
          <select value={z.tunnel_id || defaultTunnelID} onChange={(e) => setZ({ ...z, tunnel_id: e.target.value })} className="w-full rounded border border-line bg-panel px-2 py-1.5 text-[13px]">
            {tunnels.map((s) => (
              <option key={s.id} value={s.id}>{tunnelLabel(s)}{s.connected ? " · connected" : ""}</option>
            ))}
          </select>
        </Field>
        <Field label="Маршрут">
          <div className="inline-flex overflow-hidden rounded-md border border-line">
            {(["tunnel", "direct"] as Route[]).map((rv) => (
              <button key={rv} type="button" onClick={() => setZ({ ...z, route: rv })}
                className={cn("px-3 py-1.5 text-[13px] transition", z.route === rv ? "bg-accent text-white" : "bg-panel hover:bg-line-soft")}>
                {ROUTE_LABEL[rv]}
              </button>
            ))}
          </div>
        </Field>
        <Field label="Что матчит — домены, маски и IP (по строке)"
          hint="Префиксы xray-стиля: domain:vk.com (суффикс), full:exact.com (точный), geosite:cn / geoip:cn, regexp:^.*\.foo$ (Go regex), keyword:foo (substring), list:user (читает /opt/etc/nfqws2/lists/user.list)">
          <Textarea rows={6} value={matches}
            placeholder={"youtube.com\n*ip*\ndomain:vk.com\ngeosite:cn\nregexp:^.*\\.googlevideo\\.com$\n104.18.0.0/16"}
            onChange={(e) => {
              const lines = splitRaw(e.target.value);
              setZ({ ...z, domains: lines, ips: [] });
            }} />
        </Field>
        <Field label="Источники LAN (пусто = ко всей сети)"
          hint="Если задано, правило применяется ТОЛЬКО к пакетам от этих устройств. IPv4 — по адресу; v6-адрес учим из ARP-кэша по MAC, чтобы менялся вместе с SLAAC.">
          <div className="flex items-start gap-2">
            <Textarea rows={2} className="flex-1" value={(z.source_ips || []).join("\n")}
              placeholder={"192.168.31.243\n192.168.31.100"}
              onChange={(e) => setZ({ ...z, source_ips: splitRaw(e.target.value) })} />
            <DeviceDrop devices={devices} onPick={(ip) => {
              const cur = cleanArr(z.source_ips || []);
              if (!cur.includes(ip)) setZ({ ...z, source_ips: [...cur, ip] });
            }} />
          </div>
        </Field>
        <div className="flex items-center gap-2"><Switch checked={!!z.enabled} onChange={(v) => setZ({ ...z, enabled: v })} label="Включено" /></div>
      </div>
    </Modal>
  );
}

function DeviceDrop({ devices, onPick }: { devices: Device[]; onPick: (ip: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <span className="relative inline-block">
      <Button mini onClick={() => setOpen((v) => !v)}>+ из списка</Button>
      {open && (
        <div className="absolute right-0 top-full z-10 mt-1 max-h-72 w-72 overflow-y-auto rounded-lg border border-line bg-panel p-1 text-xs shadow-lg">
          {devices.length === 0 ? <div className="px-2 py-1 text-muted">пусто</div> : devices.map((d) => (
            <button key={d.mac + d.ip} type="button" onClick={() => { onPick(d.ip); setOpen(false); }}
              className="block w-full rounded px-2 py-1 text-left hover:bg-line-soft">
              {d.hostname && <b className="text-ink">{d.hostname} </b>}
              <span className="font-mono">{d.ip}</span>
            </button>
          ))}
        </div>
      )}
    </span>
  );
}

function CopyFromServerModal({ st, onClose, onCopied }: { st: Awg2Status; onClose: () => void; onCopied: () => void | Promise<void> }) {
  const others = useMemo(() => (st.servers || []).filter((s) => s.id !== st.active_server_id), [st]);
  const [sel, setSel] = useState<string>(others[0]?.id || "");
  const [busy, setBusy] = useState(false);

  const run = async () => {
    if (!sel || busy) return;
    if (!(await confirmDialog({
      title: "Перезаписать правила?",
      body: "Текущие глобальные правила будут заменены правилами с выбранного подключения. Остальные настройки не трогаются.",
      confirmLabel: "Перезаписать",
      danger: true,
    }))) return;
    setBusy(true);
    try {
      await api("POST", "/api/awg2/routing/rules/copy", { from_server_id: sel });
      await onCopied();
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Скопировать правила с другого сервера" onClose={onClose} actions={
      <>
        <Button variant="ghost" onClick={onClose} disabled={busy}>Отмена</Button>
        <Button variant="primary" onClick={run} disabled={busy || !sel}>{busy ? "Копируем…" : "Перезаписать"}</Button>
      </>
    }>
      {others.length === 0 ? (
        <p className="text-xs text-muted">Других серверов нет — добавьте/импортируйте ещё один на вкладке «Сервер».</p>
      ) : (
        <Field label="Источник">
          <select value={sel} onChange={(e) => setSel(e.target.value)} className="w-full rounded border border-line bg-panel px-2 py-1.5 text-[13px]">
            {others.map((s) => (
              <option key={s.id} value={s.id}>{s.label || s.id} {s.endpoint ? `· ${s.endpoint}` : ""}</option>
            ))}
          </select>
        </Field>
      )}
    </Modal>
  );
}

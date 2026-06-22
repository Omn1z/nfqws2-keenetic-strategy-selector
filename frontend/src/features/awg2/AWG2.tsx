import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Modal } from "@/components/ui/Modal";
import { Field, Input, Select } from "@/components/ui/form";
import ServerPane from "./ServerPane";
import PeerShareModal from "./PeerShareModal";
import RoutingPane from "./RoutingPane";
import DevicesRoutingPane from "./DevicesRoutingPane";
import TracePane from "./TracePane";
import SpeedTestCard from "./SpeedTestCard";
import type { Awg2ServerSummary, Awg2Status, AwgClientStatus, AwgDeployResult } from "@/types/api";

type Sub = "server" | "routing" | "devices" | "trace";
type DeployOpts = { quiet?: boolean; skipReload?: boolean };

const human = (n: number) => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
};
const ago = (t: number) => {
  if (!t) return "нет";
  const s = Math.max(0, Math.floor(Date.now() / 1000) - t);
  return s < 60 ? `${s} с` : s < 3600 ? `${Math.floor(s / 60)} мин` : `${Math.floor(s / 3600)} ч`;
};

function MiniSpinner() {
  return <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-current border-r-transparent align-[-1px]" />;
}

function serverLine(srv: Awg2ServerSummary, deploying: boolean) {
  if (!srv.enabled) return { kind: "neutral" as const, label: "сервер выкл" };
  if (deploying) return { kind: "warn" as const, label: "деплой..." };
  if (srv.imported) return { kind: "ok" as const, label: srv.protocol === "wireguard" ? "WG import" : "AWG import" };
  if (!srv.deployed) return { kind: "neutral" as const, label: "черновик" };
  if (srv.reachable) return { kind: "ok" as const, label: "сервер online" };
  return { kind: "warn" as const, label: srv.last_error ? "сервер offline" : "статус ждёт" };
}

function tunnelLine(srv: Awg2ServerSummary, cl: AwgClientStatus | null) {
  if (!srv.enabled) return { kind: "neutral" as const, label: "туннель выкл" };
  if (!srv.active) return { kind: "neutral" as const, label: "туннель не выбран" };
  if (!cl?.running) return { kind: "neutral" as const, label: "туннель опущен" };
  if (cl.connected) return { kind: "ok" as const, label: "туннель connected" };
  return { kind: "warn" as const, label: "туннель поднят" };
}

/** «Сервисы → AWG2»: deploy an AmneziaWG 2.0 server on a VPS over SSH, hand out
 *  client configs, and (Routing tab) split-route LAN traffic through the tunnel. */
export default function AWG2() {
  const [sub, setSub] = useState<Sub>("server");
  const [st, setSt] = useState<Awg2Status | null>(null);
  const [deploying, setDeploying] = useState<Record<string, boolean>>({});
  const [toggling, setToggling] = useState<Record<string, boolean>>({});
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [batch, setBatch] = useState<{ done: number; total: number } | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [clientsOpen, setClientsOpen] = useState(false);
  const [newServer, setNewServer] = useState({ name: "", host: "", port: "22", user: "root", auth: "password", password: "" });
  const [creating, setCreating] = useState(false);

  usePoll(async () => {
    try {
      setSt(await api<Awg2Status>("GET", "/api/awg2"));
    } catch {
      /* keep last */
    }
  }, 2500);

  // Periodically refresh live server status (SSH `awg show`) while the tab is open,
  // plus once right after mount — otherwise `status` stays null and the card reads
  // «нет связи» even when the server is up.
  const stRef = useRef<Awg2Status | null>(st);
  stRef.current = st;
  useEffect(() => {
    const tick = () => { if (stRef.current?.deployed) void api("POST", "/api/awg2/status/refresh", {}).catch(() => {}); };
    tick();
    const id = window.setInterval(tick, 15000);
    return () => window.clearInterval(id);
  }, []);

  const reload = async () => {
    try {
      setSt(await api<Awg2Status>("GET", "/api/awg2"));
    } catch {
      /* ignore */
    }
  };

  const deployServer = async (id: string, opts: DeployOpts = {}) => {
    const srv = st?.servers?.find((s) => s.id === id);
    if (!srv) return false;
    if (!srv.enabled) {
      toast("Сервер выключен — включите его перед деплоем", "err");
      return false;
    }
    if (srv.imported) {
      toast("Это импортированный профиль: деплой на VPS недоступен, можно поднимать туннель", "err");
      return false;
    }
    if (deploying[id]) return false;
    setDeploying((m) => ({ ...m, [id]: true }));
    if (!opts.quiet) toast("Запущен деплой AWG2-сервера…", "ok");
    try {
      const d = await api<{ ok: boolean; result: AwgDeployResult; error?: string }>("POST", `/api/awg2/servers/${encodeURIComponent(id)}/deploy`, {});
      if (!opts.skipReload) await reload();
      if (!opts.quiet) {
        if (d.ok) toast("Сервер развёрнут", "ok");
        else toast("Деплой с ошибкой: " + (d.error || d.result?.error || "см. журнал"), "err");
      }
      return !!d.ok;
    } catch (e) {
      toast((e as Error).message, "err");
      return false;
    } finally {
      setDeploying((m) => ({ ...m, [id]: false }));
    }
  };

  const deploySelected = async () => {
    if (!st || batch) return;
    const ids = st.servers.filter((s) => selected[s.id] && s.enabled && !s.imported).map((s) => s.id);
    if (ids.length === 0) {
      toast("Выберите включённые VPS-серверы без imported-профилей", "err");
      return;
    }
    setBatch({ done: 0, total: ids.length });
    let ok = 0;
    for (let i = 0; i < ids.length; i++) {
      if (await deployServer(ids[i], { quiet: true, skipReload: true })) ok++;
      setBatch({ done: i + 1, total: ids.length });
      await reload();
    }
    setBatch(null);
    toast(`Деплой завершён: ${ok}/${ids.length}`, ok === ids.length ? "ok" : "err");
  };

  const addServer = async () => {
    if (creating) return;
    setCreating(true);
    try {
      let next = await api<Awg2Status>("POST", "/api/awg2/servers", { name: newServer.name.trim() });
      if (newServer.host.trim()) {
        next = await api<Awg2Status>("POST", "/api/awg2/config", {
          ...next.config,
          conn: {
            ...next.config.conn,
            host: newServer.host.trim(),
            port: parseInt(newServer.port, 10) || 22,
            user: newServer.user.trim() || "root",
            auth_kind: newServer.auth,
            password: newServer.auth === "password" ? newServer.password : "",
          },
        });
      }
      setSt(next);
      setSub("server");
      setAddOpen(false);
      setNewServer({ name: "", host: "", port: "22", user: "root", auth: "password", password: "" });
      toast("Сервер AWG2 добавлен", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setCreating(false);
    }
  };

  const selectServer = async (id: string) => {
    if (!id || id === st?.active_server_id) return;
    const srv = st?.servers?.find((s) => s.id === id);
    if (srv && !srv.enabled) {
      toast("Сервер выключен — включите его перед выбором", "err");
      return;
    }
    try {
      const next = await api<Awg2Status>("POST", `/api/awg2/servers/${encodeURIComponent(id)}/select`, {});
      setSt(next);
      setSub("server");
      toast("Сервер AWG2 выбран", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  const toggleServer = async (id: string, enabled: boolean) => {
    if (toggling[id]) return;
    setToggling((m) => ({ ...m, [id]: true }));
    try {
      const next = await api<Awg2Status>("POST", `/api/awg2/servers/${encodeURIComponent(id)}/enabled`, { enabled });
      setSt(next);
      toast(enabled ? "Сервер включён" : "Сервер выключен", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setToggling((m) => ({ ...m, [id]: false }));
    }
  };

  const deleteServer = async (id: string) => {
    if (!id) return;
    if (!(await confirmDialog({ title: "Удалить AWG2-сервер?", body: "Конфиг, ключи и пиры этого сервера будут удалены из панели. На самом VPS уже установленный сервис не трогается.", confirmLabel: "Удалить", danger: true }))) return;
    try {
      const next = await api<Awg2Status>("DELETE", `/api/awg2/servers/${encodeURIComponent(id)}`);
      setSt(next);
      setSub("server");
      toast("Сервер AWG2 удалён", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  const openClients = async (srv: Awg2ServerSummary) => {
    if (srv.imported) {
      toast("Imported-профиль подключает только этот роутер к чужому серверу — добавлять клиентов к нему нельзя", "err");
      return;
    }
    if (!srv.active) {
      try {
        setSt(await api<Awg2Status>("POST", `/api/awg2/servers/${encodeURIComponent(srv.id)}/select`, {}));
      } catch (e) {
        toast((e as Error).message, "err");
        return;
      }
    }
    setClientsOpen(true);
  };

  const seg = (m: Sub, label: string) => (
    <button
      type="button"
      onClick={() => setSub(m)}
      className={cn("border-r border-line px-4 py-1.5 text-[13px] outline-none transition last:border-r-0 focus-visible:relative focus-visible:ring-2 focus-visible:ring-ring/40", sub === m ? "bg-accent text-white" : "bg-panel text-ink-soft hover:bg-line-soft")}
    >
      {label}
    </button>
  );

  if (!st) return <Card><span className="text-xs text-muted">Загрузка…</span></Card>;

  const dep = st.last_deploy;
  const servers = st.servers ?? [];
  const activeServer = servers.find((s) => s.id === st.active_server_id) ?? servers.find((s) => s.active);
  const selectedIDs = servers.filter((s) => selected[s.id]).map((s) => s.id);
  const canDeploySelected = selectedIDs.some((id) => {
    const srv = servers.find((s) => s.id === id);
    return !!srv?.enabled && !srv.imported;
  });
  const importedActive = st.config.install === "imported";
  const statusKind = importedActive ? (st.client?.connected ? "ok" : st.client?.running ? "warn" : "neutral") : st.deployed ? (st.status?.up ? "ok" : "warn") : "neutral";
  const statusText = importedActive ? (st.client?.connected ? "imported · connected" : st.client?.running ? "imported · поднят" : "imported профиль") : st.deployed ? (st.status?.up ? "развёрнут" : "развёрнут (нет связи)") : "не развёрнут";

  return (
    <>
      <Card
        title="AWG2 — AmneziaWG 2.0 VPN"
        sub="свой VPS или imported .conf/.vpn + сплит-роутинг"
        head={
          <div className="flex flex-wrap items-center gap-2">
            <Badge kind={statusKind}>{statusText}</Badge>
            {st.client?.running && <Badge kind={st.client.connected ? "ok" : "warn"}>{st.client.connected ? "туннель connected" : "туннель поднят"}</Badge>}
          </div>
        }
      >
        <p className="text-xs text-muted">Разворачивает обфусцированный AmneziaWG 2.0 сервер на вашем VPS по SSH или подключает роутер к уже существующему AWG/WireGuard профилю. Деплой, подключение и маршрутизация — явные действия; роутер не перезагружается.</p>
        {dep && dep.steps?.length > 0 && (
          <div className="mt-3 rounded-lg border border-line bg-line-soft p-2.5">
            <div className="mb-1 text-[11px] font-semibold text-ink-soft">Последний деплой ({dep.method}{dep.wan_iface ? `, WAN ${dep.wan_iface}` : ""}):</div>
            <ul className="space-y-0.5">
              {dep.steps.map((s, i) => (
                <li key={i} className="flex gap-2 text-[11.5px]">
                  <span className={s.ok ? "text-ok" : "text-bad"}>{s.ok ? "✓" : "✗"}</span>
                  <span className="text-ink-soft">{s.name}</span>
                  {s.detail && <span className="text-muted [overflow-wrap:anywhere]">— {s.detail}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>

      <Card
        title="Серверы AWG2"
        sub="активный сервер владеет пирами, туннелем awg0 и маршрутизацией"
        head={<Button mini onClick={() => setAddOpen(true)}>Добавить сервер</Button>}
      >
        {selectedIDs.length > 0 && (
          <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-line bg-line-soft px-3 py-2">
            <span className="text-xs font-semibold text-ink-soft">Выбрано: {selectedIDs.length}</span>
            <Button mini variant="primary" onClick={deploySelected} disabled={!!batch || !canDeploySelected}>
              {batch ? `Деплой ${batch.done}/${batch.total}` : "Переразвернуть выбранные"}
            </Button>
            <Button mini variant="ghost" onClick={() => setSelected({})} disabled={!!batch}>Снять выбор</Button>
          </div>
        )}
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {servers.map((srv) => {
            const busy = !!deploying[srv.id];
            const sLine = serverLine(srv, busy);
            const tLine = tunnelLine(srv, st.client);
            return (
              <div
                key={srv.id}
                className={cn(
                  "min-h-[168px] rounded-lg border p-3 text-[12.5px] transition",
                  srv.active ? "border-primary bg-primary/10 text-foreground" : "border-line bg-panel text-ink-soft",
                  !srv.enabled && "opacity-70",
                  busy && "animate-pulse",
                )}
              >
                <div className="flex items-start gap-2">
                  <input
                    type="checkbox"
                    checked={!!selected[srv.id]}
                    onChange={(e) => setSelected((m) => ({ ...m, [srv.id]: e.target.checked }))}
                    className="mt-1"
                    aria-label="Выбрать сервер"
                  />
                  <button
                    type="button"
                    onClick={() => selectServer(srv.id)}
                    className="min-w-0 flex-1 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
                  >
                    <div className="flex min-h-6 items-center gap-2">
                      <span className="min-w-0 truncate text-[13px] font-semibold text-ink">{srv.label || srv.host || srv.id}</span>
                      {srv.active && <Badge kind="ok">активен</Badge>}
                    </div>
                    <div className="mt-0.5 truncate text-[11.5px] text-muted">{srv.endpoint || srv.host || "адрес не задан"}</div>
                  </button>
                  <Switch checked={!!srv.enabled} onChange={(v) => toggleServer(srv.id, v)} />
                </div>

                <div className="mt-3 flex flex-wrap gap-1.5">
                  <Badge kind={sLine.kind}>{busy && <MiniSpinner />} {sLine.label}</Badge>
                  <Badge kind={tLine.kind}>{tLine.label}</Badge>
                </div>
                {srv.active && st.client?.running && (
                  <div className="mt-2 text-[11.5px] text-muted">
                    Хендшейк: {ago(st.client.last_handshake)} назад · ↓ {human(st.client.rx_bytes)} / ↑ {human(st.client.tx_bytes)}
                  </div>
                )}
                {srv.last_error && <div className="mt-2 line-clamp-2 text-[11px] text-warn" title={srv.last_error}>{srv.last_error}</div>}
                {busy && (
                  <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-line">
                    <div className="h-full w-2/3 animate-pulse rounded-full bg-accent" />
                  </div>
                )}
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <Button mini onClick={() => deployServer(srv.id)} disabled={busy || !srv.enabled || srv.imported || !srv.host}>
                    {busy ? "Деплой..." : srv.deployed ? "Переразвернуть" : "Развернуть"}
                  </Button>
                  <Button mini onClick={() => { void openClients(srv); }} disabled={!srv.enabled || srv.imported}>
                    Добавить клиента
                  </Button>
                  {srv.imported && <span className="text-[11px] text-muted">без SSH-деплоя</span>}
                </div>
              </div>
            );
          })}
        </div>
        {activeServer && (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button mini variant="danger" onClick={() => deleteServer(activeServer.id)}>Удалить выбранный</Button>
            <span className="text-xs text-muted [overflow-wrap:anywhere]">{activeServer.endpoint || activeServer.host || "новый сервер без адреса"}</span>
          </div>
        )}
      </Card>

      <div className="mb-4 inline-flex overflow-hidden rounded-lg border border-line">
        {seg("server", "Сервер")}
        {seg("routing", "Маршрутизация")}
        {seg("devices", "Устройства")}
        {seg("trace", "Трассировка")}
      </div>

      {sub === "server" && <>
        <SpeedTestCard />
        <ServerPane st={st} reload={reload} deployActive={() => activeServer ? deployServer(activeServer.id) : Promise.resolve(false)} deploying={!!(activeServer && deploying[activeServer.id])} />
      </>}
      {sub === "routing" && <RoutingPane st={st} reload={reload} />}
      {sub === "devices" && <DevicesRoutingPane st={st} reload={reload} />}
      {sub === "trace" && <TracePane />}
      {clientsOpen && <PeerShareModal st={st} reload={reload} onClose={() => setClientsOpen(false)} />}
      {addOpen && (
        <Modal
          title="Добавить AWG2 сервер"
          onClose={() => setAddOpen(false)}
          size="lg"
          actions={<><Button onClick={() => setAddOpen(false)}>Отмена</Button><Button variant="primary" onClick={addServer} disabled={creating}>{creating ? "..." : "Добавить"}</Button></>}
        >
          <div className="space-y-3">
            <Field label="Название">
              <Input value={newServer.name} placeholder="Moscow VPS" onChange={(e) => setNewServer((s) => ({ ...s, name: e.target.value }))} />
            </Field>
            <div className="grid gap-3 sm:grid-cols-[minmax(180px,1fr)_90px]">
              <Field label="Адрес VPS">
                <Input value={newServer.host} placeholder="IP или домен" onChange={(e) => setNewServer((s) => ({ ...s, host: e.target.value }))} />
              </Field>
              <Field label="SSH">
                <Input type="number" value={newServer.port} onChange={(e) => setNewServer((s) => ({ ...s, port: e.target.value }))} />
              </Field>
            </div>
            <div className="grid gap-3 sm:grid-cols-[140px_150px_minmax(160px,1fr)]">
              <Field label="Пользователь">
                <Input value={newServer.user} onChange={(e) => setNewServer((s) => ({ ...s, user: e.target.value }))} />
              </Field>
              <Field label="Авторизация">
                <Select value={newServer.auth} onChange={(e) => setNewServer((s) => ({ ...s, auth: e.target.value }))}>
                  <option value="password">Пароль</option>
                  <option value="key">SSH-ключ позже</option>
                </Select>
              </Field>
              <Field label="Пароль SSH" hint="можно оставить пустым">
                <Input type="password" value={newServer.password} onChange={(e) => setNewServer((s) => ({ ...s, password: e.target.value }))} disabled={newServer.auth !== "password"} />
              </Field>
            </div>
            <p className="text-[11px] text-muted">Остальные параметры берутся автоматически. Тонкие настройки можно раскрыть во вкладке сервера.</p>
          </div>
        </Modal>
      )}
    </>
  );
}

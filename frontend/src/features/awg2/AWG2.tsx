import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { vpnEngineIssue, vpnProfileLabel } from "@/lib/awg";
import { usePoll } from "@/lib/hooks";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Modal } from "@/components/ui/Modal";
import { Dropzone } from "@/components/ui/Dropzone";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import ServerPane from "./ServerPane";
import PeerShareModal from "./PeerShareModal";
import RoutingPane from "./RoutingPane";
import DevicesRoutingPane from "./DevicesRoutingPane";
import TracePane from "./TracePane";
import { SpeedTestPanel } from "./SpeedTestCard";
import type { Awg2ServerSummary, Awg2Status, AwgClientStatus, AwgDeployResult, AwgRoutingConfig } from "@/types/api";

type Sub = "server" | "routing" | "devices" | "trace";
type DeployOpts = { quiet?: boolean; skipReload?: boolean };
type NewConnectionMode = "import" | "warp" | "selfhosted";

const emptyNewConnection = () => ({
  name: "",
  conf: "",
  warpEndpoint: "",
  host: "",
  port: "22",
  user: "root",
  auth: "password",
  password: "",
  trafficObfuscation: true,
});

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
  if (!srv.enabled) return { kind: "neutral" as const, label: "выкл" };
  if (deploying) return { kind: "warn" as const, label: "деплой..." };
  if (srv.imported) return { kind: "neutral" as const, label: "nossh" };
  if (!srv.deployed) return { kind: "neutral" as const, label: "черновик" };
  if (srv.reachable) return { kind: "ok" as const, label: "сервер online" };
  return { kind: "warn" as const, label: srv.last_error ? "сервер offline" : "VPS" };
}

function tunnelLine(srv: Awg2ServerSummary) {
  const cl = srv.client;
  if (!srv.enabled) return { kind: "neutral" as const, label: "туннель выкл" };
  if (cl?.recovering) return { kind: "warn" as const, label: "переподключение" };
  if (srv.connected) return { kind: "ok" as const, label: "connected" };
  if (!srv.deployed && !srv.imported) return { kind: "neutral" as const, label: "черновик" };
  if (!cl?.running) return { kind: "neutral" as const, label: "туннель опущен" };
  if (cl.connected) return { kind: "ok" as const, label: "туннель connected" };
  return { kind: "warn" as const, label: "туннель поднят" };
}

function RecoveryStatus({ client }: { client: AwgClientStatus }) {
  if (!client.recovering) return null;
  const wait = Math.max(0, (client.retry_at || 0) - Math.floor(Date.now() / 1000));
  return (
    <div className="mt-2 text-[11.5px] text-warn" role="status">
      <span><MiniSpinner /> Автовосстановление{client.retry_count ? ` · попыток: ${client.retry_count}` : ""}{wait > 0 ? ` · повтор через ${wait} с` : " · проверяем соединение"}</span>
      {client.recovery_error && <div className="mt-0.5 [overflow-wrap:anywhere]">{client.recovery_error}</div>}
    </div>
  );
}

/** «Сервисы → AmneziaWG»: deploy a VPN server on a VPS over SSH, hand out
 *  client configs, and (Routing tab) split-route LAN traffic through the tunnel. */
export default function AWG2() {
  const [sub, setSub] = useState<Sub>("server");
  const [st, setSt] = useState<Awg2Status | null>(null);
  const [statusError, setStatusError] = useState("");
  const [deploying, setDeploying] = useState<Record<string, boolean>>({});
  const [toggling, setToggling] = useState<Record<string, boolean>>({});
  const [selectingID, setSelectingID] = useState("");
  const [deletingID, setDeletingID] = useState("");
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [batch, setBatch] = useState<{ done: number; total: number } | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [newMode, setNewMode] = useState<NewConnectionMode>("import");
  const [renameServer, setRenameServer] = useState<Awg2ServerSummary | null>(null);
  const [renameName, setRenameName] = useState("");
  const [renaming, setRenaming] = useState(false);
  const [clientsOpen, setClientsOpen] = useState(false);
  const [newConn, setNewConn] = useState(emptyNewConnection);
  const [creating, setCreating] = useState(false);
  const [formatBusy, setFormatBusy] = useState(false);
  const [serverBusy, setServerBusy] = useState(false);
  const [routingBusy, setRoutingBusy] = useState(false);
  const [traceBusy, setTraceBusy] = useState(false);
  const traceTail = useRef<Promise<void>>(Promise.resolve());
  const tracePending = useRef(0);
  // Keep trace writes serialized across pane unmount/remount. A pending rule
  // insertion and its auto-record cleanup must finish before another edit.
  const runTraceMutation = useCallback((work: () => Promise<void>): Promise<void> => {
    tracePending.current++;
    setTraceBusy(true);
    const next = traceTail.current.then(work);
    traceTail.current = next.catch(() => {});
    return next.finally(() => {
      tracePending.current--;
      setTraceBusy(tracePending.current > 0);
    });
  }, []);
  const [reconnectRevision, setReconnectRevision] = useState(0);
  const initialRoutingRevision = useRef<number | null>(null);
  const lastConfirmedRoutingRevision = useRef(0);
  const [speedServer, setSpeedServer] = useState<Awg2ServerSummary | null>(null);
  const statusEpoch = useRef(0);
  const statusRequest = useRef(0);
  const otherMutationBusy = creating || renaming || !!selectingID || !!deletingID || !!batch || formatBusy || serverBusy || routingBusy ||
    Object.values(deploying).some(Boolean) || Object.values(toggling).some(Boolean);
  const mutationBusy = otherMutationBusy || traceBusy;

  const acceptStatus = (next: Awg2Status) => {
    // An earlier GET must never overwrite the response of a completed mutation.
    statusEpoch.current++;
    setSt(next);
    setStatusError("");
  };
  const acceptRouting = (routing: AwgRoutingConfig) => {
    statusEpoch.current++;
    setSt((previous) => previous ? { ...previous, routing_config: routing, routing_rules: routing.zones,
      config: { ...previous.config, routing } } : previous);
    setStatusError("");
  };
  const reload = async (signal?: AbortSignal) => {
    const request = ++statusRequest.current;
    const epoch = statusEpoch.current;
    try {
      const next = await api<Awg2Status>("GET", "/api/awg2", undefined, { signal });
      if (!signal?.aborted && request === statusRequest.current && epoch === statusEpoch.current) {
        setSt(next);
        setStatusError("");
      }
    } catch (e) {
      /* Keep the last complete snapshot; the next poll can recover. */
      if (!signal?.aborted && request === statusRequest.current && epoch === statusEpoch.current) setStatusError((e as Error).message);
    }
  };

  usePoll(reload, 2500, !mutationBusy);
  const routingState = st?.routing_state;
  useEffect(() => {
    if (!routingState) return;
    if (initialRoutingRevision.current === null || routingState.revision < lastConfirmedRoutingRevision.current) {
      // Initial loading and a service restart are not a user routing change.
      initialRoutingRevision.current = routingState.revision;
      lastConfirmedRoutingRevision.current = routingState.revision;
      setReconnectRevision(0);
      return;
    }
    if (!routingState.ready || routingState.applying || routingState.revision <= 0) return;
    if (routingState.revision > initialRoutingRevision.current && routingState.revision > lastConfirmedRoutingRevision.current) {
      lastConfirmedRoutingRevision.current = routingState.revision;
      setReconnectRevision(routingState.revision);
    }
  }, [routingState?.revision, routingState?.ready, routingState?.applying]);

  // Periodically refresh live server status (SSH `awg show`) while the tab is open,
  // plus once right after mount — otherwise `status` stays null and the card reads
  // «нет связи» even when the server is up.
  const stRef = useRef<Awg2Status | null>(st);
  stRef.current = st;
  usePoll(async (signal) => {
    const cur = stRef.current;
    if (cur?.deployed && cur.config.install !== "imported") {
      await api("POST", "/api/awg2/status/refresh", {}, { signal, timeoutMs: 30_000 });
    }
  }, 15000, !mutationBusy);

  const openRename = (srv: Awg2ServerSummary) => {
    setRenameServer(srv);
    setRenameName(srv.label || "");
  };

  const submitRename = async () => {
    if (!renameServer || mutationBusy) return;
    setRenaming(true);
    try {
      const next = await api<Awg2Status>("POST", `/api/awg2/servers/${encodeURIComponent(renameServer.id)}/rename`, { name: renameName.trim() });
      acceptStatus(next);
      setRenameServer(null);
      toast("Имя подключения сохранено", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setRenaming(false);
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
    const desired = st?.active_server_id === srv.id ? st.config : srv;
    const engineIssue = st && vpnEngineIssue(st.engine, desired.traffic_obfuscation !== false && (desired.protocol_version === "3.1" || srv.protocol_version === "3.1"));
    if (engineIssue) { toast(engineIssue, "err"); return false; }
    if (deploying[id]) return false;
    setDeploying((m) => ({ ...m, [id]: true }));
    if (!opts.quiet) toast("Запущено развёртывание VPN-сервера…", "ok");
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
    if (!st || mutationBusy) return;
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

  const closeNewConnection = () => {
    if (creating) return;
    setAddOpen(false);
    setNewMode("import");
    setNewConn(emptyNewConnection());
  };

  const autoRaiseActiveTunnel = async (success: string) => {
    let started = false;
    try {
      await api("POST", "/api/awg2/client/up", {});
      started = true;
    } catch (e) {
      toast("Подключение создано, но туннель не поднялся: " + (e as Error).message, "err");
    }
    const next = await api<Awg2Status>("GET", "/api/awg2");
    if (started) toast(success, "ok");
    return next;
  };

  const submitNewConnection = async () => {
    if (mutationBusy) return;
    if (newMode === "selfhosted" && st) {
      const issue = vpnEngineIssue(st.engine, newConn.trafficObfuscation);
      if (issue) { toast(issue, "err"); return; }
    }
    setCreating(true);
    try {
      let next: Awg2Status;
      if (newMode === "import") {
        if (!newConn.conf.trim()) {
          toast("Вставьте .conf/.vpn или выберите файл", "err");
          return;
        }
        next = await api<Awg2Status>("POST", "/api/awg2/import", { conf: newConn.conf, name: newConn.name.trim() });
        next = await autoRaiseActiveTunnel("Подключение добавлено, VPN на роутере запущен");
      } else if (newMode === "warp") {
        next = await api<Awg2Status>("POST", "/api/awg2/warp", {
          name: newConn.name.trim() || "Cloudflare WARP",
          endpoint: newConn.warpEndpoint.trim(),
          accept_tos: true,
        });
        next = await autoRaiseActiveTunnel("WARP создан, VPN на роутере запущен");
      } else {
        if (!newConn.name.trim()) {
          toast("Укажите имя self-hosted сервера", "err");
          return;
        }
        if (!newConn.host.trim()) {
          toast("Укажите адрес VPS", "err");
          return;
        }
        next = await api<Awg2Status>("POST", "/api/awg2/servers", { name: newConn.name.trim() });
        next = await api<Awg2Status>("POST", "/api/awg2/config", {
          ...next.config,
          protocol_version: "3.1",
          traffic_obfuscation: newConn.trafficObfuscation,
          conn: {
            ...next.config.conn,
            host: newConn.host.trim(),
            port: parseInt(newConn.port, 10) || 22,
            user: newConn.user.trim() || "root",
            auth_kind: newConn.auth,
            password: newConn.auth === "password" ? newConn.password : "",
          },
        });
        const id = next.active_server_id;
        setDeploying((m) => ({ ...m, [id]: true }));
        let d: { ok: boolean; result: AwgDeployResult; error?: string } = { ok: false, result: {} as AwgDeployResult };
        try {
          d = await api<{ ok: boolean; result: AwgDeployResult; error?: string }>("POST", `/api/awg2/servers/${encodeURIComponent(id)}/deploy`, {});
        } finally {
          setDeploying((m) => ({ ...m, [id]: false }));
        }
        next = await api<Awg2Status>("GET", "/api/awg2");
        if (d.ok) {
          next = await autoRaiseActiveTunnel("Сервер развёрнут, VPN на роутере запущен");
        } else {
          toast("Self-hosted подключение создано, но deploy завершился с ошибкой: " + (d.error || d.result?.error || "см. журнал"), "err");
        }
      }
      acceptStatus(next);
      setAddOpen(false);
      setNewMode("import");
      setNewConn(emptyNewConnection());
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setCreating(false);
    }
  };

  const onImportFiles = (files: FileList) => {
    const f = files.item(0);
    if (!f) return;
    void f.text().then((text) => {
      setNewConn((s) => ({
        ...s,
        conf: text,
        name: s.name.trim() ? s.name : f.name.replace(/\.(conf|vpn|txt)$/i, ""),
      }));
    }).catch((e) => toast((e as Error).message, "err"));
  };

  const selectServer = async (id: string) => {
    if (!id) return;
    if (id === st?.active_server_id) {
      setSub("server");
      return;
    }
    if (mutationBusy) return;
    setSelectingID(id);
    try {
      const next = await api<Awg2Status>("POST", `/api/awg2/servers/${encodeURIComponent(id)}/select`, {});
      toast("Открыты настройки подключения", "ok");
      acceptStatus(next);
      setSub("server");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setSelectingID("");
    }
  };

  const toggleServer = async (id: string, enabled: boolean) => {
    if (mutationBusy) return;
    setToggling((m) => ({ ...m, [id]: true }));
    try {
      const next = await api<Awg2Status>("POST", `/api/awg2/servers/${encodeURIComponent(id)}/enabled`, { enabled });
      acceptStatus(next);
      toast(enabled ? "Подключение включено, туннель поднимается" : "Подключение выключено", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setToggling((m) => ({ ...m, [id]: false }));
    }
  };

  const deleteServer = async (id: string) => {
    if (!id || mutationBusy) return;
    if (!(await confirmDialog({ title: "Удалить VPN-подключение?", body: "Конфиг, ключи и пиры этого сервера будут удалены из панели. На самом VPS уже установленный сервис не трогается.", confirmLabel: "Удалить", danger: true }))) return;
    setDeletingID(id);
    try {
      const next = await api<Awg2Status>("DELETE", `/api/awg2/servers/${encodeURIComponent(id)}`);
      acceptStatus(next);
      toast("VPN-подключение удалено", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setDeletingID("");
    }
  };

  const openClients = async (srv: Awg2ServerSummary) => {
    if (mutationBusy) return;
    if (srv.imported) {
      toast("Imported-профиль подключает только этот роутер к чужому серверу — добавлять клиентов к нему нельзя", "err");
      return;
    }
    if (!srv.active) {
      setSelectingID(srv.id);
      try {
        acceptStatus(await api<Awg2Status>("POST", `/api/awg2/servers/${encodeURIComponent(srv.id)}/select`, {}));
      } catch (e) {
        toast((e as Error).message, "err");
        return;
      } finally {
        setSelectingID("");
      }
    }
    setClientsOpen(true);
  };

  const seg = (m: Sub, label: string) => (
    <button
      type="button"
      disabled={formatBusy || (m === "trace" && otherMutationBusy)}
      onClick={() => setSub(m)}
      className={cn("border-r border-line px-4 py-1.5 text-[13px] outline-none transition last:border-r-0 focus-visible:relative focus-visible:ring-2 focus-visible:ring-ring/40 disabled:cursor-not-allowed disabled:opacity-50", sub === m ? "bg-accent text-primary-foreground" : "bg-panel text-ink-soft hover:bg-line-soft")}
    >
      {label}
    </button>
  );

  if (!st) return <Card><span className="text-xs text-muted">{statusError || "Загрузка…"}</span>{statusError && <Button mini className="ml-2" onClick={() => { void reload(); }}>Повторить</Button>}</Card>;

  const dep = st.last_deploy;
  const servers = st.servers ?? [];
  const activeServer = servers.find((s) => s.id === st.active_server_id) ?? servers.find((s) => s.active);
  const connectedCount = servers.filter((s) => s.connected).length;
  const enabledCount = servers.filter((s) => s.enabled).length;
  const selectedIDs = servers.filter((s) => selected[s.id]).map((s) => s.id);
  const canDeploySelected = selectedIDs.some((id) => {
    const srv = servers.find((s) => s.id === id);
    return !!srv?.enabled && !srv.imported;
  });
  const statusKind = connectedCount > 0 ? "ok" : enabledCount > 0 ? "warn" : "neutral";
  const statusText = enabledCount > 0 ? `${connectedCount}/${enabledCount} туннелей connected` : "туннели выключены";
  const newConnectionSubmitLabel =
    newMode === "import" ? "Добавить подключение" :
    newMode === "warp" ? "Создать WARP" :
    "Развернуть сервер";
  const newEngineIssue = newMode === "selfhosted" ? vpnEngineIssue(st.engine, newConn.trafficObfuscation) : "";

  return (
    <>
      {statusError && <Card><p className="text-xs text-warn" role="status">Статус временно недоступен: {statusError} Показаны последние полученные данные.</p><Button mini className="mt-2" disabled={mutationBusy} onClick={() => { void reload(); }}>Обновить статус</Button></Card>}
      {(routingState?.applying || routingState?.error || (routingState && routingState.revision > 0 && !routingState.ready) || reconnectRevision > 0) && (
        <Card title="Состояние маршрутизации">
          {routingState?.applying
            ? <p className="text-xs text-muted" role="status"><MiniSpinner /> Настройки применяются: подготавливаем DNS и маршруты.</p>
            : routingState?.error
            ? <p className="text-xs text-bad" role="alert">Не удалось подготовить маршруты: {routingState.error}</p>
            : routingState && routingState.revision > 0 && !routingState.ready
            ? <p className="text-xs text-warn" role="status">Готовность маршрутов пока не подтверждена.</p>
            : reconnectRevision > 0 && <p className="text-xs text-ink-soft" role="status">Маршруты применены. Открытые соединения нужно переподключить: перезагрузите уже открытый сайт или повторно подключите приложение.</p>}
          {reconnectRevision > 0 && !routingState?.applying && routingState?.ready && <Button mini className="mt-2" onClick={() => setReconnectRevision(0)}>Понятно</Button>}
        </Card>
      )}
      <Card
        title="AmneziaWG VPN"
        sub="свой VPS или imported .conf/.vpn + сплит-роутинг"
        head={
          <div className="flex flex-wrap items-center gap-2">
            <Badge kind={statusKind}>{statusText}</Badge>
            <Badge kind={st.engine.update_available ? "warn" : st.engine.installed ? "ok" : "neutral"}>{st.engine.update_available ? "доступен новый движок" : st.engine.awg3_supported ? "движок AWG 3.1" : st.engine.installed ? "движок установлен" : "движок не установлен"}</Badge>
            {st.engine.update_available && <Button mini onClick={() => setSub("routing")} disabled={formatBusy}>Обновить движок</Button>}
          </div>
        }
      >
        <p className="text-xs text-muted">Разворачивает VPN-сервер на вашем VPS по SSH или подключает роутер к существующему профилю AmneziaWG, WireGuard или WARP.</p>
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
        title="VPN-подключения"
        sub="self-hosted, WARP и импортированные подключения"
        head={<Button mini onClick={() => setAddOpen(true)} disabled={mutationBusy}>Новое подключение</Button>}
      >
        {selectedIDs.length > 0 && (
          <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-line bg-line-soft px-3 py-2">
            <span className="text-xs font-semibold text-ink-soft">Выбрано: {selectedIDs.length}</span>
            <Button mini variant="primary" onClick={deploySelected} disabled={mutationBusy || !canDeploySelected}>
              {batch ? `Деплой ${batch.done}/${batch.total}` : "Переразвернуть выбранные"}
            </Button>
            <Button mini variant="ghost" onClick={() => setSelected({})} disabled={!!batch}>Снять выбор</Button>
          </div>
        )}
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {servers.map((srv) => {
            const busy = !!deploying[srv.id];
            const sLine = serverLine(srv, busy);
            const tLine = tunnelLine(srv);
            const cl = srv.client;
            return (
              <div
                key={srv.id}
                className={cn(
                  "min-h-[168px] rounded-lg border border-line bg-panel p-3 text-[12.5px] text-ink-soft transition",
                  !srv.enabled && "opacity-70",
                  busy && "animate-pulse",
                )}
              >
                <div className="flex items-start gap-2">
                  <input
                    type="checkbox"
                    checked={!!selected[srv.id]}
                    onClick={(e) => e.stopPropagation()}
                    onChange={(e) => setSelected((m) => ({ ...m, [srv.id]: e.target.checked }))}
                    className="mt-1"
                    aria-label="Выбрать сервер"
                  />
                  <div className="min-w-0 flex-1 text-left">
                    <div className="flex min-h-6 items-center gap-2">
                      <button
                        type="button"
                        disabled={mutationBusy}
                        title="Переименовать"
                        onClick={(e) => { e.stopPropagation(); openRename(srv); }}
                        className="min-w-0 max-w-full truncate text-left text-[13px] font-semibold text-ink outline-none transition hover:text-accent focus-visible:ring-2 focus-visible:ring-ring/40"
                      >
                        {srv.label || srv.host || srv.id}
                      </button>
                      {selectingID === srv.id && <Badge kind="warn"><MiniSpinner /> настройки</Badge>}
                    </div>
                    <div className="mt-0.5 truncate text-[11.5px] text-muted">{srv.endpoint || srv.host || "адрес не задан"}{srv.client_iface ? ` · ${srv.client_iface}` : ""}</div>
                  </div>
                  <span onClick={(e) => e.stopPropagation()}>
                    <Switch checked={!!srv.enabled} onChange={(v) => toggleServer(srv.id, v)} disabled={mutationBusy} aria-label={`VPN-подключение «${srv.label || srv.id}» включено`} />
                  </span>
                </div>

                <div className="mt-3 flex flex-wrap gap-1.5">
                  <Badge kind={sLine.kind}>{busy && <MiniSpinner />} {sLine.label}</Badge>
                  <Badge kind={tLine.kind}>{tLine.label}</Badge>
                  <Badge kind="neutral">{srv.deployment_pending ? "Последний успешный: " : ""}{vpnProfileLabel(srv)}</Badge>
                  {srv.deployment_pending && <Badge kind="warn">изменения не развёрнуты</Badge>}
                  {!srv.is_warp && srv.protocol !== "wireguard" && srv.traffic_obfuscation === false && <Badge kind="neutral">обфускация выкл.</Badge>}
                </div>
                {cl?.running && (
                  <div className="mt-2 text-[11.5px] text-muted">
                    Хендшейк: {ago(cl.last_handshake)} назад · ↓ {human(cl.rx_bytes)} / ↑ {human(cl.tx_bytes)} · MTU {cl.mtu || "—"}
                  </div>
                )}
                {srv.enabled && cl && <RecoveryStatus client={cl} />}
                {srv.deployment_pending && <p className="mt-2 text-[11.5px] text-warn">Роутер и экспорт используют последнюю успешно развёрнутую конфигурацию. Завершите развёртывание в настройках.</p>}
                {srv.last_error && <div className="mt-2 line-clamp-2 text-[11px] text-warn" title={srv.last_error}>{srv.last_error}</div>}
                {busy && (
                  <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-line">
                    <div className="h-full w-2/3 animate-pulse rounded-full bg-accent" />
                  </div>
                )}
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <Button mini variant="primary" onClick={() => { void selectServer(srv.id); }} disabled={mutationBusy}>
                    Настройки
                  </Button>
                  <Button mini onClick={(e) => { e.stopPropagation(); void deployServer(srv.id); }} disabled={mutationBusy || busy || !srv.enabled || srv.imported || !srv.host}>
                    {busy ? "Деплой..." : srv.deployed ? "Переразвернуть" : "Развернуть"}
                  </Button>
                  <Button mini onClick={(e) => { e.stopPropagation(); void openClients(srv); }} disabled={mutationBusy || !srv.enabled || srv.imported}>
                    {srv.deployment_pending ? "Клиенты и экспорт" : "Добавить клиента"}
                  </Button>
                  <Button mini onClick={(e) => { e.stopPropagation(); setSpeedServer(srv); }} disabled={mutationBusy || !srv.client_iface || !srv.client?.running}>
                    Замер
                  </Button>
                  <Button mini variant="danger" onClick={(e) => { e.stopPropagation(); void deleteServer(srv.id); }} disabled={mutationBusy}>
                    Удалить
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      <div className="mb-4 inline-flex overflow-hidden rounded-lg border border-line">
        {seg("server", "Сервер")}
        {seg("routing", "Маршрутизация")}
        {seg("devices", "Устройства")}
        {seg("trace", "Трассировка")}
      </div>

      <div hidden={sub !== "server"} className="space-y-4">
        <ServerPane st={st} reload={reload} acceptStatus={acceptStatus} deployActive={() => activeServer ? deployServer(activeServer.id) : Promise.resolve(false)} deploying={!!(activeServer && deploying[activeServer.id])} onFormatBusyChange={setFormatBusy} onBusyChange={setServerBusy} externalBusy={mutationBusy} onOpenEngineSettings={() => setSub("routing")} />
      </div>
      <div hidden={sub !== "routing"} className="space-y-4">
        <RoutingPane st={st} reload={reload} visible={sub === "routing"} onBusyChange={setRoutingBusy} externalBusy={mutationBusy} acceptRouting={acceptRouting} />
      </div>
      <div hidden={sub !== "devices"}>
        <DevicesRoutingPane st={st} reload={reload} active={sub === "devices"} onBusyChange={setRoutingBusy} externalBusy={mutationBusy} />
      </div>
      {sub === "trace" && <fieldset disabled={mutationBusy}><TracePane externalBusy={mutationBusy} runMutation={runTraceMutation} reload={reload} /></fieldset>}
      {clientsOpen && <PeerShareModal st={st} reload={reload} onClose={() => setClientsOpen(false)} />}
      {speedServer && (
        <Modal
          title={`Замер скорости: ${speedServer.label || speedServer.host || speedServer.id}`}
          onClose={() => setSpeedServer(null)}
          size="lg"
        >
          <SpeedTestPanel
            serverLabel={speedServer.label || speedServer.host || speedServer.id}
            tunnelIface={speedServer.client_iface || ""}
          />
        </Modal>
      )}
      {renameServer && (
        <Modal
          title="Переименовать подключение"
          onClose={() => !renaming && setRenameServer(null)}
          actions={<><Button onClick={() => setRenameServer(null)} disabled={renaming}>Отмена</Button><Button variant="primary" onClick={submitRename} disabled={mutationBusy}>{renaming ? "..." : "Сохранить"}</Button></>}
        >
          <Field label="Название">
            <Input value={renameName} autoFocus onChange={(e) => setRenameName(e.target.value)} />
          </Field>
        </Modal>
      )}
      {addOpen && (
        <Modal
          title="Новое подключение"
          onClose={closeNewConnection}
          size="lg"
          actions={<><Button onClick={closeNewConnection} disabled={creating}>Отмена</Button><Button variant="primary" onClick={submitNewConnection} disabled={mutationBusy || !!newEngineIssue}>{creating ? "..." : newConnectionSubmitLabel}</Button></>}
        >
          <div className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-3">
              {([
                ["import", "Существующий сервер"],
                ["warp", "Создать WARP подключение"],
                ["selfhosted", "Развернуть сервер (Self Hosted)"],
              ] as const).map(([mode, label]) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setNewMode(mode)}
                  className={cn(
                    "min-h-[58px] rounded-lg border px-3 py-2 text-left text-[13px] font-semibold outline-none transition focus-visible:ring-2 focus-visible:ring-ring/40",
                    newMode === mode ? "border-primary bg-primary/10 text-ink" : "border-line bg-panel text-ink-soft hover:border-accent",
                  )}
                >
                  {label}
                </button>
              ))}
            </div>

            <Field label="Название">
              <Input
                value={newConn.name}
                placeholder={newMode === "warp" ? "Cloudflare WARP" : newMode === "selfhosted" ? "Moscow VPS" : "AWG Moscow / WireGuard Home"}
                onChange={(e) => setNewConn((s) => ({ ...s, name: e.target.value }))}
              />
            </Field>

            {newMode === "import" && (
              <div className="grid gap-3 lg:grid-cols-[minmax(220px,0.8fr)_minmax(280px,1.2fr)]">
                <Dropzone accept=".conf,.vpn,.txt" onFiles={onImportFiles}>
                  <div className="text-sm font-semibold">Выберите .conf/.vpn</div>
                  <div className="mt-1 text-xs text-muted">или перетащите файл сюда</div>
                </Dropzone>
                <Field label="Содержимое .conf/.vpn">
                  <Textarea
                    rows={9}
                    value={newConn.conf}
                    placeholder={"[Interface]\nPrivateKey = ...\nAddress = ...\n\n[Peer]\nPublicKey = ...\nEndpoint = host:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n\nили vpn://..."}
                    onChange={(e) => setNewConn((s) => ({ ...s, conf: e.target.value }))}
                  />
                </Field>
              </div>
            )}

            {newMode === "warp" && (
              <Field label="Endpoint">
                <Input
                  value={newConn.warpEndpoint}
                  placeholder="auto"
                  onChange={(e) => setNewConn((s) => ({ ...s, warpEndpoint: e.target.value }))}
                />
              </Field>
            )}

            {newMode === "selfhosted" && (
              <>
                <div className="rounded-lg border border-line bg-line-soft p-3">
                  <Switch checked={newConn.trafficObfuscation} onChange={(v) => setNewConn((s) => ({ ...s, trafficObfuscation: v }))} disabled={creating} label="Обфускация трафика" />
                  <p className="mt-2 text-xs text-muted">{newConn.trafficObfuscation
                    ? "Создаст сервер AWG 3.1 с автоматическими настройками обфускации и подключит роутер. Для других устройств потребуется клиент с поддержкой AWG 3.1."
                    : "Создаст сервер с обычным форматом WireGuard. Шифрование VPN остаётся включённым."}</p>
                </div>
                {newEngineIssue && <div className="rounded-lg bg-warn-bg px-3 py-2 text-xs text-warn"><p>{newEngineIssue}</p><Button mini className="mt-2" onClick={() => { setAddOpen(false); setSub("routing"); }} disabled={creating}>Настройки движка</Button></div>}
                <div className="grid gap-3 sm:grid-cols-[minmax(180px,1fr)_90px]">
                  <Field label="Адрес VPS">
                    <Input value={newConn.host} placeholder="IP или домен" onChange={(e) => setNewConn((s) => ({ ...s, host: e.target.value }))} />
                  </Field>
                  <Field label="SSH">
                    <Input type="number" value={newConn.port} onChange={(e) => setNewConn((s) => ({ ...s, port: e.target.value }))} />
                  </Field>
                </div>
                <div className="grid gap-3 sm:grid-cols-[140px_150px_minmax(160px,1fr)]">
                  <Field label="Пользователь">
                    <Input value={newConn.user} onChange={(e) => setNewConn((s) => ({ ...s, user: e.target.value }))} />
                  </Field>
                  <Field label="Авторизация">
                    <Select value={newConn.auth} onChange={(e) => setNewConn((s) => ({ ...s, auth: e.target.value }))}>
                      <option value="password">Пароль</option>
                      <option value="key">SSH-ключ позже</option>
                    </Select>
                  </Field>
                  <Field label="Пароль SSH" hint="можно оставить пустым">
                    <Input type="password" value={newConn.password} onChange={(e) => setNewConn((s) => ({ ...s, password: e.target.value }))} disabled={newConn.auth !== "password"} />
                  </Field>
                </div>
              </>
            )}
          </div>
        </Modal>
      )}
    </>
  );
}

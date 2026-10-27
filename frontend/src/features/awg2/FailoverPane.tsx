import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Switch } from "@/components/ui/Switch";
import { Field, Select } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";
import type { Awg2ServerSummary, Awg2Status, AwgConnectionTestResult } from "@/types/api";
import { backupCreatesCycle, backupIDs, connectionTestPresentation, moveBackup } from "./failoverModel";

type TestResult = AwgConnectionTestResult & { request_error?: boolean };

export function ConnectionTestResult({ result }: { result: TestResult }) {
  const presentation = connectionTestPresentation(result);
  return <div className="mt-2 space-y-1 text-xs [overflow-wrap:anywhere]" role="status">
    <Badge kind={result.request_error ? "warn" : presentation.kind}>{result.request_error ? "Проверка не завершена" : presentation.label}</Badge>
    {!result.request_error && <p className="text-muted">Handshake: {result.handshake ? "есть" : "не подтверждён"} · Данные: {result.data_ok ? "получены" : "не подтверждены"}{result.latency_ms > 0 ? ` · ${Math.round(result.latency_ms)} мс` : ""}</p>}
    {result.egress_ip && <p className="text-muted">Внешний IP: <span className="font-mono">{result.egress_ip}</span></p>}
    {result.endpoint && <p className="text-muted">Endpoint: <span className="font-mono">{result.endpoint}</span></p>}
    {result.error && <p className="text-warn">{result.error}</p>}
    {result.checked_at > 0 && <p className="text-muted">Проверено: <time dateTime={new Date(result.checked_at * 1000).toISOString()}>{new Date(result.checked_at * 1000).toLocaleString("ru-RU")}</time></p>}
  </div>;
}

export function ConnectionFailoverBadge({ server, servers }: { server: Awg2ServerSummary; servers: Awg2ServerSummary[] }) {
  const status = server.failover;
  if (!status) return null;
  if (status.standby && !status.activated) return <Badge kind="neutral">резерв · ожидание</Badge>;
  if (status.standby && status.activated) return <Badge kind="warn">резерв задействован</Badge>;
  if (status.active_tunnel_id && status.active_tunnel_id !== server.id) {
    const selected = servers.find((candidate) => candidate.id === status.active_tunnel_id);
    return <Badge kind="warn">через резерв: {selected?.label || status.active_tunnel_id}</Badge>;
  }
  if (status.fallback_tunnel_ids?.length) return <Badge kind="neutral">резервов: {status.fallback_tunnel_ids.length}</Badge>;
  return null;
}

interface Props {
  st: Awg2Status;
  acceptStatus: (next: Awg2Status) => void;
  reload: () => Promise<void>;
  onBusyChange: (busy: boolean) => void;
  externalBusy: boolean;
}

export default function FailoverPane({ st, acceptStatus, reload, onBusyChange, externalBusy }: Props) {
  const id = st.active_server_id;
  const server = st.servers.find((candidate) => candidate.id === id);
  const savedIDs = backupIDs(id, st.config.client.fallback_tunnel_ids ?? []);
  const [ids, setIDs] = useState(savedIDs);
  const [standby, setStandby] = useState(!!st.config.client.standby);
  const [editing, setEditing] = useState(false);
  const [candidateIDs, setCandidateIDs] = useState<string[]>([]);
  const [operation, setOperation] = useState("");
  const [testingID, setTestingID] = useState("");
  const testController = useRef<AbortController | null>(null);
  const [results, setResults] = useState<Record<string, TestResult>>({});
  const ownBusy = !!operation;
  const busy = ownBusy || externalBusy;
  const dirty = JSON.stringify(ids) !== JSON.stringify(savedIDs) || standby !== !!st.config.client.standby;
  const savedKey = JSON.stringify([savedIDs, st.config.client.standby]);
  useEffect(() => { onBusyChange(ownBusy); }, [ownBusy, onBusyChange]);
  useEffect(() => () => { testController.current?.abort(); onBusyChange(false); }, [onBusyChange]);
  // Polling must not discard an unfinished priority edit.
  useEffect(() => {
    if (!editing && !ownBusy) {
      setIDs(savedIDs);
      setStandby(!!st.config.client.standby);
    }
  }, [savedKey, editing, ownBusy]);

  const candidates = st.servers.filter((candidate) => candidate.id !== id && !ids.includes(candidate.id) && !backupCreatesCycle(id, candidate.id, st.servers));
  const selectedCandidates = candidateIDs.filter((candidateID) => candidates.some((candidate) => candidate.id === candidateID));
  const add = () => {
    if (busy || !selectedCandidates.length) return;
    setEditing(true);
    setIDs(backupIDs(id, [...ids, ...selectedCandidates]));
    setCandidateIDs([]);
  };
  const save = async () => {
    if (busy) return;
    setOperation("save");
    try {
      const next = await api<Awg2Status>("POST", `/api/awg2/servers/${encodeURIComponent(id)}/failover`, { fallback_tunnel_ids: ids, standby });
      acceptStatus(next);
      setIDs(backupIDs(id, next.config.client.fallback_tunnel_ids ?? []));
      setStandby(!!next.config.client.standby);
      setEditing(false);
      toast("Резервные подключения сохранены", "ok");
    } catch (error) {
      toast((error as Error).message, "err");
    } finally {
      setOperation("");
    }
  };
  const setReserveStandby = async (reserve: Awg2ServerSummary, value: boolean) => {
    if (busy) return;
    setOperation(`standby:${reserve.id}`);
    try {
      const next = await api<Awg2Status>("POST", `/api/awg2/servers/${encodeURIComponent(reserve.id)}/failover`, {
        fallback_tunnel_ids: reserve.failover?.fallback_tunnel_ids ?? [], standby: value,
      });
      acceptStatus(next);
      toast(value ? "Резерв ожидает сбоя основного подключения" : "Подключение работает самостоятельно", "ok");
    } catch (error) {
      toast((error as Error).message, "err");
    } finally {
      setOperation("");
    }
  };
  const testConnections = async (testIDs: string[]) => {
    if (busy) return;
    const controller = new AbortController();
    testController.current = controller;
    setOperation("test");
    try {
      for (const testID of testIDs) {
        setTestingID(testID);
        setResults((previous) => { const next = { ...previous }; delete next[testID]; return next; });
        try {
          const result = await api<AwgConnectionTestResult>("POST", `/api/awg2/servers/${encodeURIComponent(testID)}/test`, {}, { timeoutMs: 60_000, signal: controller.signal });
          setResults((previous) => ({ ...previous, [testID]: result }));
        } catch (error) {
          setResults((previous) => ({ ...previous, [testID]: {
            server_id: testID, success: false, handshake: false, data_ok: false, latency_ms: 0, request_error: true,
            endpoint: st.servers.find((candidate) => candidate.id === testID)?.endpoint ?? "", error: controller.signal.aborted ? "Проверка отменена" : (error as Error).message, checked_at: Math.floor(Date.now() / 1000),
          } }));
        }
        if (controller.signal.aborted) break;
      }
      await reload();
    } catch (error) {
      toast("Результаты проверки получены, но статус не обновился: " + (error as Error).message, "err");
    } finally {
      setTestingID("");
      testController.current = null;
      setOperation("");
    }
  };
  const name = server?.label || server?.client_iface || id;
  const selectedReserve = st.servers.find((candidate) => candidate.id === server?.failover?.active_tunnel_id);

  return <Card title="Резервные подключения" sub={name} head={<Button variant="primary" mini onClick={() => { void save(); }} disabled={busy || !dirty}>{operation === "save" ? "Сохранение…" : "Сохранить резерв"}</Button>}>
    <p className="text-xs text-muted">Один список для всех правил этого подключения. При сбое основного туннеля используются резервы по порядку; после восстановления основного трафик возвращается к нему.</p>
    {server && <div className="mt-3 flex flex-wrap items-center gap-2"><ConnectionFailoverBadge server={server} servers={st.servers} />{selectedReserve && selectedReserve.id !== id && <span className="text-xs text-warn" role="status">Активный путь: {name} → {selectedReserve.label || selectedReserve.id}</span>}</div>}
    <div className="mt-3 rounded-lg border border-line p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs font-semibold">Основное: {name}</span>
        <Button mini onClick={() => { void testConnections([id]); }} disabled={busy || !server?.enabled}>{testingID === id ? "Проверка…" : "Проверить соединение"}</Button>
      </div>
      {results[id] && <ConnectionTestResult result={results[id]} />}
    </div>
    <ol className="mt-3 space-y-2" aria-label="Приоритет резервных подключений">
      {ids.map((reserveID, index) => {
        const reserve = st.servers.find((candidate) => candidate.id === reserveID);
        const label = reserve?.label || reserve?.client_iface || reserveID;
        return <li key={reserveID} className="rounded-lg border border-line p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-line-soft text-xs font-semibold" aria-label={`Приоритет ${index + 1}`}>{index + 1}</span>
            <span className="min-w-0 flex-1 text-xs font-semibold [overflow-wrap:anywhere]">{label}</span>
            <Badge kind={!reserve ? "bad" : reserve.connected ? "ok" : "neutral"}>{!reserve ? "подключение удалено" : !reserve.enabled ? "выключено" : reserve.connected ? "подключено" : reserve.failover?.standby ? "ожидание" : "нет соединения"}</Badge>
            <Button mini onClick={() => { setEditing(true); setIDs(moveBackup(ids, index, -1)); }} disabled={busy || index === 0} aria-label={`Повысить приоритет ${label}`}>↑</Button>
            <Button mini onClick={() => { setEditing(true); setIDs(moveBackup(ids, index, 1)); }} disabled={busy || index === ids.length - 1} aria-label={`Понизить приоритет ${label}`}>↓</Button>
            <Button mini variant="ghost" onClick={() => { setEditing(true); setIDs(ids.filter((entry) => entry !== reserveID)); }} disabled={busy} aria-label={`Убрать из резерва ${label}`}>Убрать</Button>
          </div>
          {reserve && <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
            <Switch checked={!!reserve.failover?.standby} onChange={(value) => { void setReserveStandby(reserve, value); }} disabled={busy} label="Ожидать сбоя основного" aria-label={`Ожидать сбоя основного: ${label}`} />
            <Button mini onClick={() => { void testConnections([reserveID]); }} disabled={busy || !reserve.enabled}>{testingID === reserveID ? "Проверка…" : "Проверить резерв"}</Button>
          </div>}
          {reserve && !reserve.enabled && <p className="mt-2 text-xs text-warn">Подключение выключено. Включите его в списке VPN, чтобы резерв мог запускаться автоматически.</p>}
          {results[reserveID] && <ConnectionTestResult result={results[reserveID]} />}
        </li>;
      })}
    </ol>
    {!ids.length && <div className="mt-3 space-y-1 text-xs text-muted" role="status">
      <p>Общий резерв для {name} ещё не выбран. Добавьте существующие VPN-подключения ниже и сохраните список.</p>
      <p>Резерв отдельного правила подменяет подключение только для этого правила. Общий список здесь позволяет резерву заменять {name} для всех его правил, включая новые списки.</p>
    </div>}
    <div className="mt-3 flex flex-wrap items-end gap-2">
      <Field label="Добавить резервы" hint="можно выбрать сразу несколько" className="min-w-48 flex-1"><Select multiple value={selectedCandidates} onChange={(event) => setCandidateIDs(Array.from(event.target.selectedOptions, (option) => option.value).filter(Boolean))} disabled={busy || !candidates.length} aria-label="Добавить резервные подключения">
        <option value="" disabled hidden>{candidates.length ? "Выберите подключения…" : "Нет подходящих подключений"}</option>
        {candidates.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.label || candidate.id}{candidate.client_iface ? ` · ${candidate.client_iface}` : ""}{!candidate.enabled ? " · выключено" : ""}</option>)}
      </Select></Field>
      <Button onClick={add} disabled={busy || !selectedCandidates.length}>Добавить{selectedCandidates.length ? ` (${selectedCandidates.length})` : ""}</Button>
      <Button onClick={() => { void testConnections([id, ...ids].filter((testID) => st.servers.some((candidate) => candidate.id === testID && candidate.enabled))); }} disabled={busy || ![id, ...ids].some((testID) => st.servers.some((candidate) => candidate.id === testID && candidate.enabled))}>{operation === "test" ? "Проверяем подключения…" : "Проверить основной и резервы"}</Button>
      {operation === "test" && <Button onClick={() => testController.current?.abort()}>Остановить проверку</Button>}
    </div>
    {dirty && <p className="mt-2 text-xs text-warn" role="status">Порядок или список изменён. Сохраните резерв, чтобы применить автопереключение.</p>}
    {ids.some((reserveID) => st.servers.some((candidate) => candidate.id === reserveID && candidate.is_warp)) && <p className="mt-3 text-xs text-muted">При выборе WARP как резерва трафик выходит через Cloudflare; внешний IP вашего AWG-сервера не сохраняется.</p>}
    <p className="mt-3 text-xs text-muted">«Ожидать сбоя основного» применяется сразу: резерв остаётся offline, пока не понадобится. Проверка временно запускает ожидающий туннель и проверяет handshake и передачу данных. Результаты ниже относятся к моменту проверки.</p>
    <div className="mt-4 border-t border-line pt-3">
      <Switch checked={standby} onChange={(value) => { setEditing(true); setStandby(value); }} disabled={busy} label="Это подключение — резерв по требованию" />
      <p className="mt-2 text-xs text-muted">Включите, если {name} служит резервом для другого подключения. Для самостоятельного постоянного соединения оставьте выключенным.</p>
    </div>
  </Card>;
}

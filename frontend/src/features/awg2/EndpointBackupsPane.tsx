import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Field, Input } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";
import type { Awg2Status, AwgClientStatus } from "@/types/api";
import { endpointPort, MAX_ENDPOINT_BACKUPS, moveEndpointBackup, primaryEndpointForBackups, saveEndpointBackups, validateEndpointBackups } from "./endpointBackups";

export function EndpointSelectionStatus({ client }: { client: AwgClientStatus | null | undefined }) {
  if (!client) return null;
  const endpoint = client.endpoint || client.endpoint_candidate;
  if (!endpoint && !client.endpoint_pool_exhausted) return null;
  const index = client.endpoint_index;
  const label = index === 0 ? "Основной адрес" : index != null && index > 0 ? `Резервный IP №${index}` : "Адрес подключения";
  return <div className="mt-2 text-[11.5px] text-muted" role="status">
    {endpoint && <span>{label}: <span className="font-mono [overflow-wrap:anywhere]">{endpoint}</span></span>}
    {client.endpoint_pool_exhausted && <p className="mt-1 text-warn">Все IP-адреса этого сервера проверены; связь пока не восстановлена.</p>}
  </div>;
}

interface Props {
  st: Awg2Status;
  acceptStatus: (next: Awg2Status) => void;
  onBusyChange: (busy: boolean) => void;
  externalBusy: boolean;
}

export default function EndpointBackupsPane({ st, acceptStatus, onBusyChange, externalBusy }: Props) {
  const saved = st.config.client.endpoint_backups ?? [];
  const [values, setValues] = useState<string[]>(() => [...saved]);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const savedKey = JSON.stringify(saved);
  const [acknowledged, setAcknowledged] = useState(savedKey);
  const dirty = JSON.stringify(values) !== acknowledged;
  const busy = saving || externalBusy;
  const primary = st.client?.endpoint_primary || primaryEndpointForBackups(st.config, st.endpoint);
  const server = st.servers.find(candidate => candidate.id === st.active_server_id);
  let inheritedPort = "";
  try { inheritedPort = endpointPort(primary); } catch { /* A draft profile may not yet have an endpoint. */ }
  useEffect(() => { onBusyChange(saving); }, [saving, onBusyChange]);
  useEffect(() => () => { onBusyChange(false); }, [onBusyChange]);
  useEffect(() => {
    if (!dirty && !saving) {
      setValues([...saved]);
      setAcknowledged(savedKey);
    }
  }, [savedKey, dirty, saving]);

  const edit = (next: string[]) => {
    if (busy) return;
    setValues(next);
    setError("");
  };
  const add = () => {
    if (busy) return;
    try {
      edit(validateEndpointBackups([...values, draft], primary));
      setDraft("");
    } catch (problem) { setError((problem as Error).message); }
  };
  const save = async () => {
    if (busy || !dirty) return;
    setError("");
    setSaving(true);
    try {
      const next = await saveEndpointBackups(st.active_server_id, values, primary);
      acceptStatus(next);
      const confirmed = next.config.client.endpoint_backups ?? [];
      setValues([...confirmed]);
      setAcknowledged(JSON.stringify(confirmed));
      toast(next.warning || "Резервные IP-адреса сохранены", next.warning ? "warn" : "ok");
    } catch (problem) { setError((problem as Error).message); }
    finally { setSaving(false); }
  };

  return <Card title="Резервные IP-адреса" sub="дополнительные адреса того же VPN-сервера" head={<Badge kind="neutral">{values.length} / {MAX_ENDPOINT_BACKUPS}</Badge>}>
    <p className="text-xs text-muted">{server?.is_warp
      ? "Для WARP указывайте только альтернативные IP того же VPN-сервиса с теми же ключами."
      : "Укажите IP-адреса, действительно закреплённые за этим сервером. На каждом адресе должен работать тот же VPN с теми же ключами."}</p>
    <p className="mt-2 text-xs text-muted">При сбое остальные IP проверяются ping-запросами параллельно: ответившие проверяются раньше, при равных результатах сохраняется порядок списка. Связь подтверждается VPN-хендшейком; отсутствие ping не исключает адрес. Рабочий резерв остаётся выбранным до следующего сбоя или перезапуска подключения. Резервные подключения проверяются после всех IP этого сервера.</p>
    <p className="mt-3 text-xs text-ink-soft">Основной адрес: <span className="font-mono [overflow-wrap:anywhere]">{primary || "ещё не задан"}</span></p>
    <EndpointSelectionStatus client={st.client} />
    {values.length > 0 ? <ol className="mt-3 space-y-2">
      {values.map((value, index) => <li key={`${index}:${value}`} className="flex min-w-0 flex-wrap items-center gap-2 rounded-lg border border-line-soft p-2">
        <span className="text-xs text-muted" aria-hidden="true">{index + 1}.</span>
        <span className="min-w-0 flex-1 font-mono text-xs [overflow-wrap:anywhere]">{value}</span>
        <div className="flex shrink-0 gap-1">
          <Button mini variant="ghost" aria-label={`Поднять резервный IP ${value}`} title="Выше в порядке проверки" disabled={busy || index === 0} onClick={() => edit(moveEndpointBackup(values, index, -1))}>↑</Button>
          <Button mini variant="ghost" aria-label={`Опустить резервный IP ${value}`} title="Ниже в порядке проверки" disabled={busy || index === values.length - 1} onClick={() => edit(moveEndpointBackup(values, index, 1))}>↓</Button>
          <Button mini variant="ghost" aria-label={`Удалить резервный IP ${value}`} disabled={busy} onClick={() => edit(values.filter((_, at) => at !== index))}>Удалить</Button>
        </div>
      </li>)}
    </ol> : <p className="mt-3 text-xs text-muted">Резервные IP-адреса пока не добавлены.</p>}
    <div className="mt-3 grid min-w-0 gap-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
      <Field label="Новый резервный IP" hint={inheritedPort ? `без порта используется UDP ${inheritedPort}` : "сначала задайте основной адрес"}>
        <Input value={draft} placeholder="203.0.113.20 или [2001:db8::20]:51820" autoComplete="off" spellCheck={false} disabled={busy || !inheritedPort || values.length >= MAX_ENDPOINT_BACKUPS} aria-invalid={!!error} aria-describedby={error ? "awg-endpoint-backups-error" : undefined} onChange={event => { setDraft(event.target.value); setError(""); }} onKeyDown={event => { if (event.key === "Enter") { event.preventDefault(); add(); } }} />
      </Field>
      <Button disabled={busy || !inheritedPort || !draft.trim() || values.length >= MAX_ENDPOINT_BACKUPS} onClick={add}>Добавить IP</Button>
    </div>
    {error && <p id="awg-endpoint-backups-error" className="mt-2 text-xs text-warn" role="alert">{error}</p>}
    <div className="mt-3 flex flex-wrap gap-2">
      <Button variant="primary" disabled={busy || !dirty} onClick={() => { void save(); }}>{saving ? "Сохранение…" : "Сохранить резервные IP"}</Button>
      {dirty && <Button variant="ghost" disabled={busy} onClick={() => { setValues([...saved]); setAcknowledged(savedKey); setDraft(""); setError(""); }}>Отменить изменения IP</Button>}
    </div>
  </Card>;
}

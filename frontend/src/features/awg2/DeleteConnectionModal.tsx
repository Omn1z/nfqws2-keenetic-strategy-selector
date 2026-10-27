import { useState } from "react";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { Field, Select } from "@/components/ui/form";
import type { Awg2Status } from "@/types/api";
import { deleteConnectionCandidates, deleteConnectionProblem, deleteConnectionReferences, initialDeleteConnectionSelection } from "./deleteConnection";
import type { DeleteConnectionSelection } from "./deleteConnection";

interface Props {
  st: Awg2Status;
  sourceID: string;
  sourceLabel: string;
  externalBusy: boolean;
  onClose: () => void;
  onDelete: (selection: DeleteConnectionSelection) => Promise<void>;
}

export function DeleteConnectionDetails({ st, sourceID, sourceLabel, selection, onChange, disabled, error = "" }: {
  st: Awg2Status; sourceID: string; sourceLabel: string; selection: DeleteConnectionSelection;
  onChange: (next: DeleteConnectionSelection) => void; disabled: boolean; error?: string;
}) {
  const candidates = deleteConnectionCandidates(st.servers, sourceID);
  const references = deleteConnectionReferences(st, sourceID);
  const target = candidates.find((candidate) => candidate.id === selection.replacementID);
  const missingTarget = !!selection.replacementID && !target;
  const problem = deleteConnectionProblem(st.servers, sourceID, selection);
  return <div className="space-y-3">
    <p>Удалить подключение <strong className="text-ink">{sourceLabel}</strong> из панели?</p>
    <div className="rounded-lg border border-line bg-line-soft p-3 text-xs">
      <p>Правил этого подключения: <strong>{references.primaryRules.length}</strong></p>
      <p className="mt-1">Правил с ним в резерве: <strong>{references.fallbackRules.length}</strong></p>
      <p className="mt-1">Резервных списков других подключений: <strong>{references.connectionBackups}</strong></p>
      <p className="mt-2 text-muted">Учтены также выключенные правила и правила, ожидающие назначения.</p>
    </div>
    <Field label="Что сделать со связанными правилами">
      <Select value={selection.mode} onChange={(event) => onChange({ ...selection, mode: event.target.value as DeleteConnectionSelection["mode"] })} disabled={disabled} aria-label="Действие со связанными правилами">
        <option value="transfer" disabled={!candidates.length}>Перенести на другое подключение</option>
        <option value="waiting">Оставить без подключения</option>
      </Select>
    </Field>
    {selection.mode === "transfer" && <>
      <Field label="Перенести на подключение">
        <Select value={selection.replacementID} onChange={(event) => onChange({ ...selection, replacementID: event.target.value })} disabled={disabled || !candidates.length} aria-label="Подключение для переноса">
          <option value="">Выберите подключение…</option>
          {missingTarget && <option value={selection.replacementID} disabled>Выбранное подключение больше недоступно</option>}
          {candidates.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.label || candidate.id}{candidate.client_iface ? ` · ${candidate.client_iface}` : ""}{!candidate.enabled ? " · выключено" : !candidate.deployed && !candidate.imported ? " · черновик" : !candidate.connected ? " · offline" : ""}</option>)}
        </Select>
      </Field>
      <p className="text-xs text-muted">Правила будут назначены выбранному подключению. Сохранятся домены, IP/CIDR, ссылки на списки, фильтры устройств, порядок, действие и включение/выключение правил. В резервных списках правил и других подключений ссылки на {sourceLabel} заменятся выбранным подключением; повторы и ссылки на себя будут убраны.</p>
      <p className="text-xs text-muted">Резервы удаляемого профиля добавятся после существующих резервов выбранного подключения.</p>
      {target && (!target.enabled || !target.connected || !target.deployed && !target.imported) && <p className="rounded-lg bg-warn-bg p-3 text-xs text-warn" role="status">{!target.enabled ? "Выбранное подключение выключено." : !target.deployed && !target.imported ? "Выбранное подключение ещё не развёрнуто." : "Выбранное подключение сейчас offline."} Перенос сохранит настройки, но не включит сервер и сам по себе не гарантирует доступ через него.</p>}
    </>}
    {selection.mode === "waiting" && <p className="text-xs text-muted">Правила, назначенные удаляемому подключению, сохранятся в ожидании: до ручного назначения они не участвуют в маршрутизации. Ссылки на него в резервах правил сохранятся как недоступные; из общих резервных списков подключений они будут убраны.</p>}
    {!candidates.length && <p className="text-xs text-muted">Других подключений нет. Сохранённые правила можно будет назначить после добавления нового VPN.</p>}
    <p className="text-xs text-muted">Если этот VPN явно выбран в DNS-сервере или Telegram-прокси, выберите новое подключение также в их настройках.</p>
    <p className="text-xs text-muted">Профиль, ключи и пиры удалятся из панели. Сервис на VPS останется установленным.</p>
    {problem && <p className="text-xs text-bad" role="alert">{problem}</p>}
    {error && <p className="text-xs text-bad" role="alert">{error}</p>}
  </div>;
}

export default function DeleteConnectionModal({ st, sourceID, sourceLabel, externalBusy, onClose, onDelete }: Props) {
  // Initial choice belongs to this dialog; polling must never silently replace
  // a removed target with a different VPN or discard an explicit waiting choice.
  const [selection, setSelection] = useState<DeleteConnectionSelection>(() => initialDeleteConnectionSelection(st.servers, sourceID));
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");
  const busy = externalBusy || deleting;
  const problem = deleteConnectionProblem(st.servers, sourceID, selection);
  const submit = async () => {
    if (busy || problem) return;
    setDeleting(true);
    setError("");
    try {
      await onDelete(selection);
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      setDeleting(false);
    }
  };
  return <Modal title="Удалить VPN-подключение" size="lg" onClose={() => { if (!busy) onClose(); }} actions={<>
    <Button onClick={onClose} disabled={busy}>Отмена</Button>
    <Button variant="danger" onClick={() => { void submit(); }} disabled={busy || !!problem}>{deleting ? "Удаление…" : selection.mode === "transfer" ? "Перенести и удалить" : "Удалить, сохранив правила"}</Button>
  </>}>
    <DeleteConnectionDetails st={st} sourceID={sourceID} sourceLabel={sourceLabel} selection={selection} onChange={(next) => { if (!busy) { setSelection(next); setError(""); } }} disabled={busy} error={error} />
  </Modal>;
}

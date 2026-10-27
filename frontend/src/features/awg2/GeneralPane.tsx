import { useEffect, useRef, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Field, Input } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";
import type { Awg2Status, AwgRecoverySettings } from "@/types/api";
import { collectRecoverySettings, defaultRecoverySettings, recoveryDirty, recoveryDraft, saveRecoverySettings, syncRecoveryDraft, type RecoveryForm } from "./recoverySettings";

interface Props {
  settings?: AwgRecoverySettings;
  acceptStatus: (next: Awg2Status) => void;
  onBusyChange: (busy: boolean) => void;
  externalBusy: boolean;
}

export default function GeneralPane({ settings, acceptStatus, onBusyChange, externalBusy }: Props) {
  const [draft, setDraft] = useState(() => recoveryDraft(settings ?? defaultRecoverySettings));
  const [saving, setSaving] = useState(false);
  const inFlight = useRef(false);
  const [saveError, setSaveError] = useState("");
  const savedKey = JSON.stringify(settings);
  useEffect(() => {
    if (settings) setDraft((state) => syncRecoveryDraft(state, settings));
  }, [savedKey]);
  useEffect(() => { onBusyChange(saving); }, [saving, onBusyChange]);
  useEffect(() => () => { onBusyChange(false); }, [onBusyChange]);
  const dirty = recoveryDirty(draft);
  const busy = saving || externalBusy;
  let candidate: AwgRecoverySettings | undefined;
  let validationError = "";
  try { candidate = collectRecoverySettings(draft.form); } catch (error) { validationError = (error as Error).message; }
  const set = (key: keyof RecoveryForm, value: string) => {
    if (busy || !settings) return;
    setSaveError("");
    setDraft((state) => ({ ...state, form: { ...state.form, [key]: value } }));
  };
  const save = async () => {
    if (busy || inFlight.current || !candidate || !settings) return;
    inFlight.current = true;
    setSaving(true);
    setSaveError("");
    try {
      const next = await saveRecoverySettings(candidate);
      if (!next.recovery_settings) throw new Error("Панель не подтвердила сохранённые общие настройки. Обновите статус перед повторной попыткой.");
      setDraft(recoveryDraft(next.recovery_settings));
      acceptStatus(next);
      toast("Общие настройки AWG сохранены", "ok");
    } catch (error) {
      setSaveError((error as Error).message);
    } finally {
      inFlight.current = false;
      setSaving(false);
    }
  };

  return <Card title="Автовосстановление AWG" sub="общие настройки для всех AWG и WARP" head={<Button mini variant="primary" onClick={() => { void save(); }} disabled={busy || !dirty || !candidate || !settings}>{saving ? "Сохранение…" : "Сохранить общие настройки"}</Button>}>
    <p className="text-xs text-muted">График автопопыток общий для всех подключений. Выбор профиля во вкладке «Сервер» на него не влияет. Новые значения используются в дальнейших автопопытках.</p>
    {!settings && <p className="mt-3 text-xs text-warn" role="status">Общие настройки пока не получены. Дождитесь обновления статуса панели.</p>}
    <fieldset disabled={busy || !settings} className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
      <Field label="Быстрый период, с" hint="1–600"><Input type="number" min={1} max={600} step={1} value={draft.form.fastSeconds} onChange={(event) => set("fastSeconds", event.target.value)} /></Field>
      <Field label="Обычная пауза, с" hint="1–30"><Input type="number" min={1} max={30} step={1} value={draft.form.retrySeconds} onChange={(event) => set("retrySeconds", event.target.value)} /></Field>
      <Field label="Долгий отказ после, мин" hint="30–60"><Input type="number" min={30} max={60} step="any" value={draft.form.slowAfterMinutes} onChange={(event) => set("slowAfterMinutes", event.target.value)} /></Field>
      <Field label="Пауза при долгом отказе, с" hint="90–900"><Input type="number" min={90} max={900} step={1} value={draft.form.slowSeconds} onChange={(event) => set("slowSeconds", event.target.value)} /></Field>
      <Field label="Ожидание handshake, с" hint="5–60"><Input type="number" min={5} max={60} step={1} value={draft.form.handshakeSeconds} onChange={(event) => set("handshakeSeconds", event.target.value)} /></Field>
    </fieldset>
    {validationError && <p className="mt-3 text-xs text-warn" role="alert">{validationError}</p>}
    {saveError && <p className="mt-3 text-xs text-bad [overflow-wrap:anywhere]" role="alert">{saveError}</p>}
    {candidate && <div className="mt-4 rounded-lg border border-line p-3 text-xs">
      <p className="font-semibold">{!settings ? "Начальные значения" : dirty ? "После сохранения" : "Текущий график"}</p>
      <ol className="mt-2 list-inside list-decimal space-y-1.5 text-muted">
        <li>Первые {candidate.fast_retry_seconds} с отказа — следующая попытка сразу после завершения предыдущей.</li>
        <li>Затем до {candidate.slow_retry_after_seconds / 60} мин отказа — пауза {candidate.retry_delay_seconds} с между попытками.</li>
        <li>После {candidate.slow_retry_after_seconds / 60} мин непрерывного отказа — пауза {candidate.slow_retry_delay_seconds} с.</li>
      </ol>
      <p className="mt-3 text-muted">В быстром периоде нет дополнительной паузы. Каждая попытка ждёт подтверждения handshake до {candidate.handshake_timeout_seconds} с; попытки выполняются последовательно. После подтверждённого восстановления при новом отказе отсчёт начинается заново.</p>
    </div>}
    {dirty && <div className="mt-3 flex flex-wrap items-center gap-2"><p className="text-xs text-warn" role="status">Общие настройки изменены. Сохраните их для применения.</p><Button mini variant="ghost" disabled={busy} onClick={() => { setDraft(recoveryDraft(draft.saved)); setSaveError(""); }}>Отменить изменения</Button></div>}
  </Card>;
}

import { api } from "@/lib/api";
import type { Awg2Status, AwgRecoverySettings } from "@/types/api";

export const defaultRecoverySettings: AwgRecoverySettings = {
  fast_retry_seconds: 60,
  retry_delay_seconds: 5,
  slow_retry_after_seconds: 3600,
  slow_retry_delay_seconds: 90,
  handshake_timeout_seconds: 20,
};

export interface RecoveryForm {
  fastSeconds: string;
  retrySeconds: string;
  slowAfterMinutes: string;
  slowSeconds: string;
  handshakeSeconds: string;
}

export interface RecoveryDraft {
  saved: AwgRecoverySettings;
  form: RecoveryForm;
}

export const recoveryToForm = (settings: AwgRecoverySettings): RecoveryForm => ({
  fastSeconds: String(settings.fast_retry_seconds),
  retrySeconds: String(settings.retry_delay_seconds),
  slowAfterMinutes: String(settings.slow_retry_after_seconds / 60),
  slowSeconds: String(settings.slow_retry_delay_seconds),
  handshakeSeconds: String(settings.handshake_timeout_seconds),
});

export const recoveryDraft = (settings: AwgRecoverySettings): RecoveryDraft => ({ saved: { ...settings }, form: recoveryToForm(settings) });

export const recoveryDirty = (state: RecoveryDraft): boolean => JSON.stringify(state.form) !== JSON.stringify(recoveryToForm(state.saved));

// A profile switch and ordinary polls update the acknowledged settings without
// discarding an unfinished global edit. Successful saves use recoveryDraft().
export const syncRecoveryDraft = (state: RecoveryDraft, saved: AwgRecoverySettings): RecoveryDraft => recoveryDirty(state)
  ? { ...state, saved: { ...saved } }
  : recoveryDraft(saved);

export function collectRecoverySettings(form: RecoveryForm): AwgRecoverySettings {
  const integer = (value: string, label: string, min: number, max: number) => {
    if (!/^\d+$/.test(value.trim())) throw new Error(`${label}: укажите целое число от ${min} до ${max}.`);
    const number = Number(value);
    if (!Number.isSafeInteger(number) || number < min || number > max) throw new Error(`${label}: допустимо от ${min} до ${max}.`);
    return number;
  };
  const slowMinutes = Number(form.slowAfterMinutes);
  if (!/^\d+(?:\.\d+)?$/.test(form.slowAfterMinutes.trim()) || !Number.isFinite(slowMinutes) || slowMinutes < 30 || slowMinutes > 60) {
    throw new Error("Долгий отказ: допустимо от 30 до 60 минут.");
  }
  return {
    fast_retry_seconds: integer(form.fastSeconds, "Быстрый период", 1, 600),
    retry_delay_seconds: integer(form.retrySeconds, "Обычная пауза", 1, 30),
    slow_retry_after_seconds: Math.round(slowMinutes * 60),
    slow_retry_delay_seconds: integer(form.slowSeconds, "Пауза при долгом отказе", 90, 900),
    handshake_timeout_seconds: integer(form.handshakeSeconds, "Ожидание handshake", 5, 60),
  };
}

export async function saveRecoverySettings(settings: AwgRecoverySettings): Promise<Awg2Status> {
  return api<Awg2Status>("POST", "/api/awg2/settings/recovery", settings);
}

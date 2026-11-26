import type { TargetCheck } from "@/types/api";

type CheckVerdict = Pick<TargetCheck, "blocked" | "verdict">;

export function summarizeTargetChecks(targets: readonly CheckVerdict[]) {
  let blocked = 0;
  let localErrors = 0;
  for (const target of targets) {
    if (target.verdict === "local_error") localErrors++;
    else if (target.blocked) blocked++;
  }
  return { blocked, localErrors };
}

export function baselineCheckMessage(targets: readonly CheckVerdict[]): string {
  const { blocked, localErrors } = summarizeTargetChecks(targets);
  if (localErrors) return `Локальная ошибка проверки у ${localErrors} целей; их доступность не определена.`;
  return blocked === 0 ? "Обходить нечего — всё доступно." : "Автоподбор тестируется только на заблокированных целях.";
}

import { summarizeTargetChecks } from "@/lib/targetChecks";
import type { TargetCheck } from "@/types/api";

export type CheckFilter = "all" | "blocked" | "ok" | "local_error";

export function blockCheckCounts(targets: readonly TargetCheck[]) {
  const { blocked, localErrors } = summarizeTargetChecks(targets);
  const available = targets.filter(target => !target.blocked && target.verdict === "ok").length;
  return { blocked, available, localErrors, undetermined: targets.length - blocked - available };
}

export function visibleBlockCheckTargets(targets: readonly TargetCheck[], query: string, filter: CheckFilter): TargetCheck[] {
  const text = query.trim().toLowerCase();
  return targets.filter(target => {
    if (filter === "blocked" && (!target.blocked || target.verdict === "local_error")) return false;
    if (filter === "ok" && (target.blocked || target.verdict !== "ok")) return false;
    if (filter === "local_error" && target.verdict !== "local_error") return false;
    return !text || `${target.host} ${target.verdict} ${target.code} ${target.err ?? ""}`.toLowerCase().includes(text);
  }).sort((a, b) => Number(b.blocked) - Number(a.blocked));
}

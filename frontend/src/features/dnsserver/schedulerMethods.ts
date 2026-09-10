import type { DnsServerDisabledMethod, DnsServerSchedulerSnapshot } from "@/types/api";

export const schedulerMethodKey = (upstream: string, route: string) => JSON.stringify([upstream, route]);

// A successful save is authoritative even if the following scheduler poll fails.
// Keep measurements until that poll can provide fresh ordering and history.
export function applyDisabledSchedulerMethods(snapshot: DnsServerSchedulerSnapshot, disabledMethods: DnsServerDisabledMethod[]): DnsServerSchedulerSnapshot {
  const disabled = new Set(disabledMethods.map((method) => schedulerMethodKey(method.upstream, method.route)));
  let stoppedProbes = 0;
  const candidates = snapshot.candidates.map((candidate) => {
    const isDisabled = disabled.has(schedulerMethodKey(candidate.upstream, candidate.route));
    if (isDisabled && candidate.probing) stoppedProbes++;
    return {
      ...candidate, disabled: isDisabled,
      ...(isDisabled ? { position: 0, exploration: false, probing: false } : {}),
    };
  });
  return {
    ...snapshot, candidates,
    ...(snapshot.active_probes !== undefined ? { active_probes: Math.max(0, snapshot.active_probes - stoppedProbes) } : {}),
  };
}

export function allAvailableSchedulerMethodsDisabled(snapshot: DnsServerSchedulerSnapshot): boolean {
  const available = snapshot.candidates.filter((candidate) => candidate.available);
  return available.length > 0 && available.every((candidate) => candidate.disabled);
}

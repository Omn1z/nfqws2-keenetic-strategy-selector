export interface DnsConfigDraft<T> {
  value: T;
  saved: T;
  baseHash: string;
}

export function dnsConfigDraft<T>(value: T, baseHash: string): DnsConfigDraft<T> {
  return { value, saved: value, baseHash };
}

export function dnsConfigDirty<T>(draft: DnsConfigDraft<T> | null): boolean {
  return !!draft && JSON.stringify(draft.value) !== JSON.stringify(draft.saved);
}

export function syncDnsConfigDraft<T>(draft: DnsConfigDraft<T> | null, saved: T, baseHash: string): DnsConfigDraft<T> {
  return draft && dnsConfigDirty(draft) ? draft : dnsConfigDraft(saved, baseHash);
}

export function dnsConfigPayload<T, P>(draft: DnsConfigDraft<T>, collect: (value: T) => P): P & { base_hash: string } {
  if (!draft.baseHash) throw new Error("Загрузите актуальные настройки DNS перед сохранением.");
  return { ...collect(draft.value), base_hash: draft.baseHash };
}

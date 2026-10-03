import type { OpenWrtDnsState } from "@/types/api";

export type OpenWrtDnsSelection = { interface: string; instance: string };

export function initialOpenWrtDnsSelection(state: OpenWrtDnsState, previous?: OpenWrtDnsSelection): OpenWrtDnsSelection {
  const interfaces = state.interfaces ?? [];
  const instances = state.instances ?? [];
  const knownInterface = (id?: string) => interfaces.some((entry) => entry.id === id) ? id : undefined;
  const knownInstance = (id?: string) => instances.some((entry) => entry.id === id) ? id : undefined;
  return {
    interface: knownInterface(previous?.interface) ?? knownInterface(state.binding?.interface) ?? knownInterface("wan") ?? interfaces[0]?.id ?? "",
    instance: knownInstance(previous?.instance) ?? knownInstance(state.binding?.instance) ?? (instances.length === 1 ? instances[0].id : ""),
  };
}

export function openWrtDnsApplyBlock(state: OpenWrtDnsState | null, selection: OpenWrtDnsSelection, flags: { dirty: boolean; running: boolean; busy: boolean }): string {
  if (flags.busy) return "Дождитесь завершения текущей операции.";
  if (!state) return "Сначала обновите состояние OpenWrt.";
  if (!state.supported) return state.reason || "Автоматическая настройка доступна только на OpenWrt.";
  if (state.conflict) return state.conflict;
  if (state.pending) return "Предыдущее применение не завершено. Сначала восстановите прежний DNS.";
  if (flags.dirty) return "Сначала сохраните или отмените изменения настроек DNS-сервера.";
  if (!flags.running) return "Для подключения OpenWrt включите DNS-сервер.";
  if (!(state.interfaces ?? []).some((entry) => entry.id === selection.interface)) return "Выберите сетевой интерфейс OpenWrt.";
  if (!(state.instances ?? []).some((entry) => entry.id === selection.instance)) return "Выберите экземпляр dnsmasq.";
  if (!state.revision) return "Состояние устарело. Обновите его перед применением.";
  return "";
}

export function openWrtDnsRestoreAllowed(state: OpenWrtDnsState | null, busy: boolean): boolean {
  return !busy && !!state?.supported && state.managed && !!state.revision && !state.conflict;
}

export function openWrtDnsEndpoint(endpoint: { host: string; port: number }): string {
  return `${endpoint.host.includes(":") ? `[${endpoint.host}]` : endpoint.host}:${endpoint.port}`;
}

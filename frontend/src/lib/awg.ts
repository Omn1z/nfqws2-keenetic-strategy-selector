import type { AwgEngineInfo } from "@/types/api";

/** Display the wire format of a profile; API paths keep their legacy awg2 name. */
export function awgVersionLabel(version?: string): string {
  return version ? `AWG ${version === "2" ? "2.0" : version}` : "AmneziaWG";
}

export function vpnProfileLabel(profile: {
  protocol?: string;
  protocol_version?: string;
  traffic_obfuscation?: boolean;
  is_warp?: boolean;
}): string {
  if (profile.is_warp) return "WARP";
  if (profile.protocol === "wireguard" || profile.traffic_obfuscation === false) return "WireGuard";
  return awgVersionLabel(profile.protocol_version);
}

/** Check the router before changing a remote server's wire format. */
export function vpnEngineIssue(engine: AwgEngineInfo, needsAWG31: boolean): string {
  if (!engine.installed) return engine.supported
    ? "Сначала установите движок AmneziaWG на роутер."
    : `Для архитектуры ${engine.arch} нет готового движка AmneziaWG.`;
  if (needsAWG31 && !engine.awg3_supported) return engine.supported
    ? "Перед переходом сервера на AWG 3.1 обновите движок на роутере."
    : `Установленный движок не поддерживает AWG 3.1; для архитектуры ${engine.arch} нет готового обновления.`;
  if (!engine.tun_ok) return "На роутере недоступен TUN. Восстановите его перед развёртыванием сервера.";
  return "";
}

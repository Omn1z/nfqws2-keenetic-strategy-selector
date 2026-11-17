import { api } from "@/lib/api";
import type { Awg2Status, AwgServerConfig } from "@/types/api";

export const MAX_ENDPOINT_BACKUPS = 8;

export function primaryEndpointForBackups(config: AwgServerConfig, endpoint: string): string {
  if (config.endpoint.trim()) return config.endpoint.trim();
  if (endpoint.trim()) return endpoint.trim();
  const host = config.conn.host.trim();
  if (!host) return "";
  return `${host.includes(":") && !host.startsWith("[") ? `[${host}]` : host}:${config.listen_port || 51820}`;
}

export function endpointPort(endpoint: string): string {
  const match = /^(?:\[[^\]]+\]|[^:]+):([0-9]+)$/.exec(endpoint.trim());
  const port = match ? Number(match[1]) : 0;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("В основном адресе не указан корректный UDP-порт.");
  return String(port);
}

function literalIP(host: string): string {
  if (host.includes(":")) {
    if (!/^[0-9a-f:.]+$/i.test(host)) throw new Error("Укажите IP-адрес без домена, маски сети или зоны интерфейса.");
    let normalized: string;
    try {
      normalized = new URL(`http://[${host}]/`).hostname.slice(1, -1);
    } catch { throw new Error("Некорректный IPv6-адрес. Для адреса с портом используйте [IPv6]:порт."); }
    const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(normalized);
    if (mapped) {
      const high = parseInt(mapped[1], 16), low = parseInt(mapped[2], 16);
      return literalIP(`${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`);
    }
    if (normalized === "::" || normalized.startsWith("ff")) throw new Error("Укажите обычный IP-адрес сервера: неопределённые адреса и multicast не подходят.");
    return normalized;
  }
  const parts = host.split(".");
  if (parts.length !== 4 || parts.some(part => !/^(?:0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) {
    throw new Error("Укажите корректный IPv4- или IPv6-адрес. Доменные имена здесь не поддерживаются.");
  }
  if (parts.every(part => part === "0") || Number(parts[0]) >= 224 && Number(parts[0]) <= 239) throw new Error("Укажите обычный IP-адрес сервера: неопределённые адреса и multicast не подходят.");
  return parts.join(".");
}

export function normalizeEndpointBackup(input: string, primary: string): string {
  const value = input.trim();
  if (!value) throw new Error("Введите резервный IP-адрес.");
  if (value.length > 128 || /[\s/%?#@]/.test(value)) throw new Error("Укажите только IP-адрес и, при необходимости, UDP-порт.");
  let host = value;
  let explicitPort: string | undefined;
  if (value.startsWith("[")) {
    const match = /^\[([^\]]+)\](?::([0-9]+))?$/.exec(value);
    if (!match) throw new Error("Для IPv6 с портом используйте [IPv6]:порт.");
    host = match[1];
    explicitPort = match[2];
  } else if (value.split(":").length === 2) {
    [host, explicitPort] = value.split(":");
  }
  const address = literalIP(host);
  let port = endpointPort(primary);
  if (explicitPort !== undefined) {
    const number = /^[0-9]+$/.test(explicitPort) ? Number(explicitPort) : 0;
    if (!Number.isInteger(number) || number < 1 || number > 65535) throw new Error("UDP-порт должен быть числом от 1 до 65535.");
    port = String(number);
  }
  return `${address.includes(":") ? `[${address}]` : address}:${port}`;
}

export function validateEndpointBackups(values: readonly string[], primary: string): string[] {
  if (values.length > MAX_ENDPOINT_BACKUPS) throw new Error(`Можно добавить не более ${MAX_ENDPOINT_BACKUPS} резервных IP-адресов.`);
  let primaryLiteral = "";
  try { primaryLiteral = normalizeEndpointBackup(primary, primary); } catch { /* The primary may be a hostname. */ }
  const seen = new Set<string>();
  return values.map(value => {
    const normalized = normalizeEndpointBackup(value, primary);
    if (normalized === primaryLiteral) throw new Error("Этот IP-адрес и порт уже используются как основные.");
    if (seen.has(normalized)) throw new Error("Этот IP-адрес и порт уже есть в списке резервных.");
    seen.add(normalized);
    return normalized;
  });
}

export function moveEndpointBackup(values: readonly string[], index: number, direction: -1 | 1): string[] {
  const next = [...values];
  const target = index + direction;
  if (index < 0 || index >= next.length || target < 0 || target >= next.length) return next;
  [next[index], next[target]] = [next[target], next[index]];
  return next;
}

export function saveEndpointBackups(serverID: string, endpoints: readonly string[], primary: string): Promise<Awg2Status & { warning?: string }> {
  if (!serverID) throw new Error("Сначала выберите VPN-подключение.");
  return api<Awg2Status & { warning?: string }>("POST", `/api/awg2/servers/${encodeURIComponent(serverID)}/endpoint-backups`, {
    endpoint_backups: validateEndpointBackups(endpoints, primary),
  });
}

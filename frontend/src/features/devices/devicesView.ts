import type { Device } from "@/types/api";

export const hasDeviceFailures = (device: Device): boolean => device.failing > 0 || (device.failing_dsts?.length ?? 0) > 0;

export function deviceRows(devices: Device[], query: string, failOnly: boolean): Device[] {
  const search = query.toLowerCase().trim();
  return devices.filter(device => (!failOnly || hasDeviceFailures(device)) && (!search ||
    [device.ip, device.mac, device.hostname ?? "", device.iface, ...(device.ipv6 ?? [])]
      .some(value => value.toLowerCase().includes(search))));
}

export function deviceSummary(devices: Device[]) {
  let failingHosts = 0, established = 0, total = 0, failing = 0, bytes = 0;
  let hasTraffic = true;
  for (const device of devices) {
    if (hasDeviceFailures(device)) failingHosts++;
    established += device.established ?? 0;
    total += device.total ?? 0;
    failing += device.failing ?? 0;
    if (Number.isFinite(device.bytes_up) && Number.isFinite(device.bytes_down)) bytes += device.bytes_up + device.bytes_down;
    else hasTraffic = false;
  }
  return { hosts: devices.length, failingHosts, established, total, failing, bytes: hasTraffic ? bytes : null };
}

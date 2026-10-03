import { api } from "@/lib/api";
import type { DnsServerSettingsDocument } from "@/types/api";

export function dnsSettingsFilename(doc: DnsServerSettingsDocument): string {
  const date = new Date(doc.exported_at);
  if (doc.format !== "nfqws2-strategy-dnsserver" || doc.version !== 1 || !doc.config || Number.isNaN(date.getTime())) {
    throw new Error("Роутер вернул некорректный файл настроек DNS");
  }
  return `dns-server-settings-${date.toISOString().slice(0, 19).replace(/[-:]/g, "").replace("T", "-")}.json`;
}

export async function exportDnsSettings(): Promise<void> {
  // Fetch the entire saved Config, including settings maintained on other tabs.
  // Never send the local form or replace its unsaved changes with this snapshot.
  const doc = await api<DnsServerSettingsDocument>("GET", "/api/dnsserver/export");
  const filename = dnsSettingsFilename(doc);
  const url = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  try {
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
  } finally {
    link.remove();
    // Allow the browser to start the download before releasing its Blob URL.
    globalThis.setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
}

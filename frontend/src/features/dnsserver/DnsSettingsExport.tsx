import { useRef, useState } from "react";
import { Button } from "@/components/ui/Button";
import { toast } from "@/components/ui/Toast";
import { exportDnsSettings } from "./exportDnsSettings";

export const DNS_SETTINGS_EXPORT_NOTE = "JSON содержит все сохранённые настройки DNS Server. Кэш, статистика, журналы и приватные VPN-ключи не экспортируются.";
export const DNS_SETTINGS_DRAFT_NOTE = "Несохранённые изменения этой вкладки не попадут в файл. Чтобы включить их, сначала сохраните настройки.";

export function DnsSettingsExportNote({ dirty }: { dirty: boolean }) {
  return <div className="mt-3 text-xs text-muted">
    <p>{DNS_SETTINGS_EXPORT_NOTE}</p>
    {dirty && <p className="mt-1 text-warn">{DNS_SETTINGS_DRAFT_NOTE}</p>}
  </div>;
}

export function DnsSettingsExportButton({ disabled }: { disabled?: boolean }) {
  const [exporting, setExporting] = useState(false);
  const active = useRef(false);
  const download = async () => {
    if (disabled || active.current) return;
    active.current = true;
    setExporting(true);
    try { await exportDnsSettings(); toast("Сохранённые настройки DNS экспортированы", "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
    finally { active.current = false; setExporting(false); }
  };
  return <Button mini disabled={disabled || exporting} onClick={download}>{exporting ? "Экспорт…" : "Экспорт сохранённых настроек"}</Button>;
}

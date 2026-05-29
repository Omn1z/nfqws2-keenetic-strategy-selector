import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useStore } from "@/providers/StoreProvider";
import { useTheme } from "@/lib/theme";
import type { ThemeMode } from "@/lib/theme";
import { toast } from "@/components/ui/Toast";
import { Spinner } from "@/components/ui/Spinner";

interface UpdateInfo {
  current: string;
  latest: string;
  available: boolean;
  error?: string;
}

const THEME_ICON: Record<ThemeMode, ReactNode> = {
  auto: <svg viewBox="0 0 24 24" width="16" height="16"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="2" /><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor" /></svg>,
  light: <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="4.3" /><path d="M12 1.6v3M12 19.4v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1.6 12h3M19.4 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" /></svg>,
  dark: <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" /></svg>,
};
const iconBtn = "grid h-7 w-7 place-items-center rounded-lg text-ink-soft transition hover:bg-line-soft hover:text-accent";

export function TopBar({ authEnabled, onMenu }: { authEnabled: boolean; onMenu: () => void }) {
  const { config } = useStore();
  const [mode, cycle] = useTheme();
  const [latest, setLatest] = useState("");
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState<{ target: string; msg: string } | null>(null);
  const version = config?.version ?? "…";

  const check = async (manual: boolean) => {
    setChecking(true);
    try {
      const u = await api<UpdateInfo>("GET", "/api/update/check");
      if (u.error) { if (manual) toast("Проверка: " + u.error, "err"); }
      else if (u.available) { setLatest(u.latest); if (manual) toast("Доступна версия " + u.latest, "ok"); }
      else { setLatest(""); if (manual) toast("Установлена последняя версия", "ok"); }
    } catch (e) { if (manual) toast((e as Error).message, "err"); }
    finally { setTimeout(() => setChecking(false), 400); }
  };
  useEffect(() => { void check(false); }, []);

  const doUpdate = async () => {
    if (!confirm(`Обновить nfqws2-strategy до ${latest}?\nСервис будет перезапущен.`)) return;
    const target = latest;
    try { await api("POST", "/api/update"); } catch (e) { toast((e as Error).message, "err"); return; }
    setUpdating({ target, msg: "Скачиваем новую версию и перезапускаем сервис." });
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      try {
        const st = await api<{ version: string }>("GET", "/api/auth/status");
        if (st.version === target) { setUpdating({ target, msg: "Готово, перезагружаем…" }); setTimeout(() => location.reload(), 1000); return; }
      } catch { /* server restarting */ }
    }
    setUpdating({ target, msg: "Перезапуск занимает дольше обычного. Обновите страницу вручную." });
  };

  const logout = async () => { try { await api("POST", "/api/auth/logout"); } catch { /* ignore */ } location.reload(); };

  return (
    <header className="relative z-20 flex h-[58px] shrink-0 items-center justify-between border-b border-border bg-card px-3 shadow-sm sm:px-5">
      <div className="flex items-center gap-2 text-base sm:gap-2.5">
        <button className={cn(iconBtn, "md:hidden")} title="Меню" aria-label="Открыть меню" onClick={onMenu}>
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18M3 12h18M3 18h18" /></svg>
        </button>
        <span className="grid h-[30px] w-[30px] place-items-center rounded-[9px] bg-gradient-to-br from-[#36a3ff] to-accent-d text-white shadow">
          <svg viewBox="0 0 24 24" width="20" height="20"><path d="M13 2 4 14h6l-1 8 9-12h-6z" fill="currentColor" /></svg>
        </span>
        <span>NFQWS2 <b className="font-bold text-accent">Strategy</b></span>
      </div>
      <div className="flex items-center gap-2 sm:gap-3.5">
        {config?.wan_ifaces && <span className="hidden text-xs text-muted sm:inline">iface {config.wan_ifaces.join(",")}</span>}
        <button className={iconBtn} title="Тема" onClick={cycle}>{THEME_ICON[mode]}</button>
        <div className="flex items-center gap-2 rounded-full bg-line-soft py-1 pl-3 pr-2">
          <span className="hidden text-xs text-muted sm:inline">версия</span>
          <span className="font-semibold tabular-nums">{version}</span>
          <button className={cn(iconBtn, checking && "animate-spin")} title="Проверить обновления" onClick={() => check(true)}>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6" /></svg>
          </button>
          {latest && (
            <button onClick={doUpdate} className="animate-pulse rounded-full bg-gradient-to-br from-[#ffb33e] to-warn px-3 py-1.5 text-xs font-semibold text-white shadow">
              Обновить до {latest}
            </button>
          )}
        </div>
        {authEnabled && (
          <button className={iconBtn} title="Выход" onClick={logout}>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" /></svg>
          </button>
        )}
      </div>
      {updating && (
        <div className="fixed inset-0 z-[60] grid place-items-center bg-[rgba(20,30,45,.55)] backdrop-blur-sm">
          <div className="w-[340px] rounded-2xl border border-line bg-panel p-9 text-center shadow-2xl">
            <Spinner className="mx-auto" />
            <h3 className="mb-2 mt-4 text-lg font-semibold">Обновление до {updating.target}</h3>
            <p className="text-xs text-muted">{updating.msg}</p>
          </div>
        </div>
      )}
    </header>
  );
}

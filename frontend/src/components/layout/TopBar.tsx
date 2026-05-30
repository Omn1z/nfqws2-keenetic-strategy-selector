import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Spinner } from "@/components/ui/Spinner";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import type { Nfqws2Version } from "@/types/api";

interface UpdateInfo {
  current: string;
  latest: string;
  available: boolean;
  error?: string;
}

interface Pending {
  id: "app" | "nfqws2";
  label: string;
  from: string;
  to: string;
}

const iconBtn = "grid h-7 w-7 place-items-center rounded-lg text-ink-soft transition hover:bg-line-soft hover:text-accent";

export function TopBar({ authEnabled, onMenu }: { authEnabled: boolean; onMenu: () => void }) {
  const { config } = useStore();
  const [latest, setLatest] = useState("");
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState<{ target: string; msg: string } | null>(null);
  const [n2s, setN2s] = useState<Nfqws2Version | null>(null);
  const [n2sUpdating, setN2sUpdating] = useState<{ target: string; msg: string } | null>(null);
  const [updOpen, setUpdOpen] = useState(false);
  const [updSel, setUpdSel] = useState<string[]>([]);
  const version = config?.version ?? "…";

  const check = async (manual: boolean) => {
    setChecking(true);
    try {
      const u = await api<UpdateInfo>("GET", "/api/update/check");
      if (u.error) { if (manual) toast("Проверка: " + u.error, "err"); }
      else if (u.available) { setLatest(u.latest); if (manual) toast("Доступно обновление панели: " + u.latest, "ok"); }
      else { setLatest(""); }
    } catch (e) { if (manual) toast((e as Error).message, "err"); }
    finally { setTimeout(() => setChecking(false), 400); }
  };
  const checkN2s = async () => {
    try { setN2s(await api<Nfqws2Version>("GET", "/api/nfqws2/version")); } catch { /* ignore */ }
    try { setN2s(await api<Nfqws2Version>("GET", "/api/nfqws2/update/check")); } catch { /* keep version-only */ }
  };
  useEffect(() => { void check(false); void checkN2s(); }, []);
  const recheck = async () => { await check(true); await checkN2s(); };

  // Every component with a pending update, unified into one button + modal.
  const pending: Pending[] = [];
  if (latest) pending.push({ id: "app", label: "Панель управления", from: version, to: latest });
  if (n2s?.available && n2s.latest) pending.push({ id: "nfqws2", label: "Движок NFQWS2", from: n2s.package, to: n2s.latest });

  // Update flows (no confirm — the modal is the confirmation).
  const appUpdateFlow = async () => {
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
  const n2sUpdateFlow = async () => {
    const target = n2s?.latest;
    if (!target) return;
    setN2sUpdating({ target, msg: "Выполняется opkg upgrade (может занять до минуты)…" });
    try {
      const r = await api<{ ok: boolean; output: string; error?: string }>("POST", "/api/nfqws2/update");
      if (!r.ok) { setN2sUpdating(null); toast("Обновление nfqws2: " + (r.error || "ошибка"), "err"); return; }
    } catch (e) { setN2sUpdating(null); toast((e as Error).message, "err"); return; }
    setN2sUpdating(null);
    toast("nfqws2 обновлён до " + target, "ok");
    await checkN2s();
  };
  const runUpdates = async (ids: string[]) => {
    setUpdOpen(false);
    if (ids.includes("nfqws2")) await n2sUpdateFlow(); // first — doesn't restart our panel
    if (ids.includes("app")) await appUpdateFlow();    // last — restarts the panel + reloads the page
  };

  const logout = async () => { try { await api("POST", "/api/auth/logout"); } catch { /* ignore */ } location.reload(); };

  return (
    <header className="relative z-20 flex h-[58px] shrink-0 items-center justify-between border-b border-border bg-card px-3 shadow-sm sm:px-5">
      <div className="flex min-w-0 items-center gap-2 text-base sm:gap-2.5">
        <button className={cn(iconBtn, "shrink-0 md:hidden")} title="Меню" aria-label="Открыть меню" onClick={onMenu}>
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18M3 12h18M3 18h18" /></svg>
        </button>
        <span className="grid h-[30px] w-[30px] shrink-0 place-items-center rounded-[9px] bg-gradient-to-br from-[#36a3ff] to-accent-d text-white shadow">
          <svg viewBox="0 0 24 24" width="20" height="20"><path d="M13 2 4 14h6l-1 8 9-12h-6z" fill="currentColor" /></svg>
        </span>
        <span className="truncate">NFQWS2<b className="hidden font-bold text-accent sm:inline"> Strategy</b></span>
      </div>
      <div className="flex items-center gap-2 sm:gap-3.5">
        {config?.wan_ifaces && <span className="hidden text-xs text-muted lg:inline">iface {config.wan_ifaces.join(",")}</span>}
        <div className="flex items-center gap-2 rounded-full bg-line-soft py-1 pl-3 pr-2">
          <span className="hidden text-xs text-muted sm:inline">версия</span>
          <span className="font-semibold tabular-nums">{version}</span>
          <button className={cn("hidden h-7 w-7 place-items-center rounded-lg text-ink-soft transition hover:bg-line-soft hover:text-accent sm:grid", checking && "animate-spin")} title="Проверить обновления" onClick={recheck}>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6" /></svg>
          </button>
        </div>

        {pending.length > 0 && (
          <button
            onClick={() => { setUpdSel(pending.map((p) => p.id)); setUpdOpen(true); }}
            title="Доступны обновления"
            className="shrink-0 animate-pulse rounded-full bg-gradient-to-br from-[#ffb33e] to-warn px-2.5 py-1.5 text-xs font-semibold text-white shadow sm:px-3"
          >
            <span className="sm:hidden">↑{pending.length}</span>
            <span className="hidden sm:inline">Обновления · {pending.length}</span>
          </button>
        )}

        {authEnabled && (
          <button className={iconBtn} title="Выход" onClick={logout}>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" /></svg>
          </button>
        )}
      </div>

      {updOpen && (
        <Modal
          title="Доступны обновления"
          onClose={() => setUpdOpen(false)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setUpdOpen(false)}>Отмена</Button>
              <Button variant="primary" disabled={!updSel.length} onClick={() => runUpdates(updSel)}>Обновить выбранные</Button>
            </>
          }
        >
          <p className="mb-3 text-muted">Отметьте, что обновить. Роутер не перезагружается.</p>
          <div className="flex flex-col gap-2.5">
            {pending.map((p) => (
              <label key={p.id} className="flex cursor-pointer items-center gap-2.5 text-[13.5px]">
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded-[4px] accent-[var(--c-accent)] outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
                  checked={updSel.includes(p.id)}
                  onChange={() => setUpdSel((s) => (s.includes(p.id) ? s.filter((x) => x !== p.id) : [...s, p.id]))}
                />
                <span>{p.label}: <span className="text-muted tabular-nums">{p.from}</span> → <b className="tabular-nums text-accent-d">{p.to}</b></span>
              </label>
            ))}
          </div>
        </Modal>
      )}

      {updating && (
        <div className="fixed inset-0 z-[60] grid place-items-center bg-[rgba(20,30,45,.55)] backdrop-blur-sm">
          <div className="w-[340px] rounded-2xl border border-line bg-panel p-9 text-center shadow-2xl">
            <Spinner className="mx-auto" />
            <h3 className="mb-2 mt-4 text-lg font-semibold">Обновление панели до {updating.target}</h3>
            <p className="text-xs text-muted">{updating.msg}</p>
          </div>
        </div>
      )}
      {n2sUpdating && (
        <div className="fixed inset-0 z-[60] grid place-items-center bg-[rgba(20,30,45,.55)] backdrop-blur-sm">
          <div className="w-[340px] rounded-2xl border border-line bg-panel p-9 text-center shadow-2xl">
            <Spinner className="mx-auto" />
            <h3 className="mb-2 mt-4 text-lg font-semibold">Обновление nfqws2 до {n2sUpdating.target}</h3>
            <p className="text-xs text-muted">{n2sUpdating.msg}</p>
          </div>
        </div>
      )}
    </header>
  );
}

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { toast } from "@/components/ui/Toast";
import { cn } from "@/lib/cn";
import type { AutomationStatus } from "@/types/api";

function fmtAge(sec: number): string {
  if (sec <= 0) return "—";
  if (sec < 60) return `${sec}с`;
  if (sec < 3600) return `${Math.round(sec / 60)} мин`;
  if (sec < 86400) return `${Math.round(sec / 3600)} ч`;
  return `${Math.round(sec / 86400)} д`;
}

function fmtAgo(ts: number): string {
  if (!ts) return "никогда";
  const delta = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  return fmtAge(delta) + " назад";
}

export function AutomationPanel() {
  const [st, setSt] = useState<AutomationStatus | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = async () => {
    try {
      setSt(await api<AutomationStatus>("GET", "/api/nfqws2/automation"));
    } catch (e) {
      toast("automation: " + (e as Error).message, "err");
    }
  };

  useEffect(() => {
    void reload();
    const t = setInterval(reload, 5000);
    return () => clearInterval(t);
  }, []);

  if (!st) return null;

  const patch = async (delta: Partial<AutomationStatus>) => {
    if (busy) return;
    setBusy(true);
    try {
      const next = await api<AutomationStatus>("POST", "/api/nfqws2/automation", {
        mode: delta.mode ?? st.mode,
        auto_pick: delta.auto_pick ?? st.auto_pick,
        periodic_scan: delta.periodic_scan ?? st.periodic_scan,
        interval_h: delta.interval_h ?? st.interval_h,
      });
      setSt(next);
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  const pickNow = async () => {
    if (busy || st.pick_in_progress) return;
    setBusy(true);
    try {
      const next = await api<AutomationStatus>("POST", "/api/nfqws2/automation/pick-now", {});
      setSt(next);
      toast("Запущен авто-скан — займёт 1–3 мин", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  const modeBtn = (m: "off" | "on" | "auto", label: string, hint: string) => (
    <button
      type="button"
      onClick={() => patch({ mode: m })}
      disabled={busy}
      title={hint}
      className={cn(
        "border-r border-line px-3 py-1.5 text-[13px] outline-none transition last:border-r-0 focus-visible:ring-2 focus-visible:ring-ring/40",
        st.mode === m ? "bg-accent text-white" : "bg-panel text-ink-soft hover:bg-line-soft",
      )}
    >
      {label}
    </button>
  );

  return (
    <Card
      title="Автоматика"
      sub="watchdog VPN → fallback на NFQWS2 + авто-пик стратегии"
      head={
        <div className="flex flex-wrap items-center gap-1.5">
          {st.awg_healthy
            ? <Badge kind="ok">VPN ок · {fmtAge(st.handshake_age_sec)}</Badge>
            : <Badge kind="bad">VPN тух · {fmtAge(st.handshake_age_sec)}</Badge>}
          {st.nfqws2_running
            ? <Badge kind="warn">NFQWS2 работает</Badge>
            : <Badge kind="neutral">NFQWS2 выкл</Badge>}
        </div>
      }
    >
      <div className="space-y-3">
        <div>
          <div className="mb-1 text-[12px] uppercase tracking-wide text-muted">Режим NFQWS2</div>
          <div className="inline-flex overflow-hidden rounded-lg border border-line">
            {modeBtn("off", "всегда выкл", "Не запускать — даже если VPN упадёт")}
            {modeBtn("auto", "авто (fallback)", "Включать только если VPN не отвечает 60+ с")}
            {modeBtn("on", "всегда вкл", "Держать включённым постоянно (как было раньше)")}
          </div>
          <p className="mt-1 text-[11.5px] text-muted">
            «авто» — по умолчанию NFQWS2 выключен, поднимается только когда AWG-туннель тух (handshake &gt; 3 мин или rx стоит). Возвращается AWG — гасим обратно. Это экономит ~50 MB RAM и нагрузку на NFQUEUE.
          </p>
        </div>

        <div className="border-t border-line-soft pt-3">
          <div className="mb-1 text-[12px] uppercase tracking-wide text-muted">Авто-пик стратегии</div>
          <label className="flex items-center gap-2 text-[13px]">
            <input
              type="checkbox"
              checked={st.auto_pick}
              onChange={e => patch({ auto_pick: e.target.checked })}
              disabled={busy}
            />
            <span>При первом старте если конфиг пуст — сам запустить скан и применить лучшую стратегию</span>
          </label>

          <label className="mt-2 flex items-center gap-2 text-[13px]">
            <input
              type="checkbox"
              checked={st.periodic_scan}
              onChange={e => patch({ periodic_scan: e.target.checked })}
              disabled={busy}
            />
            <span>Периодически пере-сканировать раз в</span>
            <input
              type="number"
              min={1}
              max={720}
              value={st.interval_h}
              onChange={e => patch({ interval_h: Math.max(1, parseInt(e.target.value || "24", 10)) })}
              disabled={busy || !st.periodic_scan}
              className="w-16 rounded border border-line bg-panel px-1.5 py-0.5 text-right tabular-nums outline-none focus:border-accent"
            />
            <span>ч</span>
          </label>
          <p className="mt-1 text-[11.5px] text-muted">
            Скан реально дёргает заблокированные сайты с тестовыми стратегиями, занимает 1–3 мин. По умолчанию выключено.
          </p>
        </div>

        {(st.last_pick_at || st.last_pick_error) && (
          <div className="border-t border-line-soft pt-3 text-[12.5px]">
            <div className="text-muted">Последний пик</div>
            {st.last_pick_at ? (
              <div className="mt-0.5">
                <b className="text-ink">{st.last_pick_name || "—"}</b>
                <span className="ml-2 text-muted">{fmtAgo(st.last_pick_at)}</span>
              </div>
            ) : null}
            {st.last_pick_args && st.last_pick_args !== "(pre-existing)" && (
              <div className="mt-0.5 truncate font-mono text-[11px] text-ink-soft" title={st.last_pick_args}>{st.last_pick_args}</div>
            )}
            {st.last_pick_error && <div className="mt-1 text-bad">Ошибка: {st.last_pick_error}</div>}
          </div>
        )}

        <div className="flex items-center gap-2 border-t border-line-soft pt-3">
          <Button mini onClick={pickNow} disabled={busy || st.pick_in_progress}>
            {st.pick_in_progress ? "сканирую…" : "Пик сейчас"}
          </Button>
          <span className="text-[11.5px] text-muted">Скан + применить, занимает 1–3 мин</span>
        </div>
      </div>
    </Card>
  );
}

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Switch } from "@/components/ui/Switch";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import type { PiholeStatus, PiholeStats } from "@/types/api";

// «Сервисы → Pi-hole»: docker-container lifecycle for the upstream Pi-hole v6
// ad-block DNS sinkhole, with chain-toggle into AWG2's DNS proxy. The pi-hole
// admin UI itself stays at its own port (8053) — re-skinning it would be a lot
// of UI work for no win.

function fmtUptime(sec: number): string {
  if (!sec) return "—";
  if (sec < 60) return `${sec}с`;
  if (sec < 3600) return `${Math.round(sec / 60)} мин`;
  if (sec < 86400) return `${Math.round(sec / 3600)} ч`;
  return `${Math.round(sec / 86400)} д`;
}

export default function Pihole() {
  const [st, setSt] = useState<PiholeStatus | null>(null);
  const [stats, setStats] = useState<PiholeStats | null>(null);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<string>("");

  const reload = async () => {
    try {
      setSt(await api<PiholeStatus>("GET", "/api/pihole/status"));
    } catch (e) {
      toast("status: " + (e as Error).message, "err");
    }
  };
  const reloadStats = async () => {
    try {
      setStats(await api<PiholeStats>("GET", "/api/pihole/stats"));
    } catch {
      /* ignore — pi-hole may be down */
    }
  };

  useEffect(() => {
    void reload();
    void reloadStats();
    const t = setInterval(() => { void reload(); void reloadStats(); }, 5000);
    return () => clearInterval(t);
  }, []);

  if (!st) return null;

  const run = async (path: string, label: string, confirm?: { title: string; body: string; danger?: boolean }) => {
    if (busy) return;
    if (confirm && !(await confirmDialog({ ...confirm, confirmLabel: "Подтверждаю" }))) return;
    setBusy(true);
    try {
      const res = await api<{ ok: boolean; error?: string; log?: string; status?: PiholeStatus }>("POST", path, {});
      if (res.log) setLog(res.log);
      if (res.status) setSt(res.status);
      toast(res.ok ? label + ": ок" : label + ": " + (res.error || "ошибка"), res.ok ? "ok" : "err");
      await reload();
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  const install = () => run("/api/pihole/install", "Установка", {
    title: "Установить Pi-hole?",
    body: "Скачает образ pihole/pihole:latest (~150 МБ), создаст контейнер с host-network. Порты: DNS " + st.dns_port + ", UI " + st.ui_port + ". Данные на " + st.data_root + ".",
  });
  const start = () => run("/api/pihole/start", "Старт");
  const stop = () => run("/api/pihole/stop", "Стоп", {
    title: "Остановить Pi-hole?",
    body: "Блок-листы перестанут резать рекламу до следующего запуска.",
    danger: true,
  });
  const restart = () => run("/api/pihole/restart", "Рестарт");
  const upgrade = () => run("/api/pihole/upgrade", "Апгрейд", {
    title: "Обновить Pi-hole до latest?",
    body: "Pull свежего образа + пересоздание контейнера. Данные (/etc/pihole) сохраняются. Займёт 1–3 мин.",
  });
  const remove = () => run("/api/pihole/remove", "Удаление", {
    title: "Удалить контейнер Pi-hole?",
    body: "Контейнер удалится. Данные на USB (" + st.data_root + ") и образ останутся — следующий install подхватит.",
    danger: true,
  });

  const toggleChain = async (enabled: boolean) => {
    if (busy) return;
    setBusy(true);
    try {
      const next = await api<PiholeStatus>("POST", "/api/pihole/chain", { enabled });
      setSt(next);
      toast("DNS-цепь: " + (enabled ? "включена → :5354 → :" + st.dns_port : "выключена"), "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  const openAdmin = () => {
    const url = `${window.location.protocol}//${window.location.hostname}:${st.ui_port}/admin/`;
    window.open(url, "_blank", "noopener");
  };
  const showLogs = async () => {
    try {
      const d = await api<{ log: string }>("GET", "/api/pihole/logs?lines=300");
      setLog(d.log || "(пусто)");
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  const statusBadge = !st.installed
    ? <Badge kind="neutral">образ не установлен</Badge>
    : !st.running
      ? <Badge kind="neutral">контейнер выключен</Badge>
      : st.healthy
        ? <Badge kind="ok">healthy · {fmtUptime(st.uptime_sec)}</Badge>
        : <Badge kind="warn">starting · {fmtUptime(st.uptime_sec)}</Badge>;

  return (
    <>
      <Card
        title="Pi-hole"
        sub="ad-block DNS sinkhole в контейнере (v6, ~14 MB RAM)"
        head={
          <div className="flex flex-wrap items-center gap-2">
            {statusBadge}
            {st.upgrade_avail && <Badge kind="warn">доступно обновление</Badge>}
            <Button mini onClick={openAdmin} disabled={!st.running}>Открыть admin UI ↗</Button>
            <Button mini onClick={showLogs} disabled={!st.installed}>Логи</Button>
          </div>
        }
      >
        <p className="mb-3 text-xs text-muted">
          Pi-hole режет рекламу на уровне DNS — клиенты в LAN получают NXDOMAIN на доменах из чёрного списка (84&nbsp;000+ записей в дефолтном listе). Управление списками, query log, whitelist — в его собственном admin UI (порт {st.ui_port}). Пароль по умолчанию: <code className="text-ink">{st.password}</code>.
        </p>

        <div className="flex flex-wrap gap-2">
          {!st.installed && <Button variant="primary" onClick={install} disabled={busy}>Установить</Button>}
          {st.installed && !st.running && <Button variant="primary" onClick={start} disabled={busy}>Запустить</Button>}
          {st.running && <Button onClick={stop} disabled={busy}>Остановить</Button>}
          {st.installed && <Button onClick={restart} disabled={busy}>Рестарт</Button>}
          {st.installed && <Button onClick={upgrade} disabled={busy}>Обновить</Button>}
          {st.installed && <Button onClick={remove} disabled={busy}>Удалить</Button>}
        </div>
      </Card>

      <Card title="DNS-цепь" sub="как pi-hole встраивается в наш DNS-стек" className="mt-4">
        <p className="mb-2 text-[12px] text-muted">
          Когда включено: <code className="text-ink">dnsmasq:53 → наш DNS-proxy:5354 → pi-hole:{st.dns_port} → upstream DoH</code>. AWG2-зоны по-прежнему отдаются нашим proxy (через DoH в обход блока), а всё остальное идёт через pi-hole — там режется реклама. Когда выключено: наш proxy форвардит в системный dnsmasq (как сейчас).
        </p>
        <Switch
          checked={st.dns_chain_enabled}
          onChange={toggleChain}
          label={st.dns_chain_enabled ? `включено → :5354 → 127.0.0.1:${st.dns_port}` : "выключено (трафик не идёт через pi-hole)"}
        />
        {st.dns_chain_enabled && !st.running && (
          <p className="mt-2 text-[11px] text-warn">⚠ Контейнер не запущен — DNS-цепь сейчас сломана. Запусти pi-hole или выключи toggle.</p>
        )}
      </Card>

      {st.running && stats && !stats.error && (
        <Card title="Статистика" sub="из Pi-hole REST API" className="mt-4">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Запросов" value={stats.total_queries.toLocaleString()} />
            <Stat label="Заблокировано" value={stats.blocked_queries.toLocaleString()} hint={`${stats.percent_blocked.toFixed(1)}%`} />
            <Stat label="Доменов в блок-листе" value={stats.domains_on_list.toLocaleString()} />
            <Stat label="Активных клиентов" value={String(stats.active_clients)} />
          </div>
        </Card>
      )}

      {log && (
        <Card title="Лог последней операции" className="mt-4">
          <pre className="max-h-72 overflow-auto rounded bg-panel-dim p-2 font-mono text-[11px] text-ink-soft">{log}</pre>
        </Card>
      )}
    </>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded border border-line p-2.5">
      <div className="text-[11px] uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-0.5 text-[20px] font-semibold tabular-nums text-ink">{value}</div>
      {hint && <div className="text-[11px] text-muted">{hint}</div>}
    </div>
  );
}

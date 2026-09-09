import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Switch } from "@/components/ui/Switch";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { Field, Input } from "@/components/ui/form";
import type { SystemPorts, SystemSettings } from "@/types/api";

const Row = ({ title, desc, children }: { title: string; desc: string; children: ReactNode }) => (
  <div className="flex items-center justify-between gap-4 border-t border-line-soft py-3.5 first:border-t-0">
    <div className="min-w-0">
      <div className="text-[13.5px] font-medium">{title}</div>
      <div className="mt-0.5 text-xs text-muted">{desc}</div>
    </div>
    <div className="shrink-0">{children}</div>
  </div>
);

const parsePort = (value: string, name: string) => {
  if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) {
    throw new Error(`${name}: укажите целое число от 1 до 65535`);
  }
  return Number(value);
};

function Ports() {
  const [saved, setSaved] = useState<SystemPorts | null>(null);
  const [panelPort, setPanelPort] = useState("");
  const [dnsPort, setDnsPort] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [panelURL, setPanelURL] = useState("");
  const [panelNotice, setPanelNotice] = useState("");
  const saving = useRef(false);

  const accept = (ports: SystemPorts) => {
    setSaved(ports);
    setPanelPort(String(ports.panel_port));
    setDnsPort(String(ports.dns_port));
  };
  const load = useCallback(async () => {
    try { accept(await api<SystemPorts>("GET", "/api/system/ports")); setError(""); }
    catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const save = async () => {
    if (!saved || saving.current) return;
    try {
      const next = { panel_port: parsePort(panelPort, "Порт панели"), dns_port: parsePort(dnsPort, "Порт DNS") };
      if (next.panel_port === next.dns_port) throw new Error("Панель и DNS-сервер должны использовать разные порты");
      saving.current = true; setBusy(true); setError(""); setPanelNotice("");
      const ports = await api<SystemPorts>("POST", "/api/system/ports", next);
      accept(ports);
      if (ports.panel_port !== saved.panel_port) {
        // A proxy can expose a different scheme or port from the actual panel.
        // Only change the browser address when it matches the direct listener.
        const browserPort = Number(window.location.port || (window.location.protocol === "https:" ? 443 : 80));
        let target: URL | null = null;
        try { if (ports.panel_url) target = new URL(ports.panel_url); } catch { /* Keep the saved result; URL is optional. */ }
        if (target && target.hostname === window.location.hostname && target.protocol === window.location.protocol &&
          !target.username && !target.password && browserPort === saved.panel_port) {
          target.pathname = window.location.pathname;
          target.search = window.location.search;
          target.hash = window.location.hash;
          const href = target.href;
          setPanelURL(href);
          toast("Порты сохранены — открываем панель по новому адресу…", "ok");
          window.setTimeout(() => window.location.assign(href), 600);
          return;
        }
        setPanelNotice(`Порт панели изменён на ${ports.panel_port}. Если подключение идёт через прокси, обновите его адрес назначения отдельно.`);
      }
      toast("Порты сохранены", "ok");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      saving.current = false; setBusy(false);
    }
  };

  const dirty = saved && (panelPort !== String(saved.panel_port) || dnsPort !== String(saved.dns_port));
  return (
    <Card title="Порты" sub="веб-панель и DNS Server">
      {!saved ? <>
        <p role={error ? "alert" : undefined} className="text-xs text-muted">{error || "Загрузка…"}</p>
        {error && <Button mini className="mt-3" onClick={load}>Повторить</Button>}
      </> : <form onSubmit={(e) => { e.preventDefault(); void save(); }}>
        <fieldset disabled={busy || !!panelURL} className="grid min-w-0 gap-4 sm:grid-cols-2">
          <Field label="Порт веб-панели · TCP">
            <Input type="number" inputMode="numeric" min={1} max={65535} step={1} required value={panelPort} onChange={(e) => setPanelPort(e.target.value)} />
            <span className="mt-1.5 block text-xs font-normal text-muted">При прямом подключении панель откроется по новому адресу.</span>
          </Field>
          <Field label="Порт DNS-сервера · UDP и TCP">
            <Input type="number" inputMode="numeric" min={1} max={65535} step={1} required value={dnsPort} onChange={(e) => setDnsPort(e.target.value)} />
            <span className="mt-1.5 block text-xs font-normal text-muted">По умолчанию 5355. Порт 53 обычно занят DNS роутера.</span>
          </Field>
        </fieldset>
        <p className="mt-3 text-xs text-muted">Изменения применяются сразу. Сохранение порта DNS не включает выключенный сервис. Укажите новый порт и в настройках DNS-клиентов.</p>
        {error && <p role="alert" className="mt-3 text-xs text-bad [overflow-wrap:anywhere]">{error}</p>}
        {panelURL && <p role="status" className="mt-3 text-xs text-muted">Новый адрес панели: <a className="text-accent underline [overflow-wrap:anywhere]" href={panelURL}>{panelURL}</a></p>}
        {panelNotice && <p role="status" className="mt-3 text-xs text-muted">{panelNotice}</p>}
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" disabled={busy || !!panelURL || !dirty}>{busy ? "Сохранение…" : "Сохранить порты"}</Button>
          {dirty && <Button type="button" disabled={busy || !!panelURL} onClick={() => { accept(saved); setError(""); }}>Отменить</Button>}
        </div>
      </form>}
    </Card>
  );
}

export default function System() {
  const [s, setS] = useState<SystemSettings | null>(null);
  const [confirmAuthOff, setConfirmAuthOff] = useState(false);
  const [restarting, setRestarting] = useState(false);
  // Backups: nothing stored on the server — download streams a sealed blob
  // straight to the user; restore takes the same blob back via file upload.
  // No password — sealing is anti-tamper, not anti-disclosure.
  const [downloading, setDownloading] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const fileRef = useRef<HTMLInputElement | null>(null);

  const download = async () => {
    if (downloading) return;
    setDownloading(true);
    try {
      const resp = await fetch("/api/system/backup", { method: "POST" });
      if (!resp.ok) throw new Error(await resp.text() || `HTTP ${resp.status}`);
      const blob = await resp.blob();
      const cd = resp.headers.get("Content-Disposition") || "";
      const m = /filename="?([^";]+)"?/i.exec(cd);
      const filename = m ? m[1] : "selector-backup.bak";
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = filename; document.body.appendChild(a); a.click();
      a.remove(); URL.revokeObjectURL(url);
      toast("Резервная копия скачана", "ok");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setDownloading(false);
    }
  };

  const restoreFromFile = async () => {
    const f = fileRef.current?.files?.[0];
    if (!f) { toast("Выбери файл резервной копии", "err"); return; }
    if (!window.confirm(
      `Восстановить из «${f.name}»? Текущие настройки селектора будут перезаписаны и сервис перезапущен.`,
    )) return;
    setRestoring(true);
    try {
      const fd = new FormData();
      fd.append("archive", f);
      const resp = await fetch("/api/system/restore", { method: "POST", body: fd });
      if (!resp.ok) throw new Error(await resp.text() || `HTTP ${resp.status}`);
      const { restored } = await resp.json();
      if (fileRef.current) fileRef.current.value = "";
      toast(`Восстановлено ${restored} файлов — перезапускаю селектор…`, "ok");
      // Restore changed the on-disk state; trigger the same restart flow as the
      // "Перезапустить" button so the new files take effect immediately.
      try { await api<{ status: string }>("POST", "/api/system/restart", {}); } catch { /* selector is going down anyway */ }
      window.setTimeout(() => window.location.reload(), 8000);
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setRestoring(false);
    }
  };

  const load = useCallback(async () => {
    try { setS(await api<SystemSettings>("GET", "/api/system/settings")); } catch (e) { toast((e as Error).message, "err"); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const apply = async (patch: Partial<Pick<SystemSettings, "auth_enabled" | "logging_enabled" | "http_logs_enabled" | "trace_mode">>, ok: string) => {
    try { setS(await api<SystemSettings>("POST", "/api/system/settings", patch)); toast(ok, "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
  };

  const onAuth = (on: boolean) => {
    if (!on) { setConfirmAuthOff(true); return; } // disabling auth needs confirmation
    void apply({ auth_enabled: true }, "Авторизация включена");
  };
  const confirmDisableAuth = () => { setConfirmAuthOff(false); void apply({ auth_enabled: false }, "Авторизация выключена — вход без пароля"); };

  const onRestart = async () => {
    if (restarting) return;
    if (!window.confirm("Перезапустить селектор? Веб-интерфейс будет недоступен ~6 секунд.")) return;
    setRestarting(true);
    try {
      await api<{ status: string }>("POST", "/api/system/restart", {});
      toast("Селектор перезапускается… вернёмся через ~6 сек", "ok");
      window.setTimeout(() => window.location.reload(), 8000);
    } catch (e) {
      toast((e as Error).message, "err");
      setRestarting(false);
    }
  };

  if (!s) return <Card><span className="text-xs text-muted">Загрузка…</span></Card>;

  return (
    <>
      <Card title="Система" sub="настройки сервиса">
        <Row title="Авторизация" desc="Запрашивать логин/пароль роутера при входе в веб-интерфейс.">
          {s.auth_forced_off
            ? <span className="text-xs text-muted">выключена через N2S_NOAUTH</span>
            : <Switch checked={s.auth_enabled} onChange={onAuth} />}
        </Row>
        <Row title="Логирование" desc="Запись логов сервиса (вкладка «Логи» и файл). Выключение останавливает сбор.">
          <Switch checked={s.logging_enabled} onChange={(on) => apply({ logging_enabled: on }, on ? "Логирование включено" : "Логирование выключено")} />
        </Row>
        <Row title="HTTP-логи запросов" desc="Строки «GET /api/… 14ms» в логах. Выключение убирает их шум, остальные логи остаются.">
          <Switch checked={s.http_logs_enabled} onChange={(on) => apply({ http_logs_enabled: on }, on ? "HTTP-логи включены" : "HTTP-логи выключены")} />
        </Row>
        <Row title="Трассировка VPN" desc="Запись DNS/SNI-событий в буфер для вкладки «AmneziaWG → Трассировка». Счётчики (RPS на главной) тикают всегда — кольцо буфера наполняется только в выбранном режиме.">
          <select
            value={s.trace_mode}
            onChange={(e) => void apply({ trace_mode: e.target.value as SystemSettings["trace_mode"] }, "Режим трассировки сохранён")}
            className="h-9 rounded border border-line bg-panel px-2 text-[13px]"
          >
            <option value="off">Выкл (только счётчики)</option>
            <option value="auto">Авто — пока открыта вкладка</option>
            <option value="always">Всегда писать</option>
          </select>
        </Row>
        <Row title="Перезапуск селектора" desc="SIGTERM текущему процессу и автоматический ре-стейт через xmir-init. ~6 секунд недоступности. Делает полную ре-инициализацию: маршрутизация, прокси, авто-AWG, pi-hole-хук — всё с нуля.">
          <Button variant="danger" onClick={onRestart} disabled={restarting}>{restarting ? "перезапуск…" : "Перезапустить"}</Button>
        </Row>
      </Card>

      <Ports />

      <Card title="Резервные копии" sub="на сервере ничего не хранится — архив скачивается сразу тебе; обратно — тем же файлом">
        <Row
          title="Скачать резервную копию"
          desc="Полный snapshot конфигов селектора. Архив запечатан — отредактировать его руками не получится, при восстановлении подделанный файл отказывается."
        >
          <Button variant="primary" onClick={download} disabled={downloading}>
            {downloading ? "Готовим…" : "Скачать"}
          </Button>
        </Row>
        <Row
          title="Восстановить из файла"
          desc="Селектор автоматически перезапустится после восстановления. Битый/отредактированный файл — отказ."
        >
          <div className="flex items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              accept=".bak,application/octet-stream"
              className="text-xs text-muted file:mr-2 file:rounded file:border file:border-line file:bg-panel file:px-2 file:py-1 file:text-[12px] hover:file:bg-line-soft"
            />
            <Button variant="danger" onClick={restoreFromFile} disabled={restoring}>
              {restoring ? "Восстанавливаю…" : "Восстановить"}
            </Button>
          </div>
        </Row>
      </Card>

      {confirmAuthOff && (
        <Modal
          title="Выключить авторизацию?"
          onClose={() => setConfirmAuthOff(false)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setConfirmAuthOff(false)}>Отмена</Button>
              <Button variant="danger" onClick={confirmDisableAuth}>Выключить</Button>
            </>
          }
        >
          <p>Веб-интерфейс станет доступен <b>без входа</b> — любой в сети сможет открыть его и менять стратегии DPI.</p>
          <p className="mt-2 text-muted">Включить обратно можно здесь же, на вкладке «Система».</p>
        </Modal>
      )}
    </>
  );
}

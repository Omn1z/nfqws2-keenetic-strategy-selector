import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Switch } from "@/components/ui/Switch";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import type { SystemSettings } from "@/types/api";

const Row = ({ title, desc, children }: { title: string; desc: string; children: ReactNode }) => (
  <div className="flex items-center justify-between gap-4 border-t border-line-soft py-3.5 first:border-t-0">
    <div className="min-w-0">
      <div className="text-[13.5px] font-medium">{title}</div>
      <div className="mt-0.5 text-xs text-muted">{desc}</div>
    </div>
    <div className="shrink-0">{children}</div>
  </div>
);

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

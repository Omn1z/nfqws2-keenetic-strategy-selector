import { useCallback, useEffect, useState } from "react";
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

  const load = useCallback(async () => {
    try { setS(await api<SystemSettings>("GET", "/api/system/settings")); } catch (e) { toast((e as Error).message, "err"); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const apply = async (patch: Partial<Pick<SystemSettings, "auth_enabled" | "logging_enabled">>, ok: string) => {
    try { setS(await api<SystemSettings>("POST", "/api/system/settings", patch)); toast(ok, "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
  };

  const onAuth = (on: boolean) => {
    if (!on) { setConfirmAuthOff(true); return; } // disabling auth needs confirmation
    void apply({ auth_enabled: true }, "Авторизация включена");
  };
  const confirmDisableAuth = () => { setConfirmAuthOff(false); void apply({ auth_enabled: false }, "Авторизация выключена — вход без пароля"); };

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

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { FileManager } from "./FileManager";
import { ConfigPane } from "./ConfigPane";
import type { Nfqws2Version } from "@/types/api";

type Sub = "config" | "scripts" | "lists";

interface ServiceResult { name: string; ok: boolean; detail: string }

/** «Сервисы → NFQWS2»: manage the live nfqws2 engine — its config, Lua DPI
 *  scripts and domain/IP lists — plus engine version + reload/restart. */
export default function Nfqws2() {
  const [sub, setSub] = useState<Sub>("config");
  const [ver, setVer] = useState<Nfqws2Version | null>(null);
  const [working, setWorking] = useState(false);

  useEffect(() => {
    void (async () => { try { setVer(await api<Nfqws2Version>("GET", "/api/nfqws2/version")); } catch { /* ignore */ } })();
  }, []);

  const reload = async () => {
    try {
      await api("POST", "/api/nfqws2/reload", {});
      toast("nfqws2: конфиг перечитан (reload, очередь не прервана)", "ok");
    } catch (e) {
      toast("Reload: " + (e as Error).message, "err");
    }
  };

  const restart = async () => {
    if (working) return;
    setWorking(true);
    try {
      const d = await api<{ results: ServiceResult[] }>("POST", "/api/services/restart", { services: ["nfqws2"] });
      const r = d.results?.[0];
      toast(r?.ok ? "nfqws2 перезапущен" : "nfqws2: " + (r?.detail || "ошибка"), r?.ok ? "ok" : "err");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setWorking(false);
    }
  };

  const seg = (m: Sub, label: string) => (
    <button
      type="button"
      onClick={() => setSub(m)}
      className={cn("border-r border-line px-4 py-1.5 text-[13px] outline-none transition last:border-r-0 focus-visible:relative focus-visible:ring-2 focus-visible:ring-ring/40", sub === m ? "bg-accent text-white" : "bg-panel text-ink-soft hover:bg-line-soft")}
    >
      {label}
    </button>
  );

  return (
    <>
      <Card
        title="NFQWS2"
        sub="движок обхода DPI (zapret2)"
        head={
          <div className="flex flex-wrap items-center gap-2">
            {ver && <Badge kind="neutral">пакет {ver.package || "?"}</Badge>}
            {ver?.engine && <Badge kind="neutral">движок {ver.engine}</Badge>}
            <Button mini onClick={reload} title="SIGHUP: перечитать конфиг и списки без обрыва очереди">Применить (reload)</Button>
            <Button mini variant="primary" onClick={restart} disabled={working}>{working ? "…" : "Перезапустить"}</Button>
          </div>
        }
      >
        <p className="text-xs text-muted">Редактирование живого движка nfqws2: конфиг, Lua-скрипты обхода и списки доменов/IP. «Применить (reload)» перечитывает списки без обрыва очереди; «Перезапустить» нужен после смены портов, интерфейса или стратегий.</p>
      </Card>

      <div className="mb-4 inline-flex overflow-hidden rounded-lg border border-line">
        {seg("config", "Конфиг")}
        {seg("scripts", "Скрипты")}
        {seg("lists", "Списки")}
      </div>

      {sub === "config" && <ConfigPane restart={restart} />}
      {sub === "scripts" && <FileManager key="lua" kind="lua" reload={reload} />}
      {sub === "lists" && <FileManager key="list" kind="list" reload={reload} />}
    </>
  );
}

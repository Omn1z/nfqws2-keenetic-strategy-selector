import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { FileManager } from "./FileManager";
import { ConfigPane } from "./ConfigPane";
import { AutomationPanel } from "./AutomationPanel";
import { FileExplorer } from "./FileExplorer";
import { StrategyArchives } from "./StrategyArchives";
import type { Nfqws2Version } from "@/types/api";

type Sub = "config" | "scripts" | "lists" | "bypass" | "files" | "archives" | "automation";

interface ServiceResult { name: string; ok: boolean; detail: string }

/** «Сервисы → NFQWS2»: manage the live nfqws2 engine — its config, Lua DPI
 *  scripts and domain/IP lists — plus engine version + reload/restart. */
export default function Nfqws2() {
  const [sub, setSub] = useState<Sub>("config");
  const [visited, setVisited] = useState<Set<Sub>>(() => new Set(["config"]));
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

  const applyBypass = async () => {
    await api("POST", "/api/nfqws2/bypass/apply", {});
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
      onClick={() => { setSub(m); setVisited((current) => new Set([...current, m])); }}
      role="tab"
      aria-selected={sub === m}
      aria-controls={`nfqws-tab-${m}`}
      className={cn("border-r border-line px-4 py-1.5 text-[13px] outline-none transition last:border-r-0 focus-visible:relative focus-visible:ring-2 focus-visible:ring-ring/40", sub === m ? "bg-accent text-primary-foreground" : "bg-panel text-ink-soft hover:bg-line-soft")}
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
            {ver && <Badge kind="neutral">пакет {ver.package || (ver.package_status === "missing" ? "не установлен" : "версия недоступна")}</Badge>}
            {ver?.engine && <Badge kind="neutral">движок {ver.engine}</Badge>}
            <Button mini onClick={reload} title="SIGHUP: перечитать конфиг и списки без обрыва очереди">Применить (reload)</Button>
            <Button mini variant="primary" onClick={restart} disabled={working}>{working ? "…" : "Перезапустить"}</Button>
          </div>
        }
      >
        <p className="text-xs text-muted">Редактирование живого движка nfqws2: конфиг, Lua-скрипты обхода и списки доменов/IP. «Применить (reload)» перечитывает списки без обрыва очереди; «Перезапустить» нужен после смены портов, интерфейса или стратегий.</p>
      </Card>

      <div className="mb-4 flex flex-wrap overflow-hidden rounded-lg border border-line" role="tablist" aria-label="Управление NFQWS2">
        {seg("config", "Конфиг")}
        {seg("scripts", "Скрипты")}
        {seg("lists", "Списки")}
        {seg("bypass", "Списки NFQUEUE Bypass")}
        {seg("files", "Файлы")}
        {seg("archives", "Архивы стратегий")}
        {seg("automation", "Автоматизация")}
      </div>

      {/* Lazily mount once, then retain drafts, undo stacks and import previews. */}
      {visited.has("config") && <div id="nfqws-tab-config" role="tabpanel" hidden={sub !== "config"}><ConfigPane restart={restart} /></div>}
      {visited.has("scripts") && <div id="nfqws-tab-scripts" role="tabpanel" hidden={sub !== "scripts"}><FileManager kind="lua" reload={reload} allowUpload={false} /></div>}
      {visited.has("lists") && <div id="nfqws-tab-lists" role="tabpanel" hidden={sub !== "lists"}><FileManager kind="list" reload={reload} allowUpload={false} /></div>}
      {visited.has("bypass") && <div id="nfqws-tab-bypass" role="tabpanel" hidden={sub !== "bypass"}>
        <FileManager
          key="bypass"
          kind="bypass"
          reload={applyBypass}
          allowCreate={false}
          allowUpload={false}
        />
      </div>}
      {visited.has("files") && <div id="nfqws-tab-files" role="tabpanel" hidden={sub !== "files"}><FileExplorer /></div>}
      {visited.has("archives") && <div id="nfqws-tab-archives" role="tabpanel" hidden={sub !== "archives"}><StrategyArchives /></div>}
      {sub === "automation" && <div id="nfqws-tab-automation" role="tabpanel"><AutomationPanel /></div>}
    </>
  );
}

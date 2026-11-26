import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { FileManager } from "./FileManager";
import { ConfigPane } from "./ConfigPane";
import { AutomationPanel } from "./AutomationPanel";
import { FileExplorer } from "./FileExplorer";
import { StrategyArchives } from "./StrategyArchives";
import { ServiceStrategies } from "./ServiceStrategies";
import { Nfqws2ServiceControls, useNfqws2ServiceControl } from "./Nfqws2ServiceControl";
import type { Nfqws2Version } from "@/types/api";

type Sub = "config" | "services" | "scripts" | "lists" | "bypass" | "files" | "archives" | "automation";

/** «Сервисы → NFQWS2»: manage the live nfqws2 engine — its config, Lua DPI
 *  scripts and domain/IP lists — plus engine version and service controls. */
export default function Nfqws2() {
  const [sub, setSub] = useState<Sub>("config");
  const [visited, setVisited] = useState<Set<Sub>>(() => new Set(["config"]));
  const [ver, setVer] = useState<Nfqws2Version | null>(null);
  const service = useNfqws2ServiceControl();

  useEffect(() => {
    void (async () => { try { setVer(await api<Nfqws2Version>("GET", "/api/nfqws2/version")); } catch { /* ignore */ } })();
  }, []);

  const applyBypass = async () => {
    await api("POST", "/api/nfqws2/bypass/apply", {});
  };

  const restart = () => service.run("restart");

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
            <Nfqws2ServiceControls status={service.status} error={service.error} pending={service.pending} onToggle={enabled => { void service.run(enabled ? "start" : "stop"); }} onRestart={() => { void restart(); }} />
          </div>
        }
      >
        <p className="text-xs text-muted">Сохраните правки конфига, стратегий, Lua-скриптов и списков, затем нажмите «Перезапуск службы». Движок полностью перезапустится и применит сохранённые параметры; обход DPI ненадолго прервётся.</p>
        {service.status?.manual_off && <p className="mt-2 text-xs text-muted">Служба выключена вручную. Автоматика не запустит её до включения переключателем.</p>}
        {service.error && <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-warn" role="alert"><span>Не удалось проверить состояние службы: {service.error}</span><Button mini disabled={service.pending !== null} onClick={() => { void service.refresh(); }}>Проверить состояние</Button></div>}
      </Card>

      <div className="mb-4 flex flex-wrap overflow-hidden rounded-lg border border-line" role="tablist" aria-label="Управление NFQWS2">
        {seg("config", "Конфиг")}
        {seg("services", "Сервисы")}
        {seg("scripts", "Скрипты")}
        {seg("lists", "Списки")}
        {seg("bypass", "Списки NFQUEUE Bypass")}
        {seg("files", "Файлы")}
        {seg("archives", "Архивы стратегий")}
        {seg("automation", "Автоматизация")}
      </div>

      {/* Lazily mount once, then retain drafts, undo stacks and import previews. */}
      {visited.has("config") && <div id="nfqws-tab-config" role="tabpanel" hidden={sub !== "config"}><ConfigPane restart={async () => { await restart(); }} canRestart={service.canRestart} /></div>}
      {visited.has("services") && <div id="nfqws-tab-services" role="tabpanel" hidden={sub !== "services"}><ServiceStrategies restart={restart} canRestart={service.canRestart} /></div>}
      {visited.has("scripts") && <div id="nfqws-tab-scripts" role="tabpanel" hidden={sub !== "scripts"}><FileManager kind="lua" apply={restart} canApply={service.canRestart} allowUpload={false} /></div>}
      {visited.has("lists") && <div id="nfqws-tab-lists" role="tabpanel" hidden={sub !== "lists"}><FileManager kind="list" apply={restart} canApply={service.canRestart} allowUpload={false} /></div>}
      {visited.has("bypass") && <div id="nfqws-tab-bypass" role="tabpanel" hidden={sub !== "bypass"}>
        <FileManager
          key="bypass"
          kind="bypass"
          apply={applyBypass}
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

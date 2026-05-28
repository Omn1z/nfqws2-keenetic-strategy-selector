import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Select } from "@/components/ui/form";
import type { LogEntry } from "@/types/api";

const LEVEL: Record<string, string> = { error: "text-bad", warn: "text-warn", info: "text-ink" };
const fmtTime = (ms: number) =>
  `${new Date(ms).toLocaleTimeString("ru-RU", { hour12: false })}.${String(ms % 1000).padStart(3, "0")}`;

export default function Logs() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [modules, setModules] = useState<string[]>([]);
  const [module, setModule] = useState("all");
  const [paused, setPaused] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  usePoll(async () => {
    try {
      const r = await api<{ entries: LogEntry[]; modules: string[] }>("GET", "/api/logs?limit=1000");
      setEntries(r.entries ?? []);
      setModules(r.modules ?? []);
    } catch { /* keep last */ }
  }, 2000, !paused);

  const shown = useMemo(() => (module === "all" ? entries : entries.filter((e) => e.module === module)), [entries, module]);

  useEffect(() => {
    if (!paused && boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
  }, [shown, paused]);

  const clear = async () => {
    try { await api("POST", "/api/logs/clear"); setEntries([]); toast("Логи очищены", "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
  };

  return (
    <Card
      title="Логи"
      sub="последние записи по модулям сервиса"
      head={
        <div className="flex items-center gap-2.5">
          <Select value={module} onChange={(e) => setModule(e.target.value)} className="w-auto">
            <option value="all">все модули</option>
            {modules.map((m) => <option key={m} value={m}>{m}</option>)}
          </Select>
          <Button mini onClick={() => setPaused((p) => !p)}>{paused ? "▶ Возобновить" : "⏸ Пауза"}</Button>
          <Button mini variant="danger" onClick={clear}>Очистить</Button>
        </div>
      }
    >
      <div ref={boxRef} className="max-h-[600px] overflow-auto rounded-lg border border-line bg-input p-3 font-mono text-xs leading-relaxed">
        {shown.length === 0 && <div className="text-muted">Пусто.</div>}
        {shown.map((e, i) => (
          <div key={i} className="whitespace-pre-wrap [overflow-wrap:anywhere]">
            <span className="text-muted">{fmtTime(e.t)}</span>{" "}
            <span className="text-accent-d">[{e.module}]</span>{" "}
            <span className={cn(LEVEL[e.level] ?? "text-ink")}>{e.msg}</span>
          </div>
        ))}
      </div>
      <p className="mt-2 text-xs text-muted">Логи TG WS Proxy — модуль <code>tgws</code>. Трассировки устройств — модуль <code>trace</code>.</p>
    </Card>
  );
}

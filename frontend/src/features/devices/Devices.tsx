import { useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { hostOf } from "@/lib/format";
import { useStore } from "@/providers/StoreProvider";
import { toast } from "@/components/ui/Toast";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import type { Device, Trace } from "@/types/api";

const KIND: Record<string, { label: string; cls: string }> = {
  new: { label: "NEW", cls: "text-ink-soft" },
  unreplied: { label: "НЕТ ОТВЕТА", cls: "text-bad" },
  replied: { label: "ОТВЕТ", cls: "text-ok" },
  gone: { label: "ЗАКРЫТО", cls: "text-warn" },
};
const problems = (t: Trace) => (t.events ?? []).filter((e) => e.kind === "unreplied" || e.kind === "gone").length;

function downloadTrace(t: Trace) {
  const lines = [
    `# Трассировка ${t.ip} — ${t.seconds}с — ${new Date(t.started_at * 1000).toLocaleString("ru-RU")}`,
    `# соединений: ${t.conns.length}, событий: ${t.events.length}`,
    "",
    "## События",
    ...(t.events ?? []).map((e) => `+${(e.at_ms / 1000).toFixed(1)}с ${e.kind.toUpperCase()} ${e.proto} ${e.dst}${e.note ? " — " + e.note : ""}`),
    "",
    "## Соединения",
    ...(t.conns ?? []).map((c) => `${c.proto} ${c.dst} state=${c.state || "-"} ${c.first_ms}-${c.last_ms}мс пакетов≈${c.max_packets} байт≈${c.max_bytes}${c.unreplied ? " UNREPLIED" : ""}${c.gone ? " GONE" : ""}`),
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `trace-${t.ip}-${t.id.slice(0, 6)}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

const DstList = ({ items }: { items: string[] }) =>
  !items.length ? (
    <ul className="m-0 list-none p-0 text-xs text-muted">—</ul>
  ) : (
    <ul className="m-0 max-h-[168px] list-none overflow-y-auto p-0 font-mono text-xs">
      {items.slice(0, 50).map((x, i) => <li key={i} className="border-b border-line-soft py-0.5 text-ink-soft [overflow-wrap:anywhere]">{x}</li>)}
      {items.length > 50 && <li className="py-0.5 text-muted">…ещё {items.length - 50}</li>}
    </ul>
  );

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [err, setErr] = useState("");
  const [trace, setTrace] = useState<Trace | null>(null);
  const [tracing, setTracing] = useState(false);
  const { setPendingTargets } = useStore();

  usePoll(async () => {
    try { const v = await api<{ devices: Device[] }>("GET", "/api/devices"); setDevices(v.devices ?? []); setErr(""); }
    catch (e) { setErr((e as Error).message); }
  }, 5000);

  usePoll(async () => {
    if (!trace) return;
    try {
      const t = await api<Trace>("GET", `/api/trace/${trace.id}`);
      setTrace(t);
      if (t.status !== "running") {
        setTracing(false);
        toast(`Трассировка ${t.ip} завершена — проблем: ${problems(t)}`, problems(t) ? "warn" : "ok");
      }
    } catch (e) { setTracing(false); toast((e as Error).message, "err"); }
  }, 1000, tracing);

  const sendToRun = (failing: string[]) => {
    setPendingTargets([...new Set(failing.map(hostOf).filter(Boolean))]);
    location.hash = "runs";
  };
  const startTrace = async (ip: string) => {
    try { const t = await api<Trace>("POST", `/api/devices/${encodeURIComponent(ip)}/trace`, { seconds: 30 }); setTrace(t); setTracing(true); toast(`Трассировка ${ip} запущена на 30 с`, "ok"); }
    catch (e) { toast((e as Error).message, "err"); }
  };

  return (
    <>
      {trace && (
        <Card
          title={`Трассировка ${trace.ip}`}
          sub={tracing ? "идёт запись…" : trace.status === "error" ? `ошибка: ${trace.error}` : "готово"}
          head={
            <div className="flex items-center gap-2.5">
              {trace.status !== "running" && <Button mini onClick={() => downloadTrace(trace)}>Скачать лог</Button>}
              <Button mini variant="ghost" onClick={() => { setTrace(null); setTracing(false); }}>Закрыть</Button>
            </div>
          }
        >
          <div className="mb-2 flex flex-wrap gap-4 text-xs text-ink-soft">
            <span>прошло: <b className="tabular-nums">{(trace.elapsed_ms / 1000).toFixed(1)} / {trace.seconds} с</b></span>
            <span>соединений: <b>{(trace.conns ?? []).length || new Set((trace.events ?? []).filter((e) => e.kind === "new").map((e) => e.dst)).size}</b></span>
            <span className={problems(trace) ? "text-bad" : ""}>проблемы: <b>{problems(trace)}</b></span>
          </div>
          {tracing && (
            <div className="mb-2 h-2 overflow-hidden rounded-full bg-line">
              <div className="h-full rounded-full bg-gradient-to-r from-accent to-[#5cb3ff] transition-[width]" style={{ width: `${Math.min(100, trace.elapsed_ms / (trace.seconds * 10))}%` }} />
            </div>
          )}
          <div className="max-h-[280px] overflow-auto rounded-lg border border-line bg-input p-3 font-mono text-xs leading-relaxed">
            {(trace.events ?? []).length === 0 && <div className="text-muted">Пока нет событий… (повоспроизводите проблему — игру, звонок и т.п.)</div>}
            {(trace.events ?? []).map((e, i) => {
              const k = KIND[e.kind] ?? { label: e.kind, cls: "text-ink" };
              return (
                <div key={i} className="whitespace-pre-wrap [overflow-wrap:anywhere]">
                  <span className="text-muted">+{(e.at_ms / 1000).toFixed(1)}с</span>{" "}
                  <span className={cn("font-semibold", k.cls)}>{k.label}</span>{" "}
                  <span className="text-ink-soft">{e.proto} {e.dst}</span>
                  {e.note ? <span className="text-muted"> — {e.note}</span> : null}
                </div>
              );
            })}
          </div>
          <p className="mt-2 text-xs text-muted">Полная запись идёт и в «Логи» (модуль <code>trace</code>). «Нет ответа»/«закрыто» — вероятная потеря соединения с сервером.</p>
        </Card>
      )}

      <Card title="Активность устройств" sub="кто к чему подключается">
        <p className="mb-3 text-xs text-muted">
          Соединения сгруппированы по устройству LAN. «Не отвечают» — без ответа (<code>[UNREPLIED]</code>) или TCP в
          <code> SYN_SENT</code>. Кнопка <b>«Отследить 30с»</b> записывает все соединения устройства 30 секунд (новые,
          без ответа, закрытые) — удобно ловить обрывы в играх/звонках.
        </p>
        {err && <p className="py-8 text-center text-muted">Нет данных ({err}).</p>}
        {!err && !devices.length && <p className="py-8 text-center text-muted">Нет активных устройств LAN.</p>}
        {devices.map((d) => {
          const working = d.working ?? [], failing = d.failing_dsts ?? [];
          return (
            <div key={d.ip} className="mb-3 rounded-[10px] border border-line bg-panel p-3.5">
              <div className="mb-2.5 flex flex-wrap items-center gap-2.5">
                <span className="font-mono text-sm font-bold">{d.ip}</span>
                {d.mac && <span className="font-mono text-xs text-muted">{d.mac}</span>}
                {d.iface && <Badge>{d.iface}</Badge>}
                <span className="ml-auto text-[12.5px]">
                  <span className="text-ok">{d.established} работают</span> ·{" "}
                  <span className={d.failing ? "text-bad" : "text-muted"}>{d.failing} не отвечают</span>
                </span>
                <Button mini onClick={() => startTrace(d.ip)} disabled={tracing}>Отследить 30с</Button>
              </div>
              <div className="grid grid-cols-2 gap-3.5 max-[640px]:grid-cols-1">
                <div>
                  <div className="mb-1.5 text-[12.5px] font-semibold text-ok">Работают ({working.length})</div>
                  <DstList items={working} />
                </div>
                <div>
                  <div className="mb-1.5 flex flex-wrap items-center gap-2 text-[12.5px] font-semibold text-bad">
                    Не отвечают ({failing.length})
                    {failing.length > 0 && <Button mini onClick={() => sendToRun(failing)}>→ В прогон</Button>}
                  </div>
                  <DstList items={failing} />
                </div>
              </div>
            </div>
          );
        })}
      </Card>
    </>
  );
}

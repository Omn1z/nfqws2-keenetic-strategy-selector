import { useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { hostOf } from "@/lib/format";
import { useStore } from "@/providers/StoreProvider";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import type { Device } from "@/types/api";

function DstList({ items }: { items: string[] }) {
  if (!items.length) return <ul className="m-0 list-none p-0 text-xs text-muted">—</ul>;
  return (
    <ul className="m-0 max-h-[168px] list-none overflow-y-auto p-0 font-mono text-xs">
      {items.slice(0, 50).map((x, i) => <li key={i} className="border-b border-line-soft py-0.5 text-ink-soft [overflow-wrap:anywhere]">{x}</li>)}
      {items.length > 50 && <li className="py-0.5 text-muted">…ещё {items.length - 50}</li>}
    </ul>
  );
}

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [err, setErr] = useState("");
  const { setPendingTargets } = useStore();

  usePoll(async () => {
    try { const v = await api<{ devices: Device[] }>("GET", "/api/devices"); setDevices(v.devices ?? []); setErr(""); }
    catch (e) { setErr((e as Error).message); }
  }, 5000);

  const sendToRun = (failing: string[]) => {
    setPendingTargets([...new Set(failing.map(hostOf).filter(Boolean))]);
    location.hash = "runs";
  };

  return (
    <Card title="Активность устройств" sub="кто к чему подключается">
      <p className="mb-3 text-xs text-muted">
        Соединения сгруппированы по устройству LAN (по исходному IP). «Не отвечают» — соединения без ответа
        (<code>[UNREPLIED]</code>) или TCP в <code>SYN_SENT</code>: эти адреса стоит прогнать во вкладке «Прогоны».
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
  );
}

import { useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { usePoll } from "@/lib/hooks";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { toast } from "@/components/ui/Toast";
import ServerPane from "./ServerPane";
import ClientsPane from "./ClientsPane";
import RoutingPane from "./RoutingPane";
import type { Awg2Status, AwgDeployResult } from "@/types/api";

type Sub = "server" | "clients" | "routing";

/** «Сервисы → AWG2»: deploy an AmneziaWG 2.0 server on a VPS over SSH, hand out
 *  client configs, and (Routing tab) split-route LAN traffic through the tunnel. */
export default function AWG2() {
  const [sub, setSub] = useState<Sub>("server");
  const [st, setSt] = useState<Awg2Status | null>(null);
  const [deploying, setDeploying] = useState(false);

  usePoll(async () => {
    try {
      setSt(await api<Awg2Status>("GET", "/api/awg2"));
    } catch {
      /* keep last */
    }
  }, 2500);

  const reload = async () => {
    try {
      setSt(await api<Awg2Status>("GET", "/api/awg2"));
    } catch {
      /* ignore */
    }
  };

  const deploy = async () => {
    if (deploying) return;
    setDeploying(true);
    toast("Запущен деплой AWG2-сервера…", "ok");
    try {
      const d = await api<{ ok: boolean; result: AwgDeployResult; error?: string }>("POST", "/api/awg2/deploy", {});
      await reload();
      if (d.ok) toast("Сервер развёрнут", "ok");
      else toast("Деплой с ошибкой: " + (d.error || d.result?.error || "см. журнал"), "err");
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setDeploying(false);
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

  if (!st) return <Card><span className="text-xs text-muted">Загрузка…</span></Card>;

  const dep = st.last_deploy;
  const statusKind = st.deployed ? (st.status?.up ? "ok" : "warn") : "neutral";
  const statusText = st.deployed ? (st.status?.up ? "развёрнут" : "развёрнут (нет связи)") : "не развёрнут";

  return (
    <>
      <Card
        title="AWG2 — AmneziaWG 2.0 VPN"
        sub="свой сервер на VPS + сплит-роутинг"
        head={
          <div className="flex flex-wrap items-center gap-2">
            <Badge kind={statusKind}>{statusText}</Badge>
            <Button variant="primary" onClick={deploy} disabled={deploying || !st.config.conn.host}>
              {deploying ? "Деплой…" : st.deployed ? "Переразвернуть" : "Развернуть сервер"}
            </Button>
          </div>
        }
      >
        <p className="text-xs text-muted">Разворачивает обфусцированный AmneziaWG 2.0 сервер на вашем VPS по SSH, выдаёт клиентам конфиги и (вкладка «Маршрутизация») гоняет трафик через туннель по доменным зонам/IP. Деплой и маршрутизация — явные действия; роутер не перезагружается.</p>
        {dep && dep.steps?.length > 0 && (
          <div className="mt-3 rounded-lg border border-line bg-line-soft p-2.5">
            <div className="mb-1 text-[11px] font-semibold text-ink-soft">Последний деплой ({dep.method}{dep.wan_iface ? `, WAN ${dep.wan_iface}` : ""}):</div>
            <ul className="space-y-0.5">
              {dep.steps.map((s, i) => (
                <li key={i} className="flex gap-2 text-[11.5px]">
                  <span className={s.ok ? "text-ok" : "text-bad"}>{s.ok ? "✓" : "✗"}</span>
                  <span className="text-ink-soft">{s.name}</span>
                  {s.detail && <span className="text-muted [overflow-wrap:anywhere]">— {s.detail}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>

      <div className="mb-4 inline-flex overflow-hidden rounded-lg border border-line">
        {seg("server", "Сервер")}
        {seg("clients", "Клиенты")}
        {seg("routing", "Маршрутизация")}
      </div>

      {sub === "server" && <ServerPane st={st} reload={reload} />}
      {sub === "clients" && <ClientsPane st={st} reload={reload} />}
      {sub === "routing" && <RoutingPane st={st} reload={reload} />}
    </>
  );
}

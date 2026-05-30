import { useState } from "react";
import { api, downloadFile } from "@/lib/api";
import { cn } from "@/lib/cn";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Modal } from "@/components/ui/Modal";
import { Field, Input, Select } from "@/components/ui/form";
import { tableCls, tdCls } from "@/components/ui/Table";
import type { Awg2Status, AwgPeer, AwgPeerStatus } from "@/types/api";

const human = (n: number): string => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
};
const ago = (unix: number): string => {
  if (!unix) return "—";
  const s = Math.max(0, Math.floor(Date.now() / 1000) - unix);
  if (s < 60) return `${s} с назад`;
  if (s < 3600) return `${Math.floor(s / 60)} мин назад`;
  return `${Math.floor(s / 3600)} ч назад`;
};
const safeFile = (s: string) => (s.replace(/[^\w.-]+/g, "_") || "peer") + ".conf";

export default function ClientsPane({ st, reload }: { st: Awg2Status; reload: () => void }) {
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [tunnel, setTunnel] = useState("full");
  const [busy, setBusy] = useState(false);
  const [show, setShow] = useState<{ name: string; text: string } | null>(null);

  const peers = st.config.peers || [];
  const liveByPub: Record<string, AwgPeerStatus> = {};
  for (const p of st.status?.peers || []) liveByPub[p.public_key] = p;

  const add = async () => {
    setBusy(true);
    try {
      const body = { name: name.trim(), allowed_ips: tunnel === "full" ? "0.0.0.0/0, ::/0" : st.config.subnet || "10.13.13.0/24" };
      const d = await api<{ ok: boolean; peer: AwgPeer; error?: string }>("POST", "/api/awg2/peers", body);
      if (!d.ok) toast(d.error || "Не удалось добавить пир", "err");
      else { toast("Пир добавлен", "ok"); setAdding(false); setName(""); }
      await reload();
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (p: AwgPeer) => {
    if (!(await confirmDialog({ title: `Удалить пир «${p.name}»?`, body: "Конфиг этого клиента перестанет работать.", confirmLabel: "Удалить" }))) return;
    try {
      await api("DELETE", `/api/awg2/peers/${p.id}`);
      toast("Пир удалён", "ok");
      await reload();
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  const dl = async (p: AwgPeer) => {
    try {
      await downloadFile(`/api/awg2/peers/${p.id}/config`, safeFile(p.name));
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  const showConf = async (p: AwgPeer) => {
    try {
      const res = await fetch(`/api/awg2/peers/${p.id}/config`);
      if (!res.ok) throw new Error("Не удалось получить конфиг");
      setShow({ name: p.name, text: await res.text() });
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  return (
    <>
      <Card title="Клиенты (пиры)" sub="роутер обычно — пир №1" head={<Button variant="primary" mini onClick={() => setAdding(true)}>Добавить пир</Button>}>
        {peers.length === 0 ? (
          <p className="text-xs text-muted">Пиров пока нет. Добавьте пир — для него сгенерируются ключ и PSK, а конфиг (.conf) можно импортировать в AmneziaWG-клиент или на роутер.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className={tableCls}>
              <thead>
                <tr>
                  {["Имя", "Адрес", "Статус", "Хендшейк", "↑ / ↓", "Действия"].map((h) => (
                    <th key={h} className={cn(tdCls, "text-left font-medium text-ink-soft")}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {peers.map((p) => {
                  const l = liveByPub[p.public_key];
                  return (
                    <tr key={p.id}>
                      <td className={tdCls}>{p.name}{p.is_router && <Badge kind="neutral" className="ml-1.5">роутер</Badge>}</td>
                      <td className={cn(tdCls, "tabular-nums")}>{p.address}</td>
                      <td className={tdCls}>{st.status ? <Badge kind={l?.online ? "ok" : "neutral"}>{l?.online ? "онлайн" : "офлайн"}</Badge> : <span className="text-muted">—</span>}</td>
                      <td className={tdCls}>{l ? ago(l.latest_handshake) : "—"}</td>
                      <td className={cn(tdCls, "tabular-nums")}>{l ? `${human(l.tx_bytes)} / ${human(l.rx_bytes)}` : "—"}</td>
                      <td className={tdCls}>
                        <div className="flex flex-wrap gap-1.5">
                          <Button mini onClick={() => dl(p)}>Конфиг</Button>
                          <Button mini onClick={() => showConf(p)}>Показать</Button>
                          <Button mini onClick={() => remove(p)}>Удалить</Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {!st.deployed && peers.length > 0 && <p className="mt-2 text-[11px] text-muted">Сервер ещё не развёрнут — пиры применятся при следующем деплое.</p>}
      </Card>

      {adding && (
        <Modal
          title="Добавить пир"
          onClose={() => setAdding(false)}
          actions={<><Button onClick={() => setAdding(false)}>Отмена</Button><Button variant="primary" onClick={add} disabled={busy}>{busy ? "…" : "Добавить"}</Button></>}
        >
          <Field label="Имя пира"><Input value={name} placeholder="напр. keenetic" onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Маршрутизация клиента" className="mt-3"><Select value={tunnel} onChange={(e) => setTunnel(e.target.value)}><option value="full">Весь трафик через VPN (0.0.0.0/0)</option><option value="split">Только подсеть туннеля</option></Select></Field>
          <p className="mt-2 text-[11px] text-muted">Для пира сгенерируются пара ключей и PSK. Конфиг скачивается после добавления.</p>
        </Modal>
      )}

      {show && (
        <Modal
          title={`Конфиг: ${show.name}`}
          onClose={() => setShow(null)}
          actions={<><Button onClick={() => { void navigator.clipboard.writeText(show.text).then(() => toast("Скопировано", "ok"), () => toast("Скопируйте вручную", "err")); }}>Копировать</Button><Button variant="primary" onClick={() => setShow(null)}>Закрыть</Button></>}
        >
          <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap rounded-lg border border-line bg-line-soft p-2 font-mono text-[11px] leading-relaxed [overflow-wrap:anywhere]">{show.text}</pre>
        </Modal>
      )}
    </>
  );
}

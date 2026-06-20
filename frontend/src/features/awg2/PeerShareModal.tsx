import { useEffect, useMemo, useState } from "react";
import QRCode from "qrcode";
import { api, downloadFile } from "@/lib/api";
import { cn } from "@/lib/cn";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import type { Awg2Status, AwgPeer, AwgPeerStatus } from "@/types/api";

type ExportFormat = "conf" | "vpn";

const safeFile = (s: string, format: ExportFormat) => `${s.replace(/[^\w.-]+/g, "_") || "awg-client"}.${format}`;
const human = (n: number): string => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
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

function PeerExport({ peer }: { peer: AwgPeer }) {
  const [format, setFormat] = useState<ExportFormat>("conf");
  const [text, setText] = useState("");
  const [qr, setQr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let stop = false;
    setBusy(true);
    setText("");
    setQr("");
    void (async () => {
      try {
        const res = await fetch(`/api/awg2/peers/${encodeURIComponent(peer.id)}/config?format=${format}`);
        if (!res.ok) throw new Error(await res.text());
        const body = await res.text();
        if (stop) return;
        setText(body);
        setQr(await QRCode.toDataURL(body, { errorCorrectionLevel: "M", margin: 1, width: 220 }));
      } catch (e) {
        if (!stop) toast((e as Error).message || "Не удалось собрать QR", "err");
      } finally {
        if (!stop) setBusy(false);
      }
    })();
    return () => { stop = true; };
  }, [peer.id, format]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      toast("Скопировано", "ok");
    } catch {
      toast("Скопируйте вручную", "err");
    }
  };

  return (
    <div className="rounded-lg border border-line bg-panel p-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-0 flex-1">
          <div className="truncate text-[13px] font-semibold text-ink">{peer.name}</div>
          <div className="font-mono text-[11px] text-muted">{peer.address}</div>
        </div>
        <Select value={format} onChange={(e) => setFormat(e.target.value as ExportFormat)} className="w-28">
          <option value="conf">.conf</option>
          <option value="vpn">.vpn</option>
        </Select>
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-[220px_minmax(0,1fr)]">
        <div className="flex h-[220px] items-center justify-center rounded-lg border border-line bg-white p-2">
          {busy ? <span className="text-xs text-muted">QR...</span> : qr ? <img src={qr} alt="QR" className="h-full w-full object-contain" /> : <span className="text-xs text-bad">нет QR</span>}
        </div>
        <div className="min-w-0">
          <Textarea rows={8} value={text} readOnly className="min-h-[168px]" />
          <div className="mt-2 flex flex-wrap gap-2">
            <Button mini onClick={copy} disabled={!text}>Копировать</Button>
            <Button mini onClick={() => downloadFile(`/api/awg2/peers/${encodeURIComponent(peer.id)}/config?format=${format}`, safeFile(peer.name, format))}>Скачать</Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function PeerShareModal({ st, onClose, reload }: { st: Awg2Status; onClose: () => void; reload: () => void }) {
  const [name, setName] = useState("");
  const [route, setRoute] = useState("full");
  const [busy, setBusy] = useState(false);
  const peers = useMemo(() => (st.config.peers || []).filter((p) => !p.is_router), [st.config.peers]);
  const routerPeer = (st.config.peers || []).find((p) => p.is_router);
  const liveByPub: Record<string, AwgPeerStatus> = {};
  for (const p of st.status?.peers || []) liveByPub[p.public_key] = p;

  const add = async () => {
    setBusy(true);
    try {
      const body = {
        name: name.trim() || "AWG client",
        allowed_ips: route === "full" ? "0.0.0.0/0, ::/0" : st.config.subnet || "10.13.13.0/24",
      };
      const d = await api<{ ok: boolean; peer: AwgPeer; error?: string }>("POST", "/api/awg2/peers", body);
      if (!d.ok) toast(d.error || "Не удалось добавить клиента", "err");
      else {
        toast("Клиент добавлен", "ok");
        setName("");
      }
      await reload();
    } catch (e) {
      toast((e as Error).message, "err");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (p: AwgPeer) => {
    if (!(await confirmDialog({ title: `Удалить клиента «${p.name}»?`, body: "Этот конфиг перестанет подключаться к AWG2.", confirmLabel: "Удалить", danger: true }))) return;
    try {
      await api("DELETE", `/api/awg2/peers/${encodeURIComponent(p.id)}`);
      toast("Клиент удалён", "ok");
      await reload();
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  return (
    <Modal title="Клиенты AWG2" onClose={onClose} actions={<Button variant="primary" onClick={onClose}>Закрыть</Button>}>
      <div className="space-y-4">
        <div className="rounded-lg border border-line bg-line-soft p-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge kind={routerPeer ? "ok" : "warn"}>{routerPeer ? "роутер-пир готов" : "роутер-пир создастся автоматически"}</Badge>
            {routerPeer && <span className="font-mono text-[11px] text-muted">{routerPeer.address}</span>}
          </div>
        </div>

        <div className="rounded-lg border border-line p-3">
          <div className="grid gap-3 sm:grid-cols-[minmax(160px,1fr)_220px_auto] sm:items-end">
            <Field label="Новый клиент">
              <Input value={name} placeholder="телефон, второй роутер, ноутбук" onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Режим">
              <Select value={route} onChange={(e) => setRoute(e.target.value)}>
                <option value="full">Весь трафик</option>
                <option value="split">Только VPN-подсеть</option>
              </Select>
            </Field>
            <Button variant="primary" onClick={add} disabled={busy}>{busy ? "..." : "Добавить"}</Button>
          </div>
        </div>

        {peers.length === 0 ? (
          <p className="text-xs text-muted">Внешних клиентов пока нет. Добавьте клиента и выберите формат экспорта.</p>
        ) : (
          <div className="space-y-3">
            {peers.map((p) => {
              const live = liveByPub[p.public_key];
              return (
                <div key={p.id} className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge kind={live?.online ? "ok" : "neutral"}>{live?.online ? "онлайн" : "офлайн"}</Badge>
                    {live && <span className={cn("text-[11px] text-muted", live.online && "text-ok")}>handshake {ago(live.latest_handshake)} · ↑ {human(live.tx_bytes)} / ↓ {human(live.rx_bytes)}</span>}
                    <Button mini variant="danger" onClick={() => remove(p)}>Удалить</Button>
                  </div>
                  <PeerExport peer={p} />
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Modal>
  );
}

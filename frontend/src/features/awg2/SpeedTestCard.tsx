import { useRef, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";

/** SpeedTestCard runs the backend NDJSON-streaming probe (tunnel vs WAN) with
 *  a size selector + custom-endpoint input. Bytes are read straight into
 *  io.Discard on the router — there is NEVER a temp file on disk.
 *
 *  The frontend opens the POST as a fetch stream, parses each JSON line as it
 *  arrives, and updates a live "tunnel: 4.2 MB / 100 MB · 12 MB/s" readout
 *  so the user sees progress instead of staring at a frozen button. */

type Sample = {
  rx_bytes: number;
  duration_ms: number;
  rx_bytes_per_sec: number;
  http_status: number;
  error?: string;
};
type Result = {
  via_tunnel: Sample;
  via_direct: Sample;
  tunnel_gain_pc: number;
  sample: string;
  error?: string;
};

// Selectel hosts an open HTTP speed-test mirror in RU. Verified reachable from
// both the user's WAN (Zomro provider transit) and the tunnel — Tele2 worked
// from the tunnel but provider routing blackholed it from direct WAN, which
// killed the WAN-side comparison. Selectel peers with every major RU ISP.
const PRESETS: { key: string; label: string; bytes: number; url: string; timeoutMs: number }[] = [
  { key: "10MB",  label: "10 МБ (быстрая проверка)", bytes: 10 * 1024 * 1024,       url: "http://speedtest.selectel.ru/10MB",   timeoutMs: 15000  },
  { key: "100MB", label: "100 МБ (точно)",            bytes: 100 * 1024 * 1024,     url: "http://speedtest.selectel.ru/100MB",  timeoutMs: 60000  },
  { key: "1GB",   label: "1 ГБ (стабильная средняя)",  bytes: 1024 * 1024 * 1024,    url: "http://speedtest.selectel.ru/1GB",    timeoutMs: 180000 },
];

const human = (n: number) => {
  if (!n) return "0 B/с";
  const u = ["B/с", "KB/с", "MB/с", "GB/с"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
};
const humanBytes = (n: number) => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
};

type LiveLane = { bytes: number; rate: number; done?: Sample };

export default function SpeedTestCard() {
  const [preset, setPreset] = useState<string>("10MB");
  const [customUrl, setCustomUrl] = useState<string>("");
  const [customMB, setCustomMB] = useState<string>("100");
  const [tun, setTun] = useState<LiveLane>({ bytes: 0, rate: 0 });
  const [dir, setDir] = useState<LiveLane>({ bytes: 0, rate: 0 });
  const [phase, setPhase] = useState<"idle" | "tunnel" | "direct" | "done">("idle");
  const [result, setResult] = useState<Result | null>(null);
  const [busy, setBusy] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const settings = customUrl.trim() ? {
    url: customUrl.trim(),
    bytes: Math.max(1, parseInt(customMB || "100", 10)) * 1024 * 1024,
    timeoutMs: 180000,
  } : (() => {
    const p = PRESETS.find((x) => x.key === preset) || PRESETS[0];
    return { url: p.url, bytes: p.bytes, timeoutMs: p.timeoutMs };
  })();

  const reset = () => {
    setTun({ bytes: 0, rate: 0 });
    setDir({ bytes: 0, rate: 0 });
    setResult(null);
    setPhase("idle");
  };

  const cancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setBusy(false);
    if (phase !== "done") setPhase("idle");
  };

  const run = async () => {
    if (busy) return;
    reset();
    setBusy(true);
    setPhase("tunnel");
    const ac = new AbortController();
    abortRef.current = ac;
    try {
      const resp = await fetch("/api/awg2/speedtest", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: settings.url, max_bytes: settings.bytes, timeout_ms: settings.timeoutMs }),
        signal: ac.signal,
      });
      if (!resp.ok || !resp.body) {
        const text = await resp.text();
        throw new Error(text || `HTTP ${resp.status}`);
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() || "";
        for (const line of lines) {
          if (!line) continue;
          let evt: any;
          try { evt = JSON.parse(line); } catch { continue; }
          // Phase + progress updates feed the two lane readouts.
          switch (evt.phase) {
            case "tunnel_start":    setPhase("tunnel"); break;
            case "tunnel_progress": setTun({ bytes: evt.bytes ?? 0, rate: evt.rate_bps ?? 0 }); break;
            case "tunnel_done":     if (evt.sample) setTun({ bytes: evt.sample.rx_bytes, rate: evt.sample.rx_bytes_per_sec, done: evt.sample }); break;
            case "direct_start":    setPhase("direct"); break;
            case "direct_progress": setDir({ bytes: evt.bytes ?? 0, rate: evt.rate_bps ?? 0 }); break;
            case "direct_done":     if (evt.sample) setDir({ bytes: evt.sample.rx_bytes, rate: evt.sample.rx_bytes_per_sec, done: evt.sample }); break;
            case "result":          setResult(evt.result as Result); setPhase("done"); break;
          }
        }
      }
    } catch (e) {
      if ((e as Error).name !== "AbortError") toast((e as Error).message, "err");
    } finally {
      setBusy(false);
      abortRef.current = null;
    }
  };

  return (
    <Card
      title="Замер пропускной способности"
      sub="HTTP-загрузка двумя путями: через тоннель и напрямую. Байты пишутся в /dev/null — ничего на диск не сохраняется."
      head={
        busy
          ? <Button mini variant="danger" onClick={cancel}>Отмена</Button>
          : <Button mini variant="primary" onClick={run}>Замерить</Button>
      }
    >
      <div className="flex flex-wrap items-end gap-3 border-b border-line pb-3">
        <div className="min-w-[240px]">
          <label className="block text-[11px] text-muted">Размер сэмпла</label>
          <select value={preset} onChange={(e) => { setPreset(e.target.value); setCustomUrl(""); }}
            disabled={!!customUrl.trim()}
            className="mt-1 h-9 w-full rounded border border-line bg-panel px-2 text-[13px]">
            {PRESETS.map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}
          </select>
        </div>
        <div className="min-w-[280px] flex-1">
          <label className="block text-[11px] text-muted">Свой URL (http://…, перекрывает выбор размера)</label>
          <Input value={customUrl} onChange={(e) => setCustomUrl(e.target.value)} placeholder="http://example.org/100MB.bin" className="mt-1" />
        </div>
        {customUrl.trim() && (
          <div className="w-24">
            <label className="block text-[11px] text-muted">Cap, МБ</label>
            <Input type="number" min={1} max={4096} value={customMB} onChange={(e) => setCustomMB(e.target.value)} className="mt-1" />
          </div>
        )}
      </div>

      {phase === "idle" && !result && (
        <p className="mt-3 text-xs text-muted">
          Жми «Замерить» — селектор сначала качнёт файл через <code>awg0</code> (тоннель), потом тот же URL через WAN.
          По умолчанию <code>speedtest.tele2.net</code> (не блокируется РФ-провайдерами). Можно указать свой http-эндпоинт.
        </p>
      )}

      {(busy || result) && (
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Lane title="через тоннель (awg0)" lane={tun} cap={settings.bytes} active={phase === "tunnel" && busy} />
          <Lane title="напрямую (WAN)"      lane={dir} cap={settings.bytes} active={phase === "direct" && busy} />
        </div>
      )}

      {result && (
        <div className="mt-3 border-t border-line-soft pt-3 text-[13px]">
          {result.error && <p className="mb-2 text-bad">{result.error}</p>}
          {result.via_direct.rx_bytes_per_sec > 0 && result.via_tunnel.rx_bytes_per_sec > 0 && (
            <>
              <span className="text-muted">Разница: </span>
              <Badge kind={result.tunnel_gain_pc >= 0 ? "ok" : "warn"}>
                {result.tunnel_gain_pc >= 0 ? `+${result.tunnel_gain_pc}%` : `${result.tunnel_gain_pc}%`}
              </Badge>
              <span className="ml-2 text-muted">
                {result.tunnel_gain_pc >= 0 ? "тоннель быстрее" : "тоннель медленнее"} прямого канала
              </span>
            </>
          )}
          <p className="mt-2 text-[11px] text-muted">Источник: {result.sample}</p>
        </div>
      )}
    </Card>
  );
}

function Lane({ title, lane, cap, active }: { title: string; lane: LiveLane; cap: number; active: boolean }) {
  const pc = cap > 0 ? Math.min(100, Math.round((lane.bytes / cap) * 100)) : 0;
  const s = lane.done;
  return (
    <div className="rounded-lg border border-line p-3">
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="text-muted">{title}</span>
        {active && <span className="rounded-full bg-accent/20 px-2 py-0.5 text-[10px] uppercase text-accent-d">идёт замер</span>}
      </div>
      <div className="text-[22px] font-bold tabular-nums text-accent-d">{human(lane.rate)}</div>
      <div className="mt-1 text-[11px] text-muted">
        {s
          ? `${humanBytes(s.rx_bytes)} за ${(s.duration_ms / 1000).toFixed(1)}с · HTTP ${s.http_status}${s.error ? " · " + s.error : ""}`
          : (active ? `${humanBytes(lane.bytes)} / ${humanBytes(cap)}` : (lane.bytes > 0 ? humanBytes(lane.bytes) : "ждёт"))}
      </div>
      {/* Progress bar — visible during the active phase and after completion. */}
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded bg-panel-soft">
        <div className="h-full rounded bg-accent transition-[width] duration-200" style={{ width: `${pc}%` }} />
      </div>
    </div>
  );
}

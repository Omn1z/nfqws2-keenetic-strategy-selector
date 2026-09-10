import { useRef, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";
import { cn } from "@/lib/cn";

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

type LiveLane = { bytes: number; rate: number; done?: Sample };
type UnitMode = "bits" | "bytes";

const PRESETS: { key: string; label: string; bytes: number; url: string; timeoutMs: number }[] = [
  { key: "10MB",  label: "10 МБ",  bytes: 10 * 1024 * 1024,       url: "http://speedtest.selectel.ru/10MB",   timeoutMs: 15000  },
  { key: "100MB", label: "100 МБ", bytes: 100 * 1024 * 1024,      url: "http://speedtest.selectel.ru/100MB",  timeoutMs: 60000  },
  { key: "1GB",   label: "1 ГБ",   bytes: 1024 * 1024 * 1024,     url: "http://speedtest.selectel.ru/1GB",    timeoutMs: 180000 },
];

const formatRate = (bytesPerSec: number, mode: UnitMode) => {
  if (!bytesPerSec) return mode === "bits" ? "0 Мбит/с" : "0 МБ/с";
  const units = mode === "bits"
    ? ["бит/с", "Кбит/с", "Мбит/с", "Гбит/с"]
    : ["Б/с", "КБ/с", "МБ/с", "ГБ/с"];
  let value = mode === "bits" ? bytesPerSec * 8 : bytesPerSec;
  const step = mode === "bits" ? 1000 : 1024;
  let idx = 0;
  while (value >= step && idx < units.length - 1) {
    value /= step;
    idx++;
  }
  return `${value.toFixed(value < 10 && idx > 0 ? 1 : 0)} ${units[idx]}`;
};

const humanBytes = (n: number) => {
  if (!n) return "0 Б";
  const units = ["Б", "КБ", "МБ", "ГБ"];
  let value = n;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx++;
  }
  return `${value.toFixed(value < 10 && idx > 0 ? 1 : 0)} ${units[idx]}`;
};

interface SpeedTestPanelProps {
  className?: string;
  serverLabel?: string;
  tunnelIface?: string;
}

export function SpeedTestPanel({ className, serverLabel, tunnelIface }: SpeedTestPanelProps) {
  const [preset, setPreset] = useState("10MB");
  const [customUrl, setCustomUrl] = useState("");
  const [customMB, setCustomMB] = useState("100");
  const [unit, setUnit] = useState<UnitMode>("bits");
  const [tun, setTun] = useState<LiveLane>({ bytes: 0, rate: 0 });
  const [dir, setDir] = useState<LiveLane>({ bytes: 0, rate: 0 });
  const [phase, setPhase] = useState<"idle" | "tunnel" | "direct" | "done">("idle");
  const [result, setResult] = useState<Result | null>(null);
  const [busy, setBusy] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const settings = customUrl.trim()
    ? {
        url: customUrl.trim(),
        bytes: Math.max(1, parseInt(customMB || "100", 10)) * 1024 * 1024,
        timeoutMs: 180000,
      }
    : (() => {
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
        body: JSON.stringify({
          url: settings.url,
          iface: tunnelIface || "",
          max_bytes: settings.bytes,
          timeout_ms: settings.timeoutMs,
        }),
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
          switch (evt.phase) {
            case "tunnel_start": setPhase("tunnel"); break;
            case "tunnel_progress": setTun({ bytes: evt.bytes ?? 0, rate: evt.rate_bps ?? 0 }); break;
            case "tunnel_done": if (evt.sample) setTun({ bytes: evt.sample.rx_bytes, rate: evt.sample.rx_bytes_per_sec, done: evt.sample }); break;
            case "direct_start": setPhase("direct"); break;
            case "direct_progress": setDir({ bytes: evt.bytes ?? 0, rate: evt.rate_bps ?? 0 }); break;
            case "direct_done": if (evt.sample) setDir({ bytes: evt.sample.rx_bytes, rate: evt.sample.rx_bytes_per_sec, done: evt.sample }); break;
            case "result": setResult(evt.result as Result); setPhase("done"); break;
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
    <div className={cn("space-y-3", className)}>
      <div className="flex flex-wrap items-end gap-3">
        <label className="min-w-[142px] flex-1 text-[11px] text-muted sm:flex-none">
          Размер
          <select
            value={preset}
            onChange={(e) => { setPreset(e.target.value); setCustomUrl(""); }}
            disabled={!!customUrl.trim() || busy}
            className="mt-1 h-9 w-full rounded border border-line bg-panel px-2 text-[13px] text-ink"
          >
            {PRESETS.map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}
          </select>
        </label>

        <label className="min-w-[220px] flex-[2] text-[11px] text-muted">
          URL
          <Input
            value={customUrl}
            onChange={(e) => setCustomUrl(e.target.value)}
            placeholder="http://example.org/100MB.bin"
            className="mt-1"
            disabled={busy}
          />
        </label>

        {customUrl.trim() && (
          <label className="w-24 text-[11px] text-muted">
            Cap, МБ
            <Input
              type="number"
              min={1}
              max={4096}
              value={customMB}
              onChange={(e) => setCustomMB(e.target.value)}
              className="mt-1"
              disabled={busy}
            />
          </label>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 border-y border-line-soft py-3">
        <span className="text-[11px] font-medium uppercase text-muted">Единицы</span>
        <div className="inline-flex overflow-hidden rounded-md border border-line">
          <button
            type="button"
            aria-pressed={unit === "bits"}
            onClick={() => setUnit("bits")}
            className={cn("h-8 px-3 text-[12px] font-semibold", unit === "bits" ? "bg-accent text-white" : "bg-panel text-ink-soft hover:bg-line-soft")}
          >
            Мбит/с
          </button>
          <button
            type="button"
            aria-pressed={unit === "bytes"}
            onClick={() => setUnit("bytes")}
            className={cn("h-8 border-l border-line px-3 text-[12px] font-semibold", unit === "bytes" ? "bg-accent text-white" : "bg-panel text-ink-soft hover:bg-line-soft")}
          >
            МБ/с
          </button>
        </div>
        {serverLabel && <Badge kind="neutral">{serverLabel}{tunnelIface ? ` · ${tunnelIface}` : ""}</Badge>}
        <div className="ml-auto flex gap-2">
          {busy ? (
            <Button mini variant="danger" onClick={cancel}>Отмена</Button>
          ) : (
            <Button mini variant="primary" onClick={run}>Замерить</Button>
          )}
        </div>
      </div>

      {(busy || result) && (
        <div className="grid gap-3 sm:grid-cols-2">
          <Lane title={`через туннель${tunnelIface ? ` (${tunnelIface})` : ""}`} lane={tun} cap={settings.bytes} active={phase === "tunnel" && busy} unit={unit} />
          <Lane title="напрямую (WAN)" lane={dir} cap={settings.bytes} active={phase === "direct" && busy} unit={unit} />
        </div>
      )}

      {result && (
        <div className="border-t border-line-soft pt-3 text-[13px]">
          {result.error && <p className="mb-2 text-bad">{result.error}</p>}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted">Итог</span>
            <Badge kind={result.tunnel_gain_pc >= 0 ? "ok" : "warn"}>
              {result.tunnel_gain_pc >= 0 ? `+${result.tunnel_gain_pc}%` : `${result.tunnel_gain_pc}%`}
            </Badge>
            <span className="text-muted">{result.tunnel_gain_pc >= 0 ? "туннель быстрее" : "туннель медленнее"}</span>
          </div>
          <p className="mt-2 text-[11px] text-muted">Источник: {result.sample}</p>
        </div>
      )}

      {!busy && !result && (
        <div className="grid gap-3 text-[12px] sm:grid-cols-2">
          <IdleLane title={`через туннель${tunnelIface ? ` (${tunnelIface})` : ""}`} />
          <IdleLane title="напрямую (WAN)" />
        </div>
      )}
    </div>
  );
}

export default function SpeedTestCard() {
  return (
    <Card title="Замер пропускной способности">
      <SpeedTestPanel />
    </Card>
  );
}

function Lane({ title, lane, cap, active, unit }: { title: string; lane: LiveLane; cap: number; active: boolean; unit: UnitMode }) {
  const pc = cap > 0 ? Math.min(100, Math.round((lane.bytes / cap) * 100)) : 0;
  const s = lane.done;
  return (
    <div className="rounded-lg border border-line p-3">
      <div className="mb-1 flex items-center justify-between gap-2 text-xs">
        <span className="truncate text-muted">{title}</span>
        {active && <span className="shrink-0 rounded-full bg-accent/20 px-2 py-0.5 text-[10px] uppercase text-accent-d">идёт</span>}
      </div>
      <div className="text-[22px] font-bold tabular-nums text-accent-d">{formatRate(lane.rate, unit)}</div>
      <div className="mt-1 text-[11px] text-muted">
        {s
          ? `${humanBytes(s.rx_bytes)} за ${(s.duration_ms / 1000).toFixed(1)}с · HTTP ${s.http_status}${s.error ? " · " + s.error : ""}`
          : active ? `${humanBytes(lane.bytes)} / ${humanBytes(cap)}` : lane.bytes > 0 ? humanBytes(lane.bytes) : "ждёт"}
      </div>
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded bg-panel-soft">
        <div className="h-full rounded bg-accent transition-[width] duration-200" style={{ width: `${pc}%` }} />
      </div>
    </div>
  );
}

function IdleLane({ title }: { title: string }) {
  return (
    <div className="rounded-lg border border-dashed border-line p-3">
      <div className="mb-1 text-xs text-muted">{title}</div>
      <div className="text-[22px] font-bold tabular-nums text-muted">—</div>
      <div className="mt-1 text-[11px] text-muted">ждёт</div>
      <div className="mt-2 h-1.5 w-full rounded bg-panel-soft" />
    </div>
  );
}

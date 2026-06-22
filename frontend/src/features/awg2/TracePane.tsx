import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/form";
import { toast } from "@/components/ui/Toast";
import { confirmDialog } from "@/components/ui/Confirm";

/** One row in the per-flow trace ring. Mirrors awgroute.TraceEntry. */
type TraceEntry = {
  ts: number;
  src?: string;
  kind: "dns" | "sni";
  name: string;
  qtype?: string;
  dst?: string;
  decision: "tunnel" | "direct" | "blocked" | "cdn-skip";
  rule?: number; // 1-based index of the matched rule; absent/0 = no rule (default route)
  reason?: string;
};

type TraceStatus = { enabled: boolean; count: number; cap: number };
type TraceListResp = { status: TraceStatus; entries: TraceEntry[] };
type SortKey = "ts" | "kind" | "name" | "src" | "dst" | "decision";
type SortDir = "asc" | "desc";

const PAGE_SIZES = [10, 25, 50, 100];

const pad = (n: number, w = 2) => String(n).padStart(w, "0");
const fmtTime = (tsNs: number) => {
  const d = new Date(Math.floor(tsNs / 1e6));
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
};

// Decision → badge kind + label + tiny inline icon (so each row's verdict reads at a glance).
const DECISION: Record<TraceEntry["decision"], { k: "ok" | "neutral" | "bad" | "warn"; l: string; icon: string }> = {
  tunnel:     { k: "ok",      l: "tunnel",   icon: "↑" }, // up = via VPN
  direct:     { k: "neutral", l: "direct",   icon: "→" }, // through = native WAN
  blocked:    { k: "bad",     l: "blocked",  icon: "⊘" }, // denied
  "cdn-skip": { k: "warn",    l: "cdn-skip", icon: "≀" }, // skipped a shared CDN IP
};

// Sort-arrow glyph for a column header. Inactive columns show a neutral pair.
const sortGlyph = (key: SortKey, k: SortKey, d: SortDir) => (k === key ? (d === "asc" ? " ▲" : " ▼") : " ⇅");

// quickRule POSTs a "domain:<name>" rule to the top of the global routing list.
// Returns when the backend has persisted, so the caller can refresh.
async function quickRule(name: string, route: "tunnel" | "direct") {
  const domain = "domain:" + name.replace(/^domain:|^full:/, "");
  await api("POST", "/api/awg2/routing/rules/insert-top", {
    domain,
    route,
    name: `trace:${route}:${name}`,
  });
}

export default function TracePane() {
  const [status, setStatus] = useState<TraceStatus | null>(null);
  const [entries, setEntries] = useState<TraceEntry[]>([]);
  const [filterSrc, setFilterSrc] = useState("");
  const [filterName, setFilterName] = useState("");
  const [filterType, setFilterType] = useState("");
  const [filterDecision, setFilterDecision] = useState<"all" | TraceEntry["decision"]>("all");
  const [filterKind, setFilterKind] = useState<"all" | "dns" | "sni">("all");
  const [live, setLive] = useState(true);
  const [pageSize, setPageSize] = useState(25);
  const [page, setPage] = useState(1);
  const [sortKey, setSortKey] = useState<SortKey>("ts");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const sinceRef = useRef<number>(0);
  // Recording policy is owned by /api/system/settings.trace_mode:
  //   off    — never record (we never call /enabled)
  //   auto   — record only while this pane is mounted (enable on mount,
  //            disable on unmount; survives a Refresh)
  //   always — recording stays on; this pane just watches the ring
  // We fetch the mode on mount and act accordingly.
  const [mode, setMode] = useState<"off" | "auto" | "always" | null>(null);
  // Tracks whether WE flipped recording on, so the unmount cleanup only
  // turns it off in the auto case (and leaves it on if global mode is "always").
  const weEnabledRef = useRef<boolean>(false);
  // ipToHost is a per-render map IP-string → friendly hostname, built from the
  // /api/devices snapshot. Lets the Client column show "MyMac (192.168.31.106)"
  // / "MyWin (fe80::abc…)" instead of bare IPs. Refreshed alongside the trace
  // poll so a new device that just came online gets named within a tick.
  const [ipToHost, setIpToHost] = useState<Record<string, string>>({});
  const refreshDeviceMap = async () => {
    try {
      const r = await api<{ devices: { ip: string; ipv6?: string[]; hostname?: string }[] }>("GET", "/api/devices");
      const map: Record<string, string> = {};
      for (const d of r.devices ?? []) {
        if (!d.hostname) continue;
        if (d.ip) map[d.ip] = d.hostname;
        for (const v6 of d.ipv6 ?? []) map[v6] = d.hostname;
      }
      setIpToHost(map);
    } catch { /* keep last */ }
  };
  useEffect(() => {
    void refreshDeviceMap();
    const t = window.setInterval(() => void refreshDeviceMap(), 15_000);
    return () => window.clearInterval(t);
  }, []);

  const fetchOnce = async () => {
    try {
      const r = await api<TraceListResp>("GET", `/api/awg2/trace?since=${sinceRef.current}`);
      setStatus(r.status);
      if (r.entries.length > 0) {
        sinceRef.current = r.entries[r.entries.length - 1].ts;
        setEntries((prev) => {
          const merged = [...prev, ...r.entries];
          return merged.length > 5000 ? merged.slice(merged.length - 5000) : merged;
        });
      }
    } catch {
      /* keep last */
    }
  };

  // Mount: read the global mode; if "auto" and recording is currently off,
  // turn it on (and remember WE did → flip back off on unmount). "off" and
  // "always" are pass-through: we don't touch the recording flag.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const sys = await api<{ trace_mode: "off" | "auto" | "always" }>("GET", "/api/system/settings");
        if (cancelled) return;
        setMode(sys.trace_mode);
        const s = await api<TraceStatus>("GET", "/api/awg2/trace/status");
        if (cancelled) return;
        setStatus(s);
        if (sys.trace_mode === "auto" && !s.enabled) {
          const next = await api<TraceStatus>("POST", "/api/awg2/trace/enabled", { enabled: true });
          if (cancelled) return;
          setStatus(next);
          weEnabledRef.current = true;
        }
        await fetchOnce();
      } catch { /* keep last */ }
    })();
    return () => {
      cancelled = true;
      if (weEnabledRef.current) {
        void api<TraceStatus>("POST", "/api/awg2/trace/enabled", { enabled: false }).catch(() => {});
      }
    };
    /* eslint-disable-next-line react-hooks/exhaustive-deps */
  }, []);
  useEffect(() => {
    if (!live) return;
    const id = window.setInterval(() => { void fetchOnce(); }, 2000);
    return () => window.clearInterval(id);
  }, [live]);

  const onClear = async () => {
    if (!(await confirmDialog({ title: "Очистить весь буфер трассировки?" }))) return;
    try {
      const s = await api<TraceStatus>("POST", "/api/awg2/trace/clear", {});
      setStatus(s);
      setEntries([]);
      sinceRef.current = 0;
      setPage(1);
    } catch (e) {
      toast((e as Error).message, "err");
    }
  };

  const onSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir(key === "ts" ? "desc" : "asc"); }
  };

  // 1) filter, 2) sort, 3) paginate. All re-derive on dep change.
  const filtered = useMemo(() => {
    const sn = filterSrc.trim().toLowerCase();
    const nm = filterName.trim().toLowerCase();
    const tp = filterType.trim().toLowerCase();
    return entries.filter((e) => {
      if (filterKind !== "all" && e.kind !== filterKind) return false;
      if (filterDecision !== "all" && e.decision !== filterDecision) return false;
      if (sn) {
        const src = (e.src ?? "").toLowerCase();
        const host = (ipToHost[e.src ?? ""] ?? "").toLowerCase();
        if (!src.includes(sn) && !host.includes(sn)) return false;
      }
      if (nm && !e.name.toLowerCase().includes(nm) && !(e.dst ?? "").toLowerCase().includes(nm)) return false;
      if (tp && !(e.qtype ?? "").toLowerCase().includes(tp)) return false;
      return true;
    });
  }, [entries, filterSrc, filterName, filterType, filterKind, filterDecision, ipToHost]);

  const sorted = useMemo(() => {
    const cmp = (a: TraceEntry, b: TraceEntry): number => {
      switch (sortKey) {
        case "ts":       return a.ts - b.ts;
        case "kind":     return a.kind.localeCompare(b.kind);
        case "name":     return a.name.localeCompare(b.name);
        case "src":      return (a.src ?? "").localeCompare(b.src ?? "");
        case "dst":      return (a.dst ?? "").localeCompare(b.dst ?? "");
        case "decision": return a.decision.localeCompare(b.decision);
      }
    };
    const arr = filtered.slice().sort(cmp);
    return sortDir === "asc" ? arr : arr.reverse();
  }, [filtered, sortKey, sortDir]);

  const total = sorted.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  useEffect(() => { if (page > pages) setPage(pages); }, [page, pages]);
  const pageStart = (page - 1) * pageSize;
  const pageEnd = Math.min(pageStart + pageSize, total);
  const slice = sorted.slice(pageStart, pageEnd);

  return (
    <Card>
      {/* Header: title + Live + Refresh */}
      <div className="flex flex-wrap items-center gap-3 border-b border-line pb-3">
        <h2 className="text-[15px] font-semibold">Recent Queries</h2>
        <div className="text-xs text-muted">
          {status ? `${status.count}/${status.cap} в буфере` : "статус…"}
        </div>
        <div className="ml-auto flex items-center gap-3">
          <label className="flex cursor-pointer select-none items-center gap-1.5 text-[12px]">
            <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} className="h-3.5 w-3.5 cursor-pointer accent-accent" />
            Live update
          </label>
          <Button mini variant="primary" onClick={() => void fetchOnce()}>Refresh</Button>
        </div>
      </div>

      {/* Sub-header: clear + global type filters. Recording mode lives in the
          global system settings — show only its current effective state here. */}
      <div className="flex flex-wrap items-center gap-3 py-3">
        <span className={cn(
          "rounded px-2 py-0.5 text-[11px] font-medium",
          status?.enabled ? "bg-good-bg text-good" : "bg-panel-soft text-muted",
        )}>
          {mode === "off"     && "режим: выкл (только счётчики)"}
          {mode === "auto"    && (status?.enabled ? "режим: авто — пишу" : "режим: авто — пауза")}
          {mode === "always"  && "режим: всегда писать"}
          {mode === null      && "режим: …"}
        </span>
        <Button mini variant="ghost" onClick={onClear}>Очистить</Button>
        <span className="ml-2 text-[12px] text-muted">Тип:</span>
        <select value={filterKind} onChange={(e) => { setFilterKind(e.target.value as typeof filterKind); setPage(1); }} className="h-7 rounded border border-line bg-panel px-2 text-[12px]">
          <option value="all">все</option>
          <option value="dns">DNS</option>
          <option value="sni">SNI</option>
        </select>
        <span className="ml-2 text-[12px] text-muted">Решение:</span>
        <select value={filterDecision} onChange={(e) => { setFilterDecision(e.target.value as typeof filterDecision); setPage(1); }} className="h-7 rounded border border-line bg-panel px-2 text-[12px]">
          <option value="all">все</option>
          <option value="tunnel">tunnel</option>
          <option value="direct">direct</option>
          <option value="blocked">blocked</option>
          <option value="cdn-skip">cdn-skip</option>
        </select>
        <span className="ml-auto text-[12px] text-muted">
          Show
          <select value={pageSize} onChange={(e) => { setPageSize(parseInt(e.target.value, 10)); setPage(1); }} className="mx-1 h-7 rounded border border-line bg-panel px-1 text-[12px]">
            {PAGE_SIZES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          entries
        </span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded border border-line">
        <table className="w-full text-[11px] md:text-[12px]">
          <thead className="bg-panel-soft text-[10px] uppercase text-muted md:text-[11px]">
            <tr>
              <Th onClick={() => onSort("ts")}>Время{sortGlyph("ts", sortKey, sortDir)}</Th>
              <Th onClick={() => onSort("decision")} className="w-[40px] text-center">●</Th>
              <Th onClick={() => onSort("kind")} className="hidden md:table-cell">Kind{sortGlyph("kind", sortKey, sortDir)}</Th>
              <Th className="hidden lg:table-cell">Type</Th>
              <Th onClick={() => onSort("name")}>Domain / SNI{sortGlyph("name", sortKey, sortDir)}</Th>
              <Th onClick={() => onSort("src")} className="hidden sm:table-cell">Client{sortGlyph("src", sortKey, sortDir)}</Th>
              <Th onClick={() => onSort("dst")} className="hidden lg:table-cell">Dst{sortGlyph("dst", sortKey, sortDir)}</Th>
              <Th onClick={() => onSort("decision")}>Решение{sortGlyph("decision", sortKey, sortDir)}</Th>
              <Th className="w-[110px] text-right">Действия</Th>
            </tr>
          </thead>
          <tbody>
            {slice.length === 0 && (
              <tr>
                <td colSpan={9} className="px-2 py-6 text-center text-muted">
                  {status?.enabled ? "Ждём трафика…" : "Запись выключена. Нажми «Включить запись» сверху."}
                </td>
              </tr>
            )}
            {slice.map((e, i) => {
              const ds = DECISION[e.decision];
              return (
                <tr key={`${e.ts}-${i}`} className={cn("border-t border-line", i % 2 ? "bg-panel-soft/40" : "")}>
                  <td className="whitespace-nowrap px-2 py-1 font-mono">{fmtTime(e.ts)}</td>
                  <td className="px-2 py-1 text-center font-mono">
                    <span className={cn(
                      "inline-flex h-5 w-5 items-center justify-center rounded-full text-[11px]",
                      ds.k === "ok"      && "bg-good-bg text-good",
                      ds.k === "neutral" && "bg-panel-soft text-ink-soft",
                      ds.k === "bad"     && "bg-bad-bg text-bad",
                      ds.k === "warn"    && "bg-warn-bg text-warn",
                    )} title={ds.l}>{ds.icon}</span>
                  </td>
                  <td className="hidden whitespace-nowrap px-2 py-1 uppercase md:table-cell">{e.kind}</td>
                  <td className="hidden whitespace-nowrap px-2 py-1 lg:table-cell">{e.qtype || ""}</td>
                  <td className="px-2 py-1 font-mono">
                    <div className="truncate" title={e.reason || ""}>{e.name}</div>
                  </td>
                  <td className="hidden whitespace-nowrap px-2 py-1 sm:table-cell">
                    {e.src
                      ? (() => {
                          const host = ipToHost[e.src];
                          return host
                            ? <span title={e.src}><b className="text-ink">{host}</b> <span className="text-[10px] text-muted">{e.src.includes(":") ? "v6" : "v4"}</span></span>
                            : <span className="font-mono">{e.src}</span>;
                        })()
                      : <span className="text-muted">—</span>}
                  </td>
                  <td className="hidden whitespace-nowrap px-2 py-1 font-mono lg:table-cell">{e.dst || ""}</td>
                  <td className="whitespace-nowrap px-2 py-1">
                    {/* Tooltip on the badge surfaces the FULL reason (правило #N
                        / pi-hole sinkhole / CDN skip / default-route etc.). The
                        rule index is part of the reason text so dropping the
                        separate "Правило" column is lossless. */}
                    <span title={e.reason || ds.l}><Badge kind={ds.k}>{ds.l}</Badge></span>
                  </td>
                  <td className="whitespace-nowrap px-2 py-1 text-right">
                    {/* Context-aware: don't offer the action that matches the row's
                        current decision (already routed that way). For blocked /
                        cdn-skip rows the routing isn't actually applied to the dst,
                        so both actions remain useful. */}
                    {e.decision !== "tunnel" && (
                      <button type="button" title={`Всегда через VPN: ${e.name}`}
                        className="rounded border border-line bg-panel px-1.5 py-0.5 text-[11px] hover:bg-line-soft"
                        onClick={async () => {
                          try { await quickRule(e.name, "tunnel"); toast(`Правило добавлено: ${e.name} → через VPN`, "ok"); }
                          catch (err) { toast((err as Error).message, "err"); }
                        }}>↑ VPN</button>
                    )}
                    {e.decision !== "direct" && (
                      <button type="button" title={`Всегда мимо VPN: ${e.name}`}
                        className="ml-1 rounded border border-line bg-panel px-1.5 py-0.5 text-[11px] hover:bg-line-soft"
                        onClick={async () => {
                          try { await quickRule(e.name, "direct"); toast(`Правило добавлено: ${e.name} → мимо VPN`, "ok"); }
                          catch (err) { toast((err as Error).message, "err"); }
                        }}>→ direct</button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
          {/* Pi-hole-style filter inputs in the footer row */}
          <tfoot className="bg-panel-soft">
            <tr>
              <td className="px-2 py-1 text-[11px] uppercase text-muted">Время</td>
              <td className="px-2 py-1" />
              <td className="px-2 py-1 text-[11px] uppercase text-muted">Kind</td>
              <td className="px-2 py-1">
                <Input value={filterType} onChange={(e) => { setFilterType(e.target.value); setPage(1); }} placeholder="A/AAAA/…" className="h-7 text-[12px]" />
              </td>
              <td className="px-2 py-1">
                <Input value={filterName} onChange={(e) => { setFilterName(e.target.value); setPage(1); }} placeholder="Domain / dst IP" className="h-7 text-[12px]" />
              </td>
              <td className="px-2 py-1">
                <Input value={filterSrc} onChange={(e) => { setFilterSrc(e.target.value); setPage(1); }} placeholder="Client" className="h-7 text-[12px]" />
              </td>
              <td className="px-2 py-1" />
              <td className="px-2 py-1 text-[11px] uppercase text-muted">Решение</td>
              <td className="px-2 py-1" />
            </tr>
          </tfoot>
        </table>
      </div>

      {/* Footer: pagination */}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[12px] text-muted">
        <div>
          {total === 0 ? "Showing 0" : `Showing ${pageStart + 1} to ${pageEnd} of ${total}`}
        </div>
        <div className="flex items-center gap-1">
          <Button mini variant="ghost" onClick={() => setPage(1)} disabled={page <= 1}>«</Button>
          <Button mini variant="ghost" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>‹</Button>
          <span className="px-2 tabular-nums">{page} / {pages}</span>
          <Button mini variant="ghost" onClick={() => setPage((p) => Math.min(pages, p + 1))} disabled={page >= pages}>›</Button>
          <Button mini variant="ghost" onClick={() => setPage(pages)} disabled={page >= pages}>»</Button>
        </div>
      </div>

      <p className="mt-3 text-[11px] text-muted">
        DNS-строки видны только когда трафик идёт через наш :5354 (LAN → router DNS).
        Для DoH/DoT-клиентов работает SNI-сниффер (включается в зонах).
        Src=127.0.0.1 означает, что pi-hole в цепочке скрыл реальный client IP — это поправлю отдельно.
      </p>
    </Card>
  );
}

function Th({ children, onClick, className }: { children: React.ReactNode; onClick?: () => void; className?: string }) {
  return (
    <th
      onClick={onClick}
      className={cn("select-none px-2 py-1.5 text-left font-semibold", onClick && "cursor-pointer hover:text-ink", className)}
    >
      {children}
    </th>
  );
}

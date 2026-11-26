import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";
import { toast } from "@/components/ui/Toast";
import type { Blobs, Config, DnsServer, GeoFile, List, Run, RunRequest, Strategy } from "@/types/api";

interface Store {
  config: Config | null;
  lists: List[];
  strategies: Strategy[];
  dns: DnsServer[];
  geo: GeoFile[];
  blobs: Blobs;
  /** Active run, lifted here so it survives tab switches (poll keeps running). */
  activeRun: Run | null;
  runActive: boolean;
  startRun: (req: RunRequest) => Promise<Run>;
  cancelRun: () => Promise<void>;
  addRunThread: () => Promise<void>;
  /** Devices "→ run" hand-off: failing IPs to pre-fill the Runs text source. */
  pendingTargets: string[] | null;
  setPendingTargets: (t: string[] | null) => void;
  reloadConfig: () => Promise<void>;
  reloadLists: () => Promise<void>;
  reloadStrategies: () => Promise<void>;
  loadStrategies: () => Promise<void>;
  reloadDns: () => Promise<void>;
  reloadGeo: () => Promise<void>;
  loadGeo: () => Promise<void>;
  reloadBlobs: () => Promise<void>;
}

const StoreCtx = createContext<Store | null>(null);

export function useStore({ geo = false, strategies = false }: { geo?: boolean; strategies?: boolean } = {}): Store {
  const ctx = useContext(StoreCtx);
  if (!ctx) throw new Error("useStore must be used within <StoreProvider>");
  const { loadGeo, loadStrategies } = ctx;
  useEffect(() => {
    if (geo) void loadGeo();
    if (strategies) void loadStrategies();
  }, [geo, strategies, loadGeo, loadStrategies]);
  return ctx;
}

const err = (e: unknown) => toast((e as Error).message, "err");

// A successful read is shared across tabs. A mutation forces a new read, whose
// result takes precedence even when an older request finishes afterwards.
export function lazyCatalog<T>(read: () => Promise<T[] | null>, publish: (items: T[]) => void, onError?: (cause: unknown) => void) {
  let current: Promise<void> | undefined;
  function reload(): Promise<void> {
    const request = read().then(items => {
      if (current === request) publish(items ?? []);
    }).catch(cause => {
      if (current !== request) return;
      current = undefined;
      onError?.(cause);
    });
    current = request;
    return request;
  }
  return { load: () => current ?? reload(), reload };
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<Config | null>(null);
  const [lists, setLists] = useState<List[]>([]);
  const [strategies, setStrategies] = useState<Strategy[]>([]);
  const [dns, setDns] = useState<DnsServer[]>([]);
  const [geo, setGeo] = useState<GeoFile[]>([]);
  const [blobs, setBlobs] = useState<Blobs>({ system: [], custom: [], trash: [] });
  const [activeRun, setActiveRun] = useState<Run | null>(null);
  const [runActive, setRunActive] = useState(false);
  const [pendingTargets, setPendingTargets] = useState<string[] | null>(null);

  const reloadConfig = useCallback(async () => { try { setConfig(await api<Config>("GET", "/api/config")); } catch { /* non-fatal */ } }, []);
  const reloadLists = useCallback(async () => { try { setLists((await api<List[] | null>("GET", "/api/lists")) ?? []); } catch (e) { err(e); } }, []);
  const [strategyCatalog] = useState(() => lazyCatalog(() => api<Strategy[] | null>("GET", "/api/strategies"), setStrategies, err));
  const reloadDns = useCallback(async () => { try { setDns((await api<DnsServer[] | null>("GET", "/api/dns")) ?? []); } catch (e) { err(e); } }, []);
  const [geoCatalog] = useState(() => lazyCatalog(() => api<GeoFile[] | null>("GET", "/api/geo"), setGeo));
  const reloadBlobs = useCallback(async () => {
    try {
      const b = await api<Blobs>("GET", "/api/blobs");
      setBlobs({ system: b.system ?? [], custom: b.custom ?? [], trash: b.trash ?? [] });
    } catch (e) { err(e); }
  }, []);

  useEffect(() => {
    void reloadConfig(); void reloadLists(); void reloadDns(); void reloadBlobs();
  }, [reloadConfig, reloadLists, reloadDns, reloadBlobs]);

  // Active-run poll lives here (not in the Runs tab) so the run keeps updating and
  // is still shown after switching tabs.
  usePoll(async () => {
    if (!activeRun) return;
    try {
      const r = await api<Run>("GET", `/api/runs/${activeRun.id}`);
      setActiveRun(r);
      if (r.status !== "running") {
        setRunActive(false);
        void reloadLists();
        const ok = (r.results ?? []).filter((x) => x.success).length;
        if (r.status === "cancelled") toast("Прогон отменён", "ok");
        else if (r.auto && r.total === 0) toast("Цели доступны без обхода — обходить нечего", "ok");
        else toast(`Прогон завершён: найдено рабочих ${ok}`, "ok");
      }
    } catch (e) { setRunActive(false); err(e); }
  }, 1000, runActive);

  const startRun = useCallback(async (req: RunRequest) => {
    const r = await api<Run>("POST", "/api/runs", req);
    setActiveRun(r); setRunActive(true);
    return r;
  }, []);
  const cancelRun = useCallback(async () => {
    setRunActive(false);
    if (activeRun) { try { await api("POST", `/api/runs/${activeRun.id}/cancel`); } catch { /* already stopping */ } }
  }, [activeRun]);
  const addRunThread = useCallback(async () => {
    if (!activeRun) return;
    const next = (activeRun.threads || 1) + 1;
    if (next > 8) { toast("Максимум 8 потоков", "err"); return; }
    try { const d = await api<{ threads: number }>("POST", `/api/runs/${activeRun.id}/threads`, { threads: next }); toast(`Потоков: ${d.threads}`, "ok"); }
    catch (e) { err(e); }
  }, [activeRun]);

  const value: Store = {
    config, lists, strategies, dns, geo, blobs,
    activeRun, runActive, startRun, cancelRun, addRunThread,
    pendingTargets, setPendingTargets,
    reloadConfig, reloadLists, reloadDns, reloadBlobs,
    loadGeo: geoCatalog.load, reloadGeo: geoCatalog.reload,
    loadStrategies: strategyCatalog.load, reloadStrategies: strategyCatalog.reload,
  };
  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>;
}

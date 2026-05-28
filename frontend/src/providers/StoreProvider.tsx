import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api } from "@/lib/api";
import { toast } from "@/components/ui/Toast";
import type { Blobs, Config, DnsServer, GeoFile, List, Strategy } from "@/types/api";

interface Store {
  config: Config | null;
  lists: List[];
  strategies: Strategy[];
  dns: DnsServer[];
  geo: GeoFile[];
  blobs: Blobs;
  /** Devices "→ run" hand-off: failing IPs to pre-fill the Runs text source. */
  pendingTargets: string[] | null;
  setPendingTargets: (t: string[] | null) => void;
  reloadConfig: () => Promise<void>;
  reloadLists: () => Promise<void>;
  reloadStrategies: () => Promise<void>;
  reloadDns: () => Promise<void>;
  reloadGeo: () => Promise<void>;
  reloadBlobs: () => Promise<void>;
}

const StoreCtx = createContext<Store | null>(null);

export function useStore(): Store {
  const ctx = useContext(StoreCtx);
  if (!ctx) throw new Error("useStore must be used within <StoreProvider>");
  return ctx;
}

const err = (e: unknown) => toast((e as Error).message, "err");

export function StoreProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<Config | null>(null);
  const [lists, setLists] = useState<List[]>([]);
  const [strategies, setStrategies] = useState<Strategy[]>([]);
  const [dns, setDns] = useState<DnsServer[]>([]);
  const [geo, setGeo] = useState<GeoFile[]>([]);
  const [blobs, setBlobs] = useState<Blobs>({ system: [], custom: [] });
  const [pendingTargets, setPendingTargets] = useState<string[] | null>(null);

  const reloadConfig = useCallback(async () => { try { setConfig(await api<Config>("GET", "/api/config")); } catch { /* non-fatal */ } }, []);
  const reloadLists = useCallback(async () => { try { setLists((await api<List[] | null>("GET", "/api/lists")) ?? []); } catch (e) { err(e); } }, []);
  const reloadStrategies = useCallback(async () => { try { setStrategies((await api<Strategy[] | null>("GET", "/api/strategies")) ?? []); } catch (e) { err(e); } }, []);
  const reloadDns = useCallback(async () => { try { setDns((await api<DnsServer[] | null>("GET", "/api/dns")) ?? []); } catch (e) { err(e); } }, []);
  const reloadGeo = useCallback(async () => { try { setGeo((await api<GeoFile[] | null>("GET", "/api/geo")) ?? []); } catch { /* non-fatal */ } }, []);
  const reloadBlobs = useCallback(async () => {
    try {
      const b = await api<Blobs>("GET", "/api/blobs");
      setBlobs({ system: b.system ?? [], custom: b.custom ?? [] });
    } catch (e) { err(e); }
  }, []);

  useEffect(() => {
    void reloadConfig(); void reloadLists(); void reloadStrategies();
    void reloadDns(); void reloadGeo(); void reloadBlobs();
  }, [reloadConfig, reloadLists, reloadStrategies, reloadDns, reloadGeo, reloadBlobs]);

  const value: Store = {
    config, lists, strategies, dns, geo, blobs, pendingTargets, setPendingTargets,
    reloadConfig, reloadLists, reloadStrategies, reloadDns, reloadGeo, reloadBlobs,
  };
  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>;
}

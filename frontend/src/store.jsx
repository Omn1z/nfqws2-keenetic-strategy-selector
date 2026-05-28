import { createContext, useContext, useState, useCallback, useEffect } from "react";
import { api } from "./api.js";
import { toast } from "./toast.jsx";

// Shared data used across tabs (config, lists, strategies, dns, geo, blobs) plus
// a cross-tab hand-off for the Devices "→ run" action.
const StoreCtx = createContext(null);
export const useStore = () => useContext(StoreCtx);

export function StoreProvider({ children }) {
  const [config, setConfig] = useState(null);
  const [lists, setLists] = useState([]);
  const [strategies, setStrategies] = useState([]);
  const [dns, setDns] = useState([]);
  const [geo, setGeo] = useState([]);
  const [blobs, setBlobs] = useState({ custom: [], system: [] });
  const [pendingTargets, setPendingTargets] = useState(null); // Devices → Runs hand-off

  const reloadConfig = useCallback(async () => { try { setConfig(await api("GET", "/api/config")); } catch (_) {} }, []);
  const reloadLists = useCallback(async () => { try { setLists((await api("GET", "/api/lists")) || []); } catch (e) { toast(e.message, "err"); } }, []);
  const reloadStrategies = useCallback(async () => { try { setStrategies((await api("GET", "/api/strategies")) || []); } catch (e) { toast(e.message, "err"); } }, []);
  const reloadDns = useCallback(async () => { try { setDns((await api("GET", "/api/dns")) || []); } catch (e) { toast(e.message, "err"); } }, []);
  const reloadGeo = useCallback(async () => { try { setGeo((await api("GET", "/api/geo")) || []); } catch (_) {} }, []);
  const reloadBlobs = useCallback(async () => {
    try { const b = await api("GET", "/api/blobs"); setBlobs({ custom: b.custom || [], system: b.system || [] }); }
    catch (e) { toast(e.message, "err"); }
  }, []);

  useEffect(() => {
    reloadConfig(); reloadLists(); reloadStrategies(); reloadDns(); reloadGeo(); reloadBlobs();
  }, [reloadConfig, reloadLists, reloadStrategies, reloadDns, reloadGeo, reloadBlobs]);

  const value = {
    config, lists, strategies, dns, geo, blobs, pendingTargets, setPendingTargets,
    reloadConfig, reloadLists, reloadStrategies, reloadDns, reloadGeo, reloadBlobs,
  };
  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>;
}

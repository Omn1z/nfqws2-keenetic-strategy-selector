import type { GeoAutoConfig } from "@/types/api";

const settings = ({ enabled, interval_hours, geosite_url, geoip_url }: GeoAutoConfig) => ({ enabled, interval_hours, geosite_url, geoip_url });
export const sameGeoAutoSettings = (first: GeoAutoConfig, second: GeoAutoConfig): boolean =>
  first.enabled === second.enabled && first.interval_hours === second.interval_hours && first.geosite_url === second.geosite_url && first.geoip_url === second.geoip_url;

/** Preserve newer input when an earlier blur-save acknowledges its snapshot. */
export function mergeGeoAutoDraft(current: GeoAutoConfig | null, acknowledged: GeoAutoConfig, requested: GeoAutoConfig): GeoAutoConfig {
  return current && !sameGeoAutoSettings(current, requested) ? { ...acknowledged, ...settings(current) } : acknowledged;
}

/** Blur, toggle and fetch clicks share an ordered queue; no user action is dropped. */
export function createGeoAutoRequests({ save, fetchNow, onAcknowledged }: {
  save: (cfg: GeoAutoConfig) => Promise<GeoAutoConfig>;
  fetchNow: () => Promise<GeoAutoConfig>;
  onAcknowledged: (cfg: GeoAutoConfig, requested: GeoAutoConfig) => void;
}) {
  let acknowledged: GeoAutoConfig | null = null;
  let tail: Promise<void> = Promise.resolve();
  const accept = (next: GeoAutoConfig, requested: GeoAutoConfig) => { acknowledged = next; onAcknowledged(next, requested); return next; };
  const enqueue = (operation: () => Promise<GeoAutoConfig>) => {
    const result = tail.then(operation);
    tail = result.then(() => {}, () => {});
    return result;
  };
  const persist = async (requested: GeoAutoConfig) => {
    if (acknowledged && sameGeoAutoSettings(acknowledged, requested)) return acknowledged;
    return accept(await save({ ...requested }), requested);
  };
  return {
    observe: (next: GeoAutoConfig) => accept(next, next),
    save: (requested: GeoAutoConfig) => {
      const snapshot = { ...requested };
      return enqueue(() => persist(snapshot));
    },
    fetch: (requested: GeoAutoConfig) => {
      const snapshot = { ...requested };
      return enqueue(async () => {
        await persist(snapshot);
        return accept(await fetchNow(), snapshot);
      });
    },
  };
}

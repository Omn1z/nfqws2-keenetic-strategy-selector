import { useEffect, useRef, useState } from "react";

/** Run fn() once on mount and every `ms` while `active` is true; stops on unmount. */
export function usePoll(fn: () => void | Promise<void>, ms: number, active = true): void {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    if (!active) return;
    let alive = true;
    const tick = () => {
      if (alive) void ref.current();
    };
    tick();
    const id = setInterval(tick, ms);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [ms, active]);
}

/** Active tab synced to location.hash (falls back to `fallback` for unknown hashes). */
export function useHashTab(valid: readonly string[], fallback: string): [string, (t: string) => void] {
  const read = () => {
    const t = location.hash.replace(/^#/, "");
    return valid.includes(t) ? t : fallback;
  };
  const [tab, setTab] = useState<string>(read);
  useEffect(() => {
    const onHash = () => setTab(read());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return [tab, (t: string) => { location.hash = t; setTab(t); }];
}

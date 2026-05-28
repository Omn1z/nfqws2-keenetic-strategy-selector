import { useEffect, useRef } from "react";

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

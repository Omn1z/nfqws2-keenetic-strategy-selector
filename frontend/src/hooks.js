import { useEffect, useRef } from "react";

// usePoll runs fn() once immediately and then every `ms` while `active` is true.
// It stops on unmount (so leaving a tab stops its polling). fn may be async.
export function usePoll(fn, ms, active = true) {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    if (!active) return;
    let alive = true;
    const tick = () => { if (alive) ref.current(); };
    tick();
    const id = setInterval(tick, ms);
    return () => { alive = false; clearInterval(id); };
  }, [ms, active]);
}

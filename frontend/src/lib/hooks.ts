import { useEffect, useRef } from "react";

/** Poll serially: a slow request must not accumulate more requests behind it.
 * The signal lets consumers discard/abort a request when polling is paused. */
export function usePoll(fn: (signal: AbortSignal) => void | Promise<void>, ms: number, active = true): void {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      if (controller.signal.aborted) return;
      try {
        await ref.current(controller.signal);
      } catch {
        // The consumer owns error reporting; a failed poll still needs a retry.
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(() => { void tick(); }, ms);
      }
    };
    void tick();
    return () => {
      controller.abort();
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [ms, active]);
}

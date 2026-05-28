import { useEffect, useState } from "react";

// Path-based (History API) routing. The whole UI is one embedded index.html and
// the server serves it for any non-/api path, so /lists, /runs, … deep-link and
// refresh cleanly — no hash needed.

/** The active tab from the first path segment (/lists → "lists"; "/" → fallback). */
export function tabFromPath(valid: readonly string[], fallback: string): string {
  const seg = location.pathname.replace(/^\/+/, "").split("/")[0];
  return valid.includes(seg) ? seg : fallback;
}

/** Navigate to a tab via pushState (no reload). Callable from anywhere, e.g. the
 *  Devices → Runs hand-off. Dispatches an event so useTab re-reads the path. */
export function navigate(tab: string): void {
  const path = "/" + tab;
  if (location.pathname !== path) history.pushState(null, "", path);
  window.dispatchEvent(new Event("n2s:navigate"));
}

/** Active tab synced to location.pathname; updates on navigate() and back/forward. */
export function useTab(valid: readonly string[], fallback: string): [string, (t: string) => void] {
  const [tab, setTab] = useState(() => tabFromPath(valid, fallback));
  useEffect(() => {
    const on = () => setTab(tabFromPath(valid, fallback));
    window.addEventListener("popstate", on);
    window.addEventListener("n2s:navigate", on);
    return () => {
      window.removeEventListener("popstate", on);
      window.removeEventListener("n2s:navigate", on);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return [tab, navigate];
}

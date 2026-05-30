import { useEffect, useState } from "react";

export type ThemeMode = "auto" | "light" | "dark";
const MODES: ThemeMode[] = ["auto", "light", "dark"];
const resolvesDark = (m: ThemeMode) => m === "dark" || (m === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);

const readMode = (): ThemeMode => {
  const q = location.search.match(/[?&]theme=(auto|light|dark)/)?.[1] as ThemeMode | undefined;
  return q ?? ((localStorage.getItem("theme") as ThemeMode | null) ?? "auto");
};
const applyHtml = (m: ThemeMode) => { document.documentElement.dataset.theme = resolvesDark(m) ? "dark" : "light"; };

/** Light/dark/auto persisted in localStorage and reflected on <html data-theme>.
 *  Default "auto" follows the system preference. The mode is shared across all
 *  hook instances (TopBar / SideNav drawer / System settings) via an event, so
 *  changing it in one place updates the controls everywhere. */
export function useTheme(): [ThemeMode, () => void, (m: ThemeMode) => void] {
  const [mode, setMode] = useState<ThemeMode>(readMode);
  useEffect(() => {
    applyHtml(mode);
    const onExternal = () => setMode(readMode());
    window.addEventListener("n2s:theme", onExternal);
    let mq: MediaQueryList | null = null;
    let onChange: (() => void) | null = null;
    if (mode === "auto") {
      mq = matchMedia("(prefers-color-scheme: dark)");
      onChange = () => applyHtml("auto");
      mq.addEventListener("change", onChange);
    }
    return () => {
      window.removeEventListener("n2s:theme", onExternal);
      if (mq && onChange) mq.removeEventListener("change", onChange);
    };
  }, [mode]);

  const set = (m: ThemeMode) => {
    localStorage.setItem("theme", m);
    setMode(m);
    window.dispatchEvent(new Event("n2s:theme")); // sync the other hook instances
  };
  const cycle = () => set(MODES[(MODES.indexOf(mode) + 1) % MODES.length]);
  return [mode, cycle, set];
}

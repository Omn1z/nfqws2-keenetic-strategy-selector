import { useEffect, useState } from "react";

export type ThemeMode = "auto" | "light" | "dark";
const MODES: ThemeMode[] = ["auto", "light", "dark"];
const resolvesDark = (m: ThemeMode) => m === "dark" || (m === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);

/** Light/dark/auto persisted in localStorage and reflected on <html data-theme>.
 *  Default "auto" follows the system preference. */
export function useTheme(): [ThemeMode, () => void] {
  const [mode, setMode] = useState<ThemeMode>(() => {
    const q = location.search.match(/[?&]theme=(auto|light|dark)/)?.[1] as ThemeMode | undefined;
    return q ?? ((localStorage.getItem("theme") as ThemeMode | null) ?? "auto");
  });
  useEffect(() => {
    localStorage.setItem("theme", mode);
    document.documentElement.dataset.theme = resolvesDark(mode) ? "dark" : "light";
    if (mode !== "auto") return;
    const mq = matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => { document.documentElement.dataset.theme = resolvesDark("auto") ? "dark" : "light"; };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [mode]);
  const cycle = () => setMode((m) => MODES[(MODES.indexOf(m) + 1) % MODES.length]);
  return [mode, cycle];
}

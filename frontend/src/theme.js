import { useState, useEffect } from "react";

const THEMES = ["auto", "light", "dark"];
const resolve = (mode) =>
  mode === "dark" || (mode === "auto" && matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light";

// useTheme keeps light/dark/auto in localStorage and reflects it on <html
// data-theme>. Default is "auto" (follow the system / browser preference).
export function useTheme() {
  const [mode, setMode] = useState(
    () => (location.search.match(/[?&]theme=(auto|light|dark)/) || [])[1] || localStorage.getItem("theme") || "auto"
  );
  useEffect(() => {
    localStorage.setItem("theme", mode);
    document.documentElement.dataset.theme = resolve(mode);
    if (mode !== "auto") return;
    const mq = matchMedia("(prefers-color-scheme: dark)");
    const h = () => { document.documentElement.dataset.theme = resolve("auto"); };
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, [mode]);
  const cycle = () => setMode((m) => THEMES[(THEMES.indexOf(m) + 1) % THEMES.length]);
  return [mode, cycle];
}

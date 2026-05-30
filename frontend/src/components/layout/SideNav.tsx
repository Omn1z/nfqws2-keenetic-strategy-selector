import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { NAV_GROUPS, TABS } from "@/config/nav";
import { useTheme } from "@/lib/theme";
import { THEME_MODES, THEME_ICON, THEME_LABEL } from "@/lib/themeUI";
import type { Nfqws2Version } from "@/types/api";

export function SideNav({ active, onSelect, open }: { active: string; onSelect: (t: string) => void; open: boolean }) {
  const [mode, , setTheme] = useTheme();
  const [n2sVer, setN2sVer] = useState("");
  useEffect(() => {
    void (async () => { try { const v = await api<Nfqws2Version>("GET", "/api/nfqws2/version"); setN2sVer(v.package || ""); } catch { /* ignore */ } })();
  }, []);

  // Collapsible nav sub-groups (e.g. Telegram → MT Proto / SOCKS5). Auto-expanded
  // when one of its tabs is the active one.
  const [expanded, setExpanded] = useState<Set<string>>(() => {
    const s = new Set<string>();
    for (const g of NAV_GROUPS) for (const it of g.items) if (typeof it !== "string" && it.tabs.includes(active)) s.add(it.sub);
    return s;
  });
  const toggleSub = (sub: string) => setExpanded((p) => { const n = new Set(p); if (n.has(sub)) n.delete(sub); else n.add(sub); return n; });

  const renderLink = (k: string, indent = false) => {
    const on = active === k;
    const badge = k === "nfqws2" && n2sVer ? n2sVer : ""; // NFQWS2 version shown in the nav
    return (
      <a
        key={k}
        href={"/" + k}
        aria-current={on ? "page" : undefined}
        onClick={(e) => { if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return; e.preventDefault(); onSelect(k); }}
        className={cn(
          "relative mb-0.5 flex w-full items-center gap-2.5 rounded-[10px] py-2 pr-3 text-left text-[13.5px] font-medium no-underline transition",
          indent ? "pl-7" : "pl-3",
          on ? "bg-accent-w text-accent-d" : "text-ink-soft hover:bg-line-soft hover:text-ink",
        )}
      >
        {on && <span className="absolute bottom-2 left-0 top-2 w-[3px] rounded bg-accent" />}
        {TABS[k].icon}
        <span className="flex-1 truncate">{TABS[k].label}</span>
        {badge && <span className="shrink-0 rounded bg-line-soft px-1.5 py-0.5 text-[10.5px] font-semibold tabular-nums text-muted">{badge}</span>}
      </a>
    );
  };

  return (
    <nav
      className={cn(
        // Mobile: off-canvas drawer below the 58px TopBar. md+: static rail.
        "fixed bottom-0 left-0 top-[58px] z-40 flex w-[232px] shrink-0 flex-col overflow-y-auto border-r border-border bg-card px-3 py-3.5 transition-transform md:static md:top-auto md:translate-x-0 md:shadow-none",
        open ? "translate-x-0 shadow-2xl" : "-translate-x-full",
      )}
    >
      {NAV_GROUPS.map((g) => (
        <div key={g.title} className="mb-3">
          <div className="px-3 pb-1 pt-1.5 text-[10.5px] font-bold uppercase tracking-[0.08em] text-muted">{g.title}</div>
          {g.items.map((it, i) => {
            if (typeof it === "string") return renderLink(it);
            const isOpen = expanded.has(it.sub);
            const childActive = it.tabs.includes(active);
            return (
              <div key={"sub" + i}>
                <button
                  type="button"
                  onClick={() => toggleSub(it.sub)}
                  aria-expanded={isOpen}
                  className={cn(
                    "mb-0.5 flex w-full items-center gap-2 rounded-[10px] px-3 py-2 text-left text-[13.5px] font-medium outline-none transition focus-visible:ring-2 focus-visible:ring-ring/40",
                    childActive && !isOpen ? "text-accent-d" : "text-ink-soft hover:bg-line-soft hover:text-ink",
                  )}
                >
                  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className={cn("shrink-0 transition-transform", isOpen && "rotate-90")}><path d="M9 6l6 6-6 6" /></svg>
                  <span className="flex-1">{it.sub}</span>
                  {childActive && !isOpen && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-accent" />}
                </button>
                {isOpen && it.tabs.map((k) => renderLink(k, true))}
              </div>
            );
          })}
        </div>
      ))}

      {/* Тема — полностью в навигации, на всех размерах. */}
      <div className="mt-auto border-t border-line-soft pt-3">
        <div className="mb-1 px-3 text-[10.5px] font-bold uppercase tracking-[0.08em] text-muted">Тема</div>
        <div className="inline-flex w-full overflow-hidden rounded-lg border border-line">
          {THEME_MODES.map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setTheme(m)}
              title={THEME_LABEL[m]}
              aria-pressed={mode === m}
              className={cn("flex flex-1 items-center justify-center gap-1.5 border-r border-line py-1.5 text-[11.5px] outline-none transition last:border-r-0 focus-visible:relative focus-visible:ring-2 focus-visible:ring-ring/40", mode === m ? "bg-accent text-white" : "bg-panel text-ink-soft hover:bg-line-soft")}
            >
              {THEME_ICON[m]}<span>{THEME_LABEL[m]}</span>
            </button>
          ))}
        </div>
      </div>
    </nav>
  );
}

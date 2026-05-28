import { cn } from "@/lib/cn";
import { NAV_GROUPS, TABS } from "@/config/nav";

export function SideNav({ active, onSelect }: { active: string; onSelect: (t: string) => void }) {
  return (
    <nav className="w-[232px] shrink-0 overflow-y-auto border-r border-line bg-panel px-3 py-3.5">
      {NAV_GROUPS.map((g) => (
        <div key={g.title} className="mb-3">
          <div className="px-3 pb-1 pt-1.5 text-[10.5px] font-bold uppercase tracking-[0.08em] text-muted">{g.title}</div>
          {g.tabs.map((k) => {
            const on = active === k;
            return (
              <button
                key={k}
                onClick={() => onSelect(k)}
                className={cn(
                  "relative mb-0.5 flex w-full items-center gap-2.5 rounded-[10px] px-3 py-2 text-left text-[13.5px] font-medium transition",
                  on ? "bg-accent-w text-accent-d" : "text-ink-soft hover:bg-line-soft hover:text-ink",
                )}
              >
                {on && <span className="absolute bottom-2 left-0 top-2 w-[3px] rounded bg-accent" />}
                {TABS[k].icon}
                <span>{TABS[k].label}</span>
              </button>
            );
          })}
        </div>
      ))}
    </nav>
  );
}

import { useState } from "react";
import { useTab } from "@/lib/router";
import { TAB_KEYS, TABS } from "@/config/nav";
import { SideNav } from "@/components/layout/SideNav";
import { TopBar } from "@/components/layout/TopBar";

export function Shell({ authEnabled }: { authEnabled: boolean }) {
  const [tab, select] = useTab(TAB_KEYS, "dashboard");
  const [navOpen, setNavOpen] = useState(false);
  const Active = (TABS[tab] ?? TABS.dashboard).Component;
  const go = (t: string) => {
    select(t);
    setNavOpen(false);
  };
  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <TopBar authEnabled={authEnabled} onMenu={() => setNavOpen((v) => !v)} />
      <div className="flex min-h-0 flex-1">
        {/* Dimmed backdrop behind the mobile drawer (md+ has the static rail). */}
        {navOpen && <div className="fixed inset-0 top-[58px] z-30 bg-black/40 md:hidden" aria-hidden onClick={() => setNavOpen(false)} />}
        <SideNav active={tab} onSelect={go} open={navOpen} />
        {/* Only this region scrolls. min-w-0 lets wide tables scroll inside it. */}
        <main className="min-w-0 flex-1 overflow-y-auto p-4 sm:p-6">
          <div className="mx-auto w-full max-w-[1180px]">
            <Active />
          </div>
        </main>
      </div>
    </div>
  );
}

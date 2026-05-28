import { useTab } from "@/lib/router";
import { TAB_KEYS, TABS } from "@/config/nav";
import { SideNav } from "@/components/layout/SideNav";
import { TopBar } from "@/components/layout/TopBar";

export function Shell({ authEnabled }: { authEnabled: boolean }) {
  const [tab, select] = useTab(TAB_KEYS, "dashboard");
  const Active = (TABS[tab] ?? TABS.dashboard).Component;
  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <TopBar authEnabled={authEnabled} />
      <div className="flex min-h-0 flex-1">
        <SideNav active={tab} onSelect={select} />
        {/* Only this region scrolls. */}
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-[1180px]">
            <Active />
          </div>
        </main>
      </div>
    </div>
  );
}

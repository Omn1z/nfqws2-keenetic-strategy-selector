import type { ComponentType, ReactNode } from "react";
import Dashboard from "@/features/dashboard/Dashboard";
import Connections from "@/features/connections/Connections";
import Devices from "@/features/devices/Devices";
import Runs from "@/features/runs/Runs";
import BlockCheck from "@/features/blockcheck/BlockCheck";
import Strategies from "@/features/strategies/Strategies";
import Blobs from "@/features/blobs/Blobs";
import Lists from "@/features/lists/Lists";
import Geo from "@/features/geo/Geo";
import Dns from "@/features/dns/Dns";
import Tgws from "@/features/tgws/Tgws";
import Logs from "@/features/logs/Logs";

const I = (children: ReactNode) => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
    {children}
  </svg>
);

export interface Tab {
  label: string;
  icon: ReactNode;
  Component: ComponentType;
}

export const TABS: Record<string, Tab> = {
  dashboard: { label: "Дашборд", Component: Dashboard, icon: I(<><rect x="3" y="3" width="7" height="8" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="11" width="7" height="10" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /></>) },
  conns: { label: "Соединения", Component: Connections, icon: I(<path d="M22 12h-4l-3 8L9 4l-3 8H2" />) },
  devices: { label: "Устройства", Component: Devices, icon: I(<><rect x="2" y="4" width="20" height="13" rx="2" /><path d="M8 21h8M12 17v4" /></>) },
  runs: { label: "Прогоны", Component: Runs, icon: I(<path d="M6 4l14 8-14 8z" />) },
  blockcheck: { label: "BlockCheck", Component: BlockCheck, icon: I(<><path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z" /><path d="m9 12 2 2 4-4" /></>) },
  strategies: { label: "Стратегии", Component: Strategies, icon: I(<path d="M13 2 4 14h6l-1 8 9-12h-6z" />) },
  blobs: { label: "Блобы", Component: Blobs, icon: I(<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />) },
  lists: { label: "Списки", Component: Lists, icon: I(<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />) },
  geo: { label: "GeoSite/GeoIP", Component: Geo, icon: I(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></>) },
  dns: { label: "DNS", Component: Dns, icon: I(<path d="M4 7h16M4 12h16M4 17h16" />) },
  tgws: { label: "TG WS Proxy", Component: Tgws, icon: I(<path d="M22 3 2 11l6 2 2 6 3-4 5 4z" />) },
  logs: { label: "Логи", Component: Logs, icon: I(<><rect x="4" y="3" width="16" height="18" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></>) },
};

export const NAV_GROUPS: { title: string; tabs: string[] }[] = [
  { title: "Статус", tabs: ["dashboard", "conns", "devices"] },
  { title: "Подбор", tabs: ["runs", "blockcheck", "strategies", "blobs"] },
  { title: "Списки и данные", tabs: ["lists", "geo", "dns"] },
  { title: "Сервисы", tabs: ["tgws"] },
  { title: "Управление", tabs: ["logs"] },
];

export const TAB_KEYS = Object.keys(TABS);

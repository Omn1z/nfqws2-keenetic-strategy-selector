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
import MtProto from "@/features/telegram/MtProto";
import Socks5 from "@/features/telegram/Socks5";
import Nfqws2 from "@/features/nfqws2/Nfqws2";
import Logs from "@/features/logs/Logs";
import System from "@/features/system/System";

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
  mtproto: { label: "MT Proto", Component: MtProto, icon: I(<path d="M22 3 2 11l6 2 2 6 3-4 5 4z" />) },
  socks5: { label: "SOCKS5", Component: Socks5, icon: I(<><circle cx="6" cy="12" r="2" /><circle cx="18" cy="6" r="2" /><circle cx="18" cy="18" r="2" /><path d="M8 11l8-4M8 13l8 4" /></>) },
  nfqws2: { label: "NFQWS2", Component: Nfqws2, icon: I(<><path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z" /><path d="M9 12h6M12 9v6" /></>) },
  logs: { label: "Логи", Component: Logs, icon: I(<><rect x="4" y="3" width="16" height="18" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></>) },
  system: { label: "Система", Component: System, icon: I(<><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></>) },
};

// A nav item is a tab key, or a labeled sub-group of tab keys (rendered indented).
export type NavItem = string | { sub: string; tabs: string[] };

export const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  { title: "Статус", items: ["dashboard", "conns", "devices"] },
  { title: "Подбор", items: ["runs", "blockcheck", "strategies", "blobs"] },
  { title: "Списки и данные", items: ["lists", "geo", "dns"] },
  { title: "Сервисы", items: [{ sub: "Telegram", tabs: ["mtproto", "socks5"] }, "nfqws2"] },
  { title: "Управление", items: ["logs", "system"] },
];

export const TAB_KEYS = Object.keys(TABS);

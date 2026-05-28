import { useState, useEffect } from "react";
import { api } from "./api.js";
import { useStore } from "./store.jsx";
import { useTheme } from "./theme.js";
import { toast } from "./toast.jsx";
import Dashboard from "./tabs/Dashboard.jsx";
import Connections from "./tabs/Connections.jsx";
import Devices from "./tabs/Devices.jsx";
import Runs from "./tabs/Runs.jsx";
import BlockCheck from "./tabs/BlockCheck.jsx";
import Strategies from "./tabs/Strategies.jsx";
import Blobs from "./tabs/Blobs.jsx";
import Lists from "./tabs/Lists.jsx";
import Geo from "./tabs/Geo.jsx";
import Dns from "./tabs/Dns.jsx";
import Tgws from "./tabs/Tgws.jsx";

const I = (d, extra) => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    {d}{extra}
  </svg>
);
const TABS = {
  dashboard: { label: "Дашборд", Comp: Dashboard, icon: I(<><rect x="3" y="3" width="7" height="8" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="11" width="7" height="10" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /></>) },
  conns: { label: "Соединения", Comp: Connections, icon: I(<path d="M22 12h-4l-3 8L9 4l-3 8H2" />) },
  devices: { label: "Устройства", Comp: Devices, icon: I(<><rect x="2" y="4" width="20" height="13" rx="2" /><path d="M8 21h8M12 17v4" /></>) },
  runs: { label: "Прогоны", Comp: Runs, icon: I(<path d="M6 4l14 8-14 8z" />) },
  blockcheck: { label: "BlockCheck", Comp: BlockCheck, icon: I(<><path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z" /><path d="m9 12 2 2 4-4" /></>) },
  strategies: { label: "Стратегии", Comp: Strategies, icon: I(<path d="M13 2 4 14h6l-1 8 9-12h-6z" />) },
  blobs: { label: "Блобы", Comp: Blobs, icon: I(<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />) },
  lists: { label: "Списки", Comp: Lists, icon: I(<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />) },
  geo: { label: "GeoSite/GeoIP", Comp: Geo, icon: I(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></>) },
  dns: { label: "DNS", Comp: Dns, icon: I(<path d="M4 7h16M4 12h16M4 17h16" />) },
  tgws: { label: "TG WS Proxy", Comp: Tgws, icon: I(<path d="M22 3 2 11l6 2 2 6 3-4 5 4z" />) },
};
const GROUPS = [
  { title: "Статус", tabs: ["dashboard", "conns", "devices"] },
  { title: "Подбор", tabs: ["runs", "blockcheck", "strategies", "blobs"] },
  { title: "Списки и данные", tabs: ["lists", "geo", "dns"] },
  { title: "Сервисы", tabs: ["tgws"] },
];

function useHashTab() {
  const get = () => { const t = location.hash.replace(/^#/, ""); return TABS[t] ? t : "dashboard"; };
  const [tab, setTab] = useState(get);
  useEffect(() => {
    const h = () => setTab(get());
    window.addEventListener("hashchange", h);
    return () => window.removeEventListener("hashchange", h);
  }, []);
  return [tab, (t) => { location.hash = t; setTab(t); }];
}

export function Shell({ authEnabled }) {
  const [tab, select] = useHashTab();
  const Active = TABS[tab].Comp;
  return (
    <div className="app">
      <TopBar authEnabled={authEnabled} />
      <div className="layout">
        <nav className="sidenav">
          {GROUPS.map((g) => (
            <div className="nav-group" key={g.title}>
              <div className="nav-group-title">{g.title}</div>
              {g.tabs.map((k) => (
                <button key={k} className={"nav-item" + (tab === k ? " active" : "")} onClick={() => select(k)}>
                  {TABS[k].icon}<span>{TABS[k].label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>
        <main className="content"><Active /></main>
      </div>
    </div>
  );
}

const THEME_ICON = {
  auto: <svg viewBox="0 0 24 24" width="16" height="16"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="2" /><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor" /></svg>,
  light: <svg viewBox="0 0 24 24" width="16" height="16"><circle cx="12" cy="12" r="4.3" fill="none" stroke="currentColor" strokeWidth="2" /><path d="M12 1.6v3M12 19.4v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1.6 12h3M19.4 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>,
  dark: <svg viewBox="0 0 24 24" width="16" height="16"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" /></svg>,
};

function TopBar({ authEnabled }) {
  const { config } = useStore();
  const [mode, cycle] = useTheme();
  const [latest, setLatest] = useState("");
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState(null); // null | {target, msg}
  const version = config?.version || "…";

  const check = async (manual) => {
    setChecking(true);
    try {
      const u = await api("GET", "/api/update/check");
      if (u.error) { if (manual) toast("Проверка: " + u.error, "err"); }
      else if (u.available) { setLatest(u.latest); if (manual) toast("Доступна версия " + u.latest, "ok"); }
      else { setLatest(""); if (manual) toast("Установлена последняя версия", "ok"); }
    } catch (e) { if (manual) toast(e.message, "err"); }
    finally { setTimeout(() => setChecking(false), 400); }
  };
  useEffect(() => { check(false); }, []);

  const doUpdate = async () => {
    if (!confirm("Обновить nfqws2-strategy до " + latest + "?\nСервис будет перезапущен.")) return;
    const target = latest;
    try { await api("POST", "/api/update"); } catch (e) { toast(e.message, "err"); return; }
    setUpdating({ target, msg: "Скачиваем новую версию и перезапускаем сервис." });
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      try { const st = await api("GET", "/api/auth/status"); if (st.version === target) { setUpdating({ target, msg: "Готово, перезагружаем…" }); setTimeout(() => location.reload(), 1000); return; } } catch (_) {}
    }
    setUpdating({ target, msg: "Перезапуск занимает дольше обычного. Обновите страницу вручную." });
  };

  const logout = async () => { try { await api("POST", "/api/auth/logout"); } catch (_) {} location.reload(); };

  return (
    <header className="topbar">
      <div className="brand">
        <span className="logo" aria-hidden="true"><svg viewBox="0 0 24 24" width="20" height="20"><path d="M13 2 4 14h6l-1 8 9-12h-6z" fill="currentColor" /></svg></span>
        <span className="brand-name">NFQWS2 <b>Strategy</b></span>
      </div>
      <div className="topbar-right">
        {config?.wan_ifaces && <span className="env">iface {config.wan_ifaces.join(",")}</span>}
        <button className="icon-btn" title="Тема" onClick={cycle}>{THEME_ICON[mode]}</button>
        <div className="ver">
          <span className="ver-label">версия</span>
          <span className="ver-num">{version}</span>
          <button className={"icon-btn" + (checking ? " spin" : "")} title="Проверить обновления" onClick={() => check(true)}>
            <svg viewBox="0 0 24 24" width="16" height="16"><path d="M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
          </button>
          {latest && <button className="btn-update" onClick={doUpdate}>Обновить до {latest}</button>}
        </div>
        {authEnabled && (
          <button className="icon-btn" title="Выход" onClick={logout}>
            <svg viewBox="0 0 24 24" width="16" height="16"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
          </button>
        )}
      </div>
      {updating && (
        <div className="overlay">
          <div className="overlay-card">
            <div className="spinner" />
            <h3>Обновление до {updating.target}</h3>
            <p className="hint">{updating.msg}</p>
          </div>
        </div>
      )}
    </header>
  );
}

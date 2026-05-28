import { useState, useRef } from "react";
import { api } from "../api.js";
import { toast } from "../toast.jsx";
import { usePoll } from "../hooks.js";
import { Card, Switch } from "../components.jsx";

const dcText = (m) => Object.entries(m || {}).map(([k, v]) => k + "=" + v).join("\n");
const parseDC = (text) => {
  const out = {};
  (text || "").split("\n").forEach((line) => {
    line = line.trim(); if (!line) return;
    const p = line.split(/[=:]/);
    if (p.length >= 2) { const dc = parseInt(p[0].trim(), 10), ip = p[1].trim(); if (dc && ip) out[dc] = ip; }
  });
  return out;
};
const toForm = (c) => ({
  port: c.port || 1433, secret: c.secret || "", dc: dcText(c.dc_redirects), fake_tls_domain: c.fake_tls_domain || "",
  link_host: c.link_host || "", pool_size: c.pool_size != null ? c.pool_size : 4, buffer_size: c.buffer_size || 262144,
  cfproxy: !!c.cfproxy, proxy_protocol: !!c.proxy_protocol, cfproxy_user_domain: c.cfproxy_user_domain || "", cfproxy_worker_domain: c.cfproxy_worker_domain || "",
});
const collect = (f) => ({
  port: parseInt(f.port, 10) || 1433, secret: f.secret.trim(), dc_redirects: parseDC(f.dc), fake_tls_domain: f.fake_tls_domain.trim(),
  link_host: f.link_host.trim(), pool_size: parseInt(f.pool_size, 10) || 0, buffer_size: parseInt(f.buffer_size, 10) || 262144,
  cfproxy: f.cfproxy, proxy_protocol: f.proxy_protocol, cfproxy_user_domain: f.cfproxy_user_domain.trim(), cfproxy_worker_domain: f.cfproxy_worker_domain.trim(),
});

export default function Tgws() {
  const [form, setForm] = useState(null);
  const [live, setLive] = useState(null);
  const loaded = useRef(false);

  const applyStatus = (st) => { setLive({ running: st.running, enabled: st.config?.enabled, link: st.link, stats: st.stats }); setForm(toForm(st.config || {})); };
  usePoll(async () => {
    try {
      const st = await api("GET", "/api/tgws");
      setLive({ running: st.running, enabled: st.config?.enabled, link: st.link, stats: st.stats });
      if (!loaded.current) { setForm(toForm(st.config || {})); loaded.current = true; }
    } catch (_) {}
  }, 2000);

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));
  const toggle = async (on) => { try { applyStatus(await api("POST", on ? "/api/tgws/start" : "/api/tgws/stop", {})); toast(on ? "Прокси запущен" : "Прокси остановлен", "ok"); } catch (e) { toast(e.message, "err"); } };
  const save = async () => { try { applyStatus(await api("POST", "/api/tgws/config", collect(form))); toast("Настройки сохранены", "ok"); } catch (e) { toast(e.message, "err"); } };
  const newSecret = async () => { if (!confirm("Сгенерировать новый секрет? Старые tg:// ссылки перестанут работать.")) return; try { await api("POST", "/api/tgws/secret", {}); applyStatus(await api("GET", "/api/tgws")); toast("Новый секрет сгенерирован", "ok"); } catch (e) { toast(e.message, "err"); } };
  const copy = async () => { const v = live?.link; if (!v) return; try { await navigator.clipboard.writeText(v); toast("Ссылка скопирована", "ok"); } catch (_) { toast("Скопируйте вручную", "err"); } };

  if (!form || !live) return <div className="card"><span className="hint">Загрузка…</span></div>;
  const s = live.stats || {}, cc = s.connections || {}, t = s.traffic || {}, w = s.ws || {};
  const v = (x) => (x == null ? 0 : x);

  return (
    <>
      <Card title="Telegram MTProto → WebSocket прокси" head={<span className={"badge head-action " + (live.running ? "ok" : "bad")}>{live.running ? "работает" : "остановлен"}</span>}>
        <p className="hint">Прокси для Telegram прямо на роутере: клиенты в LAN ходят через <code>&lt;роутер&gt;:порт</code>, трафик идёт к Telegram по WSS с запасными путями.</p>
        <div className="run-row mid">
          <div className="field auto-field"><span className="field-cap">Прокси включён</span><Switch checked={live.enabled} onChange={toggle} /></div>
          <span className="run-status">{live.running ? "слушает порт " + form.port : (live.enabled ? "не удалось запустить" : "")}</span>
        </div>
      </Card>

      <Card title="Подключение Telegram" sub="ссылка содержит секрет">
        <label className="field">tg:// ссылка
          <div className="link-row"><input type="text" readOnly value={live.link || ""} /><button className="btn" onClick={copy}>Копировать</button></div>
        </label>
        <p className="hint">Откройте ссылку на устройстве с Telegram (например, отправьте себе в «Избранное» и тапните) — прокси добавится автоматически.</p>
      </Card>

      <Card title="Настройки">
        <div className="two">
          <label className="field field-sm">Порт прокси<input type="number" min="1" max="65535" value={form.port} onChange={(e) => set("port", e.target.value)} /></label>
          <label className="field">Секрет (32 hex)
            <div className="link-row"><input type="text" readOnly value={form.secret} /><button className="btn" onClick={newSecret}>Сгенерировать</button></div>
          </label>
        </div>
        <label className="field">DC-редиректы <span className="hint">по строке: <code>DC=IP</code> (например <code>2=149.154.167.220</code>)</span>
          <textarea rows="3" value={form.dc} placeholder="2=149.154.167.220&#10;4=149.154.167.220" onChange={(e) => set("dc", e.target.value)} /></label>
        <div className="two">
          <label className="field">Fake-TLS домен <span className="hint">пусто = выкл.</span><input type="text" value={form.fake_tls_domain} placeholder="напр. www.cloudflare.com" onChange={(e) => set("fake_tls_domain", e.target.value)} /></label>
          <label className="field">Хост для ссылки <span className="hint">пусто = авто</span><input type="text" value={form.link_host} placeholder="192.168.1.1" onChange={(e) => set("link_host", e.target.value)} /></label>
        </div>
        <div className="two">
          <label className="field field-sm">Размер пула WS<input type="number" min="0" max="16" value={form.pool_size} onChange={(e) => set("pool_size", e.target.value)} /></label>
          <label className="field field-sm">Буфер сокета (байт)<input type="number" min="4096" step="4096" value={form.buffer_size} onChange={(e) => set("buffer_size", e.target.value)} /></label>
        </div>
        <div className="run-row mid">
          <div className="field auto-field"><span className="field-cap">CF fallback</span><Switch checked={form.cfproxy} onChange={(v) => set("cfproxy", v)} /></div>
          <div className="field auto-field"><span className="field-cap">PROXY protocol</span><Switch checked={form.proxy_protocol} onChange={(v) => set("proxy_protocol", v)} /></div>
        </div>
        <div className="two">
          <label className="field">CF свой домен <span className="hint">перебивает встроенный пул</span><input type="text" value={form.cfproxy_user_domain} onChange={(e) => set("cfproxy_user_domain", e.target.value)} /></label>
          <label className="field">CF Worker домен <span className="hint">пробуется первым</span><input type="text" value={form.cfproxy_worker_domain} onChange={(e) => set("cfproxy_worker_domain", e.target.value)} /></label>
        </div>
        <div className="actions"><button className="btn btn-primary" onClick={save}>Сохранить настройки</button><span className="hint">при включённом прокси сохранение перезапустит его</span></div>
      </Card>

      <Card title="Статистика" sub="обновляется, пока открыта вкладка">
        <div className="table-wrap">
          <table className="data tgws-stats"><tbody>
            <tr><td>Соединения</td><td className="num">{v(cc.total)}</td></tr>
            <tr><td>Активные</td><td className="num">{v(cc.active)}</td></tr>
            <tr><td>WS / TCP-fallback / CF</td><td className="num">{v(cc.ws)} / {v(cc.tcp_fallback)} / {v(cc.cfproxy)}</td></tr>
            <tr><td>Отклонено (плохой секрет) / маскировка</td><td className="num">{v(cc.bad)} / {v(cc.masked)}</td></tr>
            <tr><td>Трафик ↑ / ↓</td><td className="num">{t.human_up || "0.0B"} / {t.human_down || "0.0B"}</td></tr>
            <tr><td>Пул (попаданий/всего) · ошибки WS</td><td className="num">{v(w.pool_hits)}/{v(w.pool_hits) + v(w.pool_misses)} · {v(w.errors)}</td></tr>
          </tbody></table>
        </div>
      </Card>
    </>
  );
}

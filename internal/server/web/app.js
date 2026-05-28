"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const res = await fetch(path, opt);
  const txt = await res.text();
  const data = txt ? JSON.parse(txt) : null;
  if (!res.ok) throw new Error((data && data.error) || res.statusText);
  return data;
}

function toast(msg, kind) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (kind ? " " + kind : "");
  // restart the entrance animation
  t.style.animation = "none"; void t.offsetWidth; t.style.animation = "";
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add("hidden"), 4200);
}

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const kb = (bps) => (bps / 1024).toFixed(0);

const state = {
  lists: [], selected: null, strategies: [],
  run: null, poll: null, results: [], sort: { key: "coef", dir: -1 },
  version: "", latest: "",
};

/* ---------- navigation ---------- */
$$(".nav-item").forEach(b => b.addEventListener("click", () => {
  $$(".nav-item").forEach(x => x.classList.remove("active"));
  $$(".panel").forEach(x => x.classList.remove("active"));
  b.classList.add("active");
  const p = $("#tab-" + b.dataset.tab);
  p.classList.add("active");
}));

/* ---------- lists ---------- */
async function loadLists() {
  state.lists = await api("GET", "/api/lists") || [];
  const ul = $("#listList"); ul.innerHTML = "";
  state.lists.forEach(l => {
    const li = document.createElement("li");
    if (state.selected && state.selected.id === l.id) li.classList.add("active");
    li.innerHTML = `<div class="li-main">
        <div class="nm">${esc(l.name || "(без имени)")}</div>
        <div class="meta">${(l.domains || []).length} доменов · ${(l.successful_strategies || []).length} рабочих</div>
      </div>
      <button class="li-del" title="Удалить список" aria-label="Удалить">×</button>`;
    li.querySelector(".li-main").addEventListener("click", () => selectList(l.id));
    li.querySelector(".li-del").addEventListener("click", (e) => { e.stopPropagation(); deleteListById(l.id, l.name); });
    ul.appendChild(li);
  });
}

async function selectList(id) {
  state.selected = await api("GET", "/api/lists/" + id);
  state.results = [];
  renderListEditor();
  loadLists();
}

function renderListEditor() {
  const l = state.selected;
  $("#listsEmpty").classList.toggle("hidden", !!l);
  $("#listEditor").classList.toggle("hidden", !l);
  if (!l) return;
  $("#listName").value = l.name || "";
  $("#listDomains").value = (l.domains || []).join("\n");
  $("#listIPs").value = (l.ips || []).join("\n");
  $("#listTestURL").value = l.test_url || "";
  renderResults();
  renderSaved();
}

function collectList() {
  const l = state.selected || {};
  return {
    id: l.id || "",
    name: $("#listName").value.trim(),
    domains: $("#listDomains").value.split("\n").map(s => s.trim()).filter(Boolean),
    ips: $("#listIPs").value.split("\n").map(s => s.trim()).filter(Boolean),
    test_url: $("#listTestURL").value.trim(),
    base_strategy_ids: l.base_strategy_ids || [],
    successful_strategies: l.successful_strategies || [],
  };
}

$("#newList").addEventListener("click", () => { state.selected = { name: "", domains: [], ips: [] }; state.results = []; renderListEditor(); });
$("#saveList").addEventListener("click", async () => {
  try { state.selected = await api("POST", "/api/lists", collectList()); await loadLists(); toast("Список сохранён", "ok"); }
  catch (e) { toast(e.message, "err"); }
});
$("#deleteList").addEventListener("click", () => {
  if (!state.selected || !state.selected.id) { state.selected = null; renderListEditor(); return; }
  deleteListById(state.selected.id, state.selected.name);
});

async function deleteListById(id, name) {
  if (!confirm("Удалить список «" + (name || "без имени") + "»?")) return;
  try {
    await api("DELETE", "/api/lists/" + id);
    if (state.selected && state.selected.id === id) { state.selected = null; renderListEditor(); }
    await loadLists();
    toast("Список удалён", "ok");
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- run ---------- */
function fillRunStrategies() {
  const sel = $("#runStrategies"); sel.innerHTML = "";
  state.strategies.forEach(s => {
    const o = document.createElement("option");
    o.value = s.id; o.textContent = `${s.name || s.id} [${s.l7 || "?"}]`;
    sel.appendChild(o);
  });
}

$("#startRun").addEventListener("click", async () => {
  if (!state.selected || !state.selected.id) { toast("Сначала сохраните список", "err"); return; }
  const ids = $$("#runStrategies option:checked").map(o => o.value);
  const req = { list_id: state.selected.id, strategy_ids: ids, threads: parseInt($("#runThreads").value, 10) || 4, include_ips: $("#runIncludeIPs").checked };
  try { state.run = await api("POST", "/api/runs", req); startPolling(); }
  catch (e) { toast(e.message, "err"); }
});
$("#cancelRun").addEventListener("click", async () => {
  if (state.run) { try { await api("POST", "/api/runs/" + state.run.id + "/cancel"); } catch (e) { toast(e.message, "err"); } }
});

function startPolling() {
  $("#progressWrap").classList.remove("hidden");
  $("#cancelRun").classList.remove("hidden");
  $("#startRun").disabled = true;
  if (state.poll) clearInterval(state.poll);
  const tick = async () => {
    try {
      const r = await api("GET", "/api/runs/" + state.run.id);
      state.run = r;
      const pct = r.total ? Math.round(r.done * 100 / r.total) : 0;
      $("#progressBar").style.width = pct + "%";
      $("#progressText").textContent = `${r.done}/${r.total} стратегий · ${r.status}`;
      $("#runStatus").textContent = r.status;
      state.results = r.results || [];
      renderResults();
      if (r.status !== "running") {
        clearInterval(state.poll); state.poll = null;
        $("#cancelRun").classList.add("hidden");
        $("#startRun").disabled = false;
        if (state.selected) state.selected = await api("GET", "/api/lists/" + state.selected.id);
        renderSaved(); loadLists();
        toast("Прогон завершён: " + r.status, "ok");
      }
    } catch (e) { clearInterval(state.poll); state.poll = null; $("#startRun").disabled = false; toast(e.message, "err"); }
  };
  tick();
  state.poll = setInterval(tick, 1000);
}

/* ---------- results ---------- */
function sortVal(r, key) {
  switch (key) {
    case "name": return (r.name || "").toLowerCase();
    case "targets": return r.targets_ok;
    case "latency": return r.avg_ttfb_ms || 1e12;
    case "speed": return r.avg_speed_bps;
    case "coef": return r.coefficient;
  }
  return 0;
}
$$("#resultsTable th[data-sort]").forEach(th => th.addEventListener("click", () => {
  const k = th.dataset.sort;
  if (state.sort.key === k) state.sort.dir *= -1; else state.sort = { key: k, dir: k === "latency" ? 1 : -1 };
  renderResults();
}));

function renderResults() {
  const tb = $("#resultsTable tbody"); tb.innerHTML = "";
  [...state.results].sort((a, b) => {
    const va = sortVal(a, state.sort.key), vb = sortVal(b, state.sort.key);
    return va < vb ? -state.sort.dir : va > vb ? state.sort.dir : 0;
  }).forEach(r => {
    const tr = document.createElement("tr");
    tr.className = r.success ? "ok" : "fail";
    const status = r.error ? `<span class="badge bad" title="${esc(r.error)}">ошибка</span>`
      : (r.success ? `<span class="badge ok">OK</span>` : `<span class="badge bad">нет</span>`);
    tr.innerHTML = `
      <td>${esc(r.name || r.strategy_id)} ${status}<div class="args">${esc(r.args)}</div></td>
      <td class="num">${r.targets_ok}/${r.targets_total}</td>
      <td class="num">${r.avg_ttfb_ms ? r.avg_ttfb_ms + " мс" : "—"}</td>
      <td class="num">${r.avg_speed_bps ? kb(r.avg_speed_bps) + " КБ/с" : "—"}</td>
      <td class="num">${r.coefficient ? Math.round(r.coefficient) : "—"}</td>
      <td>${r.success ? `<button class="btn btn-mini" data-apply="${esc(r.args)}">Применить</button>` : ""}</td>`;
    tb.appendChild(tr);
  });
  $$("#resultsTable button[data-apply]").forEach(b => b.addEventListener("click", () => applyStrategy(b.dataset.apply)));
}

function renderSaved() {
  const tb = $("#savedTable tbody"); tb.innerHTML = "";
  ((state.selected && state.selected.successful_strategies) || []).forEach(s => {
    const tr = document.createElement("tr"); tr.className = "ok";
    tr.innerHTML = `
      <td>${esc(s.name || s.strategy_id)}<div class="args">${esc(s.args)}</div></td>
      <td class="num">${s.avg_ttfb_ms} мс</td>
      <td class="num">${kb(s.avg_speed_bps)} КБ/с</td>
      <td class="num">${Math.round(s.coefficient)}</td>
      <td><button class="btn btn-mini" data-apply="${esc(s.args)}">Применить</button></td>`;
    tb.appendChild(tr);
  });
  $$("#savedTable button[data-apply]").forEach(b => b.addEventListener("click", () => applyStrategy(b.dataset.apply)));
}

async function applyStrategy(args) {
  if (!confirm("Применить стратегию в основной конфиг nfqws2?\n\n" + args + "\n\nБудет создан бэкап nfqws2.conf.")) return;
  const restart = confirm("Перезапустить сервис nfqws2 сейчас? (затронет всю сеть)\n\nOK — перезапустить, Отмена — только записать конфиг.");
  try { await api("POST", "/api/apply", { args, restart }); toast(restart ? "Применено и перезапущено" : "Записано в конфиг", "ok"); }
  catch (e) { toast(e.message, "err"); }
}

/* ---------- strategies ---------- */
async function loadStrategies() {
  state.strategies = await api("GET", "/api/strategies") || [];
  fillRunStrategies();
  const tb = $("#stratTable tbody"); tb.innerHTML = "";
  state.strategies.forEach(s => {
    const tr = document.createElement("tr");
    const custom = s.source === "custom";
    tr.innerHTML = `
      <td class="mono">${esc(s.id)}</td>
      <td>${esc(s.name || "")}</td>
      <td>${esc(s.l7 || "")}</td>
      <td class="args">${esc(s.args)}</td>
      <td>${esc(s.source)}</td>
      <td>${custom ? `<button class="btn btn-mini" data-edit="${esc(s.id)}">Изм.</button> <button class="btn btn-mini btn-ghost-danger" data-del="${esc(s.id)}">×</button>` : ""}</td>`;
    tb.appendChild(tr);
  });
  $$("#stratTable button[data-edit]").forEach(b => b.addEventListener("click", () => editStrat(b.dataset.edit)));
  $$("#stratTable button[data-del]").forEach(b => b.addEventListener("click", () => delStrat(b.dataset.del)));
}
function editStrat(id) {
  const s = state.strategies.find(x => x.id === id); if (!s) return;
  $("#stratId").value = s.id; $("#stratName").value = s.name || ""; $("#stratL7").value = s.l7 || "tls"; $("#stratArgs").value = s.args || "";
  $("#stratFormTitle").textContent = "Редактировать стратегию";
  $("#stratFormTitle").scrollIntoView({ behavior: "smooth", block: "center" });
}
async function delStrat(id) {
  if (!confirm("Удалить стратегию?")) return;
  try { await api("DELETE", "/api/strategies/" + id); await loadStrategies(); } catch (e) { toast(e.message, "err"); }
}
$("#saveStrat").addEventListener("click", async () => {
  const s = { id: $("#stratId").value, name: $("#stratName").value.trim(), l7: $("#stratL7").value.trim(), args: $("#stratArgs").value.trim(), source: "custom" };
  if (!s.args) { toast("Пустые аргументы", "err"); return; }
  try { await api("POST", "/api/strategies", s); resetStratForm(); await loadStrategies(); toast("Стратегия сохранена", "ok"); }
  catch (e) { toast(e.message, "err"); }
});
$("#resetStrat").addEventListener("click", resetStratForm);
function resetStratForm() {
  $("#stratId").value = ""; $("#stratName").value = ""; $("#stratL7").value = "tls"; $("#stratArgs").value = "";
  $("#stratFormTitle").textContent = "Добавить свою стратегию";
}

/* ---------- blobs ---------- */
async function loadBlobs() {
  const b = await api("GET", "/api/blobs");
  const cu = $("#customBlobs"); cu.innerHTML = "";
  (b.custom || []).forEach(n => { const li = document.createElement("li"); li.textContent = n; cu.appendChild(li); });
  const sy = $("#systemBlobs"); sy.innerHTML = "";
  (b.system || []).forEach(n => { const li = document.createElement("li"); li.textContent = n; sy.appendChild(li); });
}
const blobDrop = $("#blobDrop"), blobInput = $("#blobFile");
async function uploadBlob(file) {
  if (!file) return;
  $("#blobName").textContent = "Загрузка: " + file.name;
  blobDrop.classList.add("busy");
  const fd = new FormData(); fd.append("file", file);
  try {
    const res = await fetch("/api/blobs", { method: "POST", body: fd });
    const d = await res.json(); if (!res.ok) throw new Error(d.error || res.statusText);
    $("#blobName").textContent = "✓ " + d.name;
    toast("Загружено: " + d.path, "ok"); await loadBlobs();
  } catch (e) { $("#blobName").textContent = ""; toast(e.message, "err"); }
  finally { blobDrop.classList.remove("busy"); }
}
blobDrop.addEventListener("click", () => blobInput.click());
blobDrop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); blobInput.click(); } });
blobInput.addEventListener("change", () => { if (blobInput.files[0]) uploadBlob(blobInput.files[0]); });
["dragenter", "dragover"].forEach(ev => blobDrop.addEventListener(ev, (e) => { e.preventDefault(); blobDrop.classList.add("drag"); }));
blobDrop.addEventListener("dragleave", (e) => { if (!blobDrop.contains(e.relatedTarget)) blobDrop.classList.remove("drag"); });
blobDrop.addEventListener("drop", (e) => { e.preventDefault(); blobDrop.classList.remove("drag"); const f = e.dataTransfer.files[0]; if (f) uploadBlob(f); });

/* ---------- updates ---------- */
async function checkUpdate(manual) {
  const btn = $("#btnCheckUpd"); btn.classList.add("spin");
  try {
    const u = await api("GET", "/api/update/check");
    state.latest = u.latest || "";
    if (u.error) { if (manual) toast("Проверка: " + u.error, "err"); return; }
    if (u.available) {
      const b = $("#btnUpdate"); b.textContent = "Обновить до " + u.latest; b.classList.remove("hidden");
      if (manual) toast("Доступна версия " + u.latest, "ok");
    } else {
      $("#btnUpdate").classList.add("hidden");
      if (manual) toast("Установлена последняя версия (" + (u.current || state.version) + ")", "ok");
    }
  } catch (e) { if (manual) toast(e.message, "err"); }
  finally { setTimeout(() => btn.classList.remove("spin"), 400); }
}

$("#btnCheckUpd").addEventListener("click", () => checkUpdate(true));
$("#btnUpdate").addEventListener("click", async () => {
  if (!confirm("Обновить nfqws2-strategy до " + state.latest + "?\nСервис будет перезапущен.")) return;
  const target = state.latest;
  try {
    await api("POST", "/api/update");
  } catch (e) { toast(e.message, "err"); return; }
  // Service is restarting; wait for it to come back on the new version.
  $("#updateOverlay").classList.remove("hidden");
  $("#updateTitle").textContent = "Обновление до " + target;
  let ok = false;
  for (let i = 0; i < 40; i++) {
    await new Promise(r => setTimeout(r, 1500));
    try {
      const cfg = await api("GET", "/api/config");
      if (cfg.version && cfg.version === target) { ok = true; break; }
    } catch (_) { /* server restarting */ }
  }
  if (ok) { $("#updateMsg").textContent = "Готово, перезагружаем страницу…"; setTimeout(() => location.reload(), 1200); }
  else { $("#updateMsg").textContent = "Перезапуск занимает дольше обычного. Обновите страницу вручную."; }
});

/* ---------- theme ---------- */
const THEMES = ["auto", "light", "dark"];
const THEME_ICON = {
  auto: '<svg viewBox="0 0 24 24" width="16" height="16"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor"/></svg>',
  light: '<svg viewBox="0 0 24 24" width="16" height="16"><circle cx="12" cy="12" r="4.3" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 1.6v3M12 19.4v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1.6 12h3M19.4 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  dark: '<svg viewBox="0 0 24 24" width="16" height="16"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>',
};
const prefersDark = matchMedia("(prefers-color-scheme: dark)");
let themeMode = (location.search.match(/[?&]theme=(auto|light|dark)/) || [])[1] || localStorage.getItem("theme") || "auto";
function applyTheme(mode) {
  themeMode = mode;
  localStorage.setItem("theme", mode);
  const dark = mode === "dark" || (mode === "auto" && prefersDark.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  const b = $("#btnTheme");
  b.innerHTML = THEME_ICON[mode];
  b.title = "Тема: " + (mode === "auto" ? "авто (как в браузере)" : mode === "light" ? "светлая" : "тёмная");
}
$("#btnTheme").addEventListener("click", () => applyTheme(THEMES[(THEMES.indexOf(themeMode) + 1) % THEMES.length]));
prefersDark.addEventListener("change", () => { if (themeMode === "auto") applyTheme("auto"); });
applyTheme(themeMode);

/* ---------- init ---------- */
(async function init() {
  try {
    const cfg = await api("GET", "/api/config");
    state.version = cfg.version || "";
    $("#verCurrent").textContent = cfg.version || "?";
    $("#envInfo").textContent = `iface ${(cfg.wan_ifaces || []).join(",")}`;
  } catch (e) { /* ignore */ }
  await loadStrategies();
  await loadLists();
  await loadBlobs();
  checkUpdate(false);
})();

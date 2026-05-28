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

function toast(msg, isErr) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  setTimeout(() => t.classList.add("hidden"), 4000);
}

const state = {
  lists: [], selected: null, strategies: [],
  run: null, poll: null, results: [], sort: { key: "coef", dir: -1 },
};

// ---------- tabs ----------
$$(".tab").forEach(b => b.addEventListener("click", () => {
  $$(".tab").forEach(x => x.classList.remove("active"));
  $$(".tab-panel").forEach(x => x.classList.remove("active"));
  b.classList.add("active");
  $("#tab-" + b.dataset.tab).classList.add("active");
}));

// ---------- lists ----------
async function loadLists() {
  state.lists = await api("GET", "/api/lists") || [];
  const ul = $("#listList"); ul.innerHTML = "";
  state.lists.forEach(l => {
    const li = document.createElement("li");
    if (state.selected && state.selected.id === l.id) li.classList.add("active");
    li.innerHTML = `<span>${esc(l.name || "(без имени)")}<br><span class="sub">${(l.domains||[]).length} доменов · ${(l.successful_strategies||[]).length} рабочих</span></span>`;
    li.addEventListener("click", () => selectList(l.id));
    ul.appendChild(li);
  });
}

async function selectList(id) {
  state.selected = await api("GET", "/api/lists/" + id);
  state.results = [];
  renderListEditor();
  await loadLists();
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
  try { state.selected = await api("POST", "/api/lists", collectList()); await loadLists(); toast("Список сохранён"); }
  catch (e) { toast(e.message, true); }
});
$("#deleteList").addEventListener("click", async () => {
  if (!state.selected || !state.selected.id) { state.selected = null; renderListEditor(); return; }
  if (!confirm("Удалить список?")) return;
  try { await api("DELETE", "/api/lists/" + state.selected.id); state.selected = null; renderListEditor(); await loadLists(); }
  catch (e) { toast(e.message, true); }
});

// ---------- run ----------
function fillRunStrategies() {
  const sel = $("#runStrategies"); sel.innerHTML = "";
  state.strategies.forEach(s => {
    const o = document.createElement("option");
    o.value = s.id; o.textContent = `${s.name || s.id} [${s.l7 || "?"}]`;
    sel.appendChild(o);
  });
}

$("#startRun").addEventListener("click", async () => {
  if (!state.selected || !state.selected.id) { toast("Сначала сохраните список", true); return; }
  const ids = $$("#runStrategies option:checked").map(o => o.value);
  const req = {
    list_id: state.selected.id,
    strategy_ids: ids,
    threads: parseInt($("#runThreads").value, 10) || 4,
    include_ips: $("#runIncludeIPs").checked,
  };
  try {
    state.run = await api("POST", "/api/runs", req);
    startPolling();
  } catch (e) { toast(e.message, true); }
});

$("#cancelRun").addEventListener("click", async () => {
  if (state.run) { try { await api("POST", "/api/runs/" + state.run.id + "/cancel"); } catch (e) { toast(e.message, true); } }
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
      $("#progressText").textContent = `${r.done}/${r.total} стратегий · статус: ${r.status}`;
      $("#runStatus").textContent = r.status;
      state.results = r.results || [];
      renderResults();
      if (r.status !== "running") {
        clearInterval(state.poll); state.poll = null;
        $("#cancelRun").classList.add("hidden");
        $("#startRun").disabled = false;
        if (state.selected) state.selected = await api("GET", "/api/lists/" + state.selected.id);
        renderSaved();
        await loadLists();
        toast("Прогон завершён: " + r.status);
      }
    } catch (e) { clearInterval(state.poll); state.poll = null; $("#startRun").disabled = false; toast(e.message, true); }
  };
  tick();
  state.poll = setInterval(tick, 1000);
}

// ---------- results ----------
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
  const rows = [...state.results].sort((a, b) => {
    const va = sortVal(a, state.sort.key), vb = sortVal(b, state.sort.key);
    if (va < vb) return -1 * state.sort.dir; if (va > vb) return 1 * state.sort.dir; return 0;
  });
  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.className = r.success ? "ok" : "fail";
    const speed = (r.avg_speed_bps / 1024).toFixed(0);
    const status = r.error ? `<span class="badge bad" title="${esc(r.error)}">ошибка</span>`
      : (r.success ? `<span class="badge ok">OK</span>` : `<span class="badge bad">нет</span>`);
    tr.innerHTML = `
      <td>${esc(r.name || r.strategy_id)} ${status}<div class="args">${esc(r.args)}</div></td>
      <td>${r.targets_ok}/${r.targets_total}</td>
      <td>${r.avg_ttfb_ms || "—"}</td>
      <td>${r.avg_speed_bps ? speed : "—"}</td>
      <td>${r.coefficient ? r.coefficient.toFixed(0) : "—"}</td>
      <td>${r.success ? `<button data-apply="${esc(r.args)}">Применить</button>` : ""}</td>`;
    tb.appendChild(tr);
  });
  $$("#resultsTable button[data-apply]").forEach(b => b.addEventListener("click", () => applyStrategy(b.dataset.apply)));
}

function renderSaved() {
  const tb = $("#savedTable tbody"); tb.innerHTML = "";
  const saved = (state.selected && state.selected.successful_strategies) || [];
  saved.forEach(s => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(s.name || s.strategy_id)}<div class="args">${esc(s.args)}</div></td>
      <td>${s.avg_ttfb_ms} мс</td>
      <td>${(s.avg_speed_bps / 1024).toFixed(0)} КБ/с</td>
      <td>${s.coefficient.toFixed(0)}</td>
      <td><button data-apply="${esc(s.args)}">Применить</button></td>`;
    tb.appendChild(tr);
  });
  $$("#savedTable button[data-apply]").forEach(b => b.addEventListener("click", () => applyStrategy(b.dataset.apply)));
}

async function applyStrategy(args) {
  if (!confirm("Применить стратегию в основной конфиг nfqws2?\n\n" + args + "\n\nБудет создан бэкап nfqws2.conf.")) return;
  const restart = confirm("Перезапустить сервис nfqws2 сейчас? (затронет всю сеть)\n\nOK — перезапустить, Отмена — только записать конфиг.");
  try { await api("POST", "/api/apply", { args, restart }); toast(restart ? "Применено и перезапущено" : "Записано в конфиг (перезапустите вручную)"); }
  catch (e) { toast(e.message, true); }
}

// ---------- strategies ----------
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
      <td>${custom ? `<button data-edit="${esc(s.id)}">Изм.</button> <button class="danger" data-del="${esc(s.id)}">×</button>` : ""}</td>`;
    tb.appendChild(tr);
  });
  $$("#stratTable button[data-edit]").forEach(b => b.addEventListener("click", () => editStrat(b.dataset.edit)));
  $$("#stratTable button[data-del]").forEach(b => b.addEventListener("click", () => delStrat(b.dataset.del)));
}

function editStrat(id) {
  const s = state.strategies.find(x => x.id === id); if (!s) return;
  $("#stratId").value = s.id; $("#stratName").value = s.name || ""; $("#stratL7").value = s.l7 || "tls"; $("#stratArgs").value = s.args || "";
  $("#stratFormTitle").textContent = "Редактировать стратегию";
  window.scrollTo(0, document.body.scrollHeight);
}
async function delStrat(id) {
  if (!confirm("Удалить стратегию?")) return;
  try { await api("DELETE", "/api/strategies/" + id); await loadStrategies(); } catch (e) { toast(e.message, true); }
}
$("#saveStrat").addEventListener("click", async () => {
  const s = { id: $("#stratId").value, name: $("#stratName").value.trim(), l7: $("#stratL7").value.trim(), args: $("#stratArgs").value.trim(), source: "custom" };
  if (!s.args) { toast("Пустые аргументы", true); return; }
  try { await api("POST", "/api/strategies", s); resetStratForm(); await loadStrategies(); toast("Стратегия сохранена"); }
  catch (e) { toast(e.message, true); }
});
$("#resetStrat").addEventListener("click", resetStratForm);
function resetStratForm() {
  $("#stratId").value = ""; $("#stratName").value = ""; $("#stratL7").value = "tls"; $("#stratArgs").value = "";
  $("#stratFormTitle").textContent = "Добавить свою стратегию";
}

// ---------- blobs ----------
async function loadBlobs() {
  const b = await api("GET", "/api/blobs");
  const cu = $("#customBlobs"); cu.innerHTML = "";
  (b.custom || []).forEach(n => { const li = document.createElement("li"); li.className = "mono"; li.textContent = n; cu.appendChild(li); });
  const sy = $("#systemBlobs"); sy.innerHTML = "";
  (b.system || []).forEach(n => { const li = document.createElement("li"); li.textContent = n; sy.appendChild(li); });
}
$("#blobForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = $("#blobFile").files[0]; if (!f) return;
  const fd = new FormData(); fd.append("file", f);
  try {
    const res = await fetch("/api/blobs", { method: "POST", body: fd });
    const d = await res.json(); if (!res.ok) throw new Error(d.error || res.statusText);
    toast("Загружено: " + d.path); await loadBlobs();
  } catch (e) { toast(e.message, true); }
});

// ---------- init ----------
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

(async function init() {
  try {
    const cfg = await api("GET", "/api/config");
    $("#cfg").textContent = `iface: ${(cfg.wan_ifaces || []).join(",")} · nfqws: ${cfg.nfqws_bin}`;
  } catch (e) { /* ignore */ }
  await loadStrategies();
  await loadLists();
  await loadBlobs();
})();

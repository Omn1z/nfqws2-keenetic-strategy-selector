"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const res = await fetch(path, opt);
  if (res.status === 401) { showLogin(); throw new Error("Требуется вход"); }
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
  lists: [], selected: null, strategies: [], geo: [],
  run: null, poll: null, results: [], sort: { key: "coef", dir: -1 },
  bc: null, bcPoll: null,
  version: "", latest: "",
};

/* verdict labels shared by baseline (auto run) and BlockCheck */
const VERDICT = {
  ok: ["доступен", "ok"], cap16k: ["обрыв 16КБ", "bad"], reset: ["RST", "bad"],
  timeout: ["таймаут", "bad"], refused: ["отказ", "warn"], dns: ["DNS", "warn"], error: ["ошибка", "bad"],
};
function verdictBadge(v) {
  const [label, kind] = VERDICT[v] || [v || "?", "bad"];
  return `<span class="badge ${kind}">${esc(label)}</span>`;
}

/* ---------- checkbox lists ---------- */
function clBoxes(elId) { return $$("#" + elId + " input[type=checkbox]"); }
function clSelected(elId) { return clBoxes(elId).filter(c => c.checked).map(c => c.value); }
function renderChecklist(elId, items) {
  const box = $("#" + elId); if (!box) return;
  box.innerHTML = "";
  items.forEach(it => {
    const lbl = document.createElement("label");
    lbl.className = "cl-item";
    lbl.innerHTML = `<input type="checkbox" value="${esc(it.value)}"><span class="cl-text">${esc(it.label)}</span>` +
      (it.sub ? `<span class="cl-sub">${esc(it.sub)}</span>` : "");
    box.appendChild(lbl);
  });
  updateAllBtn(elId);
}
function updateAllBtn(elId) {
  const boxes = clBoxes(elId);
  const all = boxes.length > 0 && boxes.every(c => c.checked);
  const btn = $(`.cl-all[data-target="${elId}"]`);
  if (btn) btn.textContent = all ? "Снять все" : "Выбрать все";
}
function toggleAll(elId) {
  const boxes = clBoxes(elId);
  const all = boxes.length > 0 && boxes.every(c => c.checked);
  boxes.forEach(c => { c.checked = !all; });
  updateAllBtn(elId);
}
$$(".cl-all").forEach(b => b.addEventListener("click", () => toggleAll(b.dataset.target)));
$$(".checklist").forEach(box => box.addEventListener("change", () => updateAllBtn(box.id)));
$("#runAuto").addEventListener("change", () => {
  const on = $("#runAuto").checked;
  $("#runStrategies").classList.toggle("disabled", on);
  $("#autoHint").classList.toggle("hidden", !on);
  const allBtn = $('.cl-all[data-target="runStrategies"]');
  if (allBtn) allBtn.disabled = on;
  if (on) { clBoxes("runStrategies").forEach(c => { c.checked = false; }); updateAllBtn("runStrategies"); }
});

/* ---------- source selector (Список / GeoSite-GeoIP / Текст) ---------- */
$$(".seg-btn").forEach(b => b.addEventListener("click", () => {
  const sel = b.closest(".srcsel");
  sel.querySelectorAll(".seg-btn").forEach(x => x.classList.toggle("active", x === b));
  sel.querySelectorAll(".srcbody").forEach(x => x.classList.toggle("hidden", x.dataset.src !== b.dataset.src));
}));
function currentSrc(seg) {
  const b = $(`.seg[data-seg="${seg}"] .seg-btn.active`);
  return b ? b.dataset.src : "list";
}
function fillRunLists() {
  const sel = $("#runList"); if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = state.lists.map(l => `<option value="${esc(l.id)}">${esc(l.name || l.id)} (${(l.domains || []).length} дом.)</option>`).join("");
  if (cur) sel.value = cur;
}
function fillGeoSelect(fileId, catId) {
  const fsel = $("#" + fileId); if (!fsel) return;
  const prev = fsel.value;
  fsel.innerHTML = (state.geo || []).map(f => `<option value="${esc(f.name)}">${esc(f.name)} [${esc(f.kind)}]</option>`).join("");
  if (prev) fsel.value = prev;
  fillGeoCats(fileId, catId);
}
function fillGeoCats(fileId, catId) {
  const f = (state.geo || []).find(x => x.name === $("#" + fileId).value);
  $("#" + catId).innerHTML = ((f && f.categories) || []).map(c => `<option value="${esc(c.name)}">${esc(c.name)} (${c.count})</option>`).join("");
}
$("#runGeoFile").addEventListener("change", () => fillGeoCats("runGeoFile", "runGeoCat"));
$("#bcGeoFile").addEventListener("change", () => fillGeoCats("bcGeoFile", "bcGeoCat"));
// Returns {list_id} or {targets} depending on the chosen source for a seg group.
async function resolveTarget(seg) {
  const src = currentSrc(seg);
  if (src === "list") {
    const id = $("#" + seg + "List").value;
    if (!id) throw new Error("Нет списков — создайте список во вкладке «Списки»");
    return { list_id: id };
  }
  if (src === "geo") {
    const geo = $("#" + seg + "GeoFile").value, category = $("#" + seg + "GeoCat").value;
    if (!geo || !category) throw new Error("Загрузите GeoSite/GeoIP и выберите категорию");
    const r = await api("POST", "/api/geo/resolve", { geo, category, limit: parseInt($("#" + seg + "GeoLimit").value, 10) || 0 });
    const targets = (r && r.targets) || [];
    if (!targets.length) throw new Error("Категория пустая");
    return { targets };
  }
  const targets = $("#" + seg + "Text").value.split("\n").map(s => s.trim()).filter(Boolean);
  if (!targets.length) throw new Error("Введите домены или IP");
  return { targets };
}

/* ---------- navigation ---------- */
$$(".nav-item").forEach(b => b.addEventListener("click", () => {
  $$(".nav-item").forEach(x => x.classList.remove("active"));
  $$(".panel").forEach(x => x.classList.remove("active"));
  b.classList.add("active");
  const p = $("#tab-" + b.dataset.tab);
  p.classList.add("active");
  if (b.dataset.tab === "runs") { fillRunLists(); fillGeoSelect("runGeoFile", "runGeoCat"); }
  if (b.dataset.tab === "blockcheck") { fillBCLists(); fillGeoSelect("bcGeoFile", "bcGeoCat"); }
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
  fillBCLists();
  fillRunLists();
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
  $("#deleteList").classList.toggle("hidden", !l.id);
  renderListGeo();
  renderSaved();
}

function collectList() {
  const l = state.selected || {};
  return {
    id: l.id || "",
    name: $("#listName").value.trim(),
    domains: $("#listDomains").value.split("\n").map(s => s.trim()).filter(Boolean),
    ips: $("#listIPs").value.split("\n").map(s => s.trim()).filter(Boolean),
    base_strategy_ids: l.base_strategy_ids || [],
    successful_strategies: l.successful_strategies || [],
  };
}

/* geo import inside the list editor */
function renderListGeo() {
  const row = $("#listGeoRow"), files = state.geo || [];
  if (!state.selected || files.length === 0) { row.classList.add("hidden"); return; }
  row.classList.remove("hidden");
  const fsel = $("#listGeoFile"), prev = fsel.value;
  fsel.innerHTML = files.map(f => `<option value="${esc(f.name)}">${esc(f.name)} [${esc(f.kind)}]</option>`).join("");
  if (prev) fsel.value = prev;
  renderListGeoCats();
}
function renderListGeoCats() {
  const f = (state.geo || []).find(x => x.name === $("#listGeoFile").value);
  const cats = (f && f.categories) || [];
  $("#listGeoCat").innerHTML = cats.map(c => `<option value="${esc(c.name)}">${esc(c.name)} (${c.count})</option>`).join("");
}
$("#listGeoFile").addEventListener("change", renderListGeoCats);
$("#listGeoAdd").addEventListener("click", async () => {
  if (!state.selected || !state.selected.id) { toast("Сначала сохраните список", "err"); return; }
  const category = $("#listGeoCat").value;
  if (!category) { toast("Нет категорий в файле", "err"); return; }
  const req = { geo: $("#listGeoFile").value, category, limit: parseInt($("#listGeoLimit").value, 10) || 0, list_id: state.selected.id };
  try {
    const list = await api("POST", "/api/geo/import", req);
    state.selected = list; renderListEditor(); await loadLists();
    toast(`Добавлено из Geo: ${(list.domains || []).length} дом. / ${(list.ips || []).length} IP`, "ok");
  } catch (e) { toast(e.message, "err"); }
});

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
  renderChecklist("runStrategies", state.strategies.map(s => ({ value: s.id, label: s.name || s.id, sub: s.l7 || "?" })));
}

$("#startRun").addEventListener("click", async () => {
  const auto = $("#runAuto").checked;
  const ids = auto ? [] : clSelected("runStrategies");
  const blobs = clSelected("runBlobs");
  let target;
  try { target = await resolveTarget("run"); } catch (e) { toast(e.message, "err"); return; }
  const req = { ...target, strategy_ids: ids, blobs, auto, threads: parseInt($("#runThreads").value, 10) || 4 };
  try { state.run = await api("POST", "/api/runs", req); startPolling(); }
  catch (e) { toast(e.message, "err"); }
});
$("#cancelRun").addEventListener("click", async () => {
  if (state.poll) { clearInterval(state.poll); state.poll = null; }
  resetRunUI(true); // hide the cancel button and loader immediately, like before the run
  if (state.run) { try { await api("POST", "/api/runs/" + state.run.id + "/cancel"); } catch (e) { /* already stopping */ } }
});
function resetRunUI(full) {
  $("#cancelRun").classList.add("hidden");
  $("#startRun").disabled = false;
  if (full) { $("#progressWrap").classList.add("hidden"); $("#runStatus").textContent = ""; }
}

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
      renderBaseline(r);
      if (r.status !== "running") {
        clearInterval(state.poll); state.poll = null;
        resetRunUI(false);
        loadLists();
        const ok = (r.results || []).filter(x => x.success).length;
        if (r.status === "cancelled") toast("Прогон отменён", "ok");
        else if (r.auto && r.total === 0) toast("Цели доступны без обхода — обходить нечего", "ok");
        else toast(`Прогон завершён: найдено рабочих ${ok}`, "ok");
      }
    } catch (e) { clearInterval(state.poll); state.poll = null; resetRunUI(true); toast(e.message, "err"); }
  };
  tick();
  state.poll = setInterval(tick, 1000);
}

/* ---------- results ---------- */
function sortVal(r, key) {
  switch (key) {
    case "status": return r.error ? 0 : (r.success ? 2 : 1);
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
      <td>${status}</td>
      <td>${esc(r.name || r.strategy_id)}<div class="args">${esc(r.args)}</div></td>
      <td class="num">${r.targets_ok}/${r.targets_total}</td>
      <td class="num">${r.avg_ttfb_ms ? r.avg_ttfb_ms + " мс" : "—"}</td>
      <td class="num">${r.avg_speed_bps ? kb(r.avg_speed_bps) + " КБ/с" : "—"}</td>
      <td class="num">${r.coefficient ? Math.round(r.coefficient) : "—"}</td>
      <td>${r.success ? `<button class="btn btn-mini" data-apply="${esc(r.args)}">Применить</button>` : ""}</td>`;
    tb.appendChild(tr);
  });
  $$("#resultsTable button[data-apply]").forEach(b => b.addEventListener("click", () => applyStrategy(b.dataset.apply)));
}

function renderBaseline(r) {
  const el = $("#baselineInfo");
  const base = (r && r.baseline) || [];
  if (!r || !r.auto || base.length === 0) { el.classList.add("hidden"); return; }
  const blocked = base.filter(b => b.blocked).length;
  const parts = base.map(b => `${esc(b.host)} ${verdictBadge(b.verdict)}`).join(" · ");
  let head = `<b>Базовый замер без обхода:</b> заблокировано ${blocked} из ${base.length}. `;
  if (blocked === 0) head += "Обходить нечего — всё доступно.";
  else head += "Автоподбор тестируется только на заблокированных целях.";
  el.innerHTML = head + `<div style="margin-top:6px">${parts}</div>`;
  el.classList.remove("hidden");
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

/* ---------- blockcheck ---------- */
function fillBCLists() {
  const sel = $("#bcList"); if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = "";
  state.lists.forEach(l => {
    const o = document.createElement("option");
    o.value = l.id; o.textContent = `${l.name || l.id} (${(l.domains || []).length} дом.)`;
    sel.appendChild(o);
  });
  if (cur) sel.value = cur;
}
$("#startBC").addEventListener("click", async () => {
  let target;
  try { target = await resolveTarget("bc"); } catch (e) { toast(e.message, "err"); return; }
  const req = { ...target, threads: parseInt($("#bcThreads").value, 10) || 4 };
  try { state.bc = await api("POST", "/api/blockcheck", req); startBCPolling(); }
  catch (e) { toast(e.message, "err"); }
});
$("#cancelBC").addEventListener("click", async () => {
  if (state.bcPoll) { clearInterval(state.bcPoll); state.bcPoll = null; }
  resetBCUI(true);
  if (state.bc) { try { await api("POST", "/api/blockcheck/" + state.bc.id + "/cancel"); } catch (e) { /* already stopping */ } }
});
function resetBCUI(full) {
  $("#cancelBC").classList.add("hidden");
  $("#startBC").disabled = false;
  if (full) { $("#bcProgressWrap").classList.add("hidden"); $("#bcStatus").textContent = ""; }
}
function startBCPolling() {
  $("#bcProgressWrap").classList.remove("hidden");
  $("#cancelBC").classList.remove("hidden");
  $("#startBC").disabled = true;
  if (state.bcPoll) clearInterval(state.bcPoll);
  const tick = async () => {
    try {
      const r = await api("GET", "/api/blockcheck/" + state.bc.id);
      state.bc = r;
      const pct = r.total ? Math.round(r.done * 100 / r.total) : 0;
      $("#bcProgressBar").style.width = pct + "%";
      $("#bcProgressText").textContent = `${r.done}/${r.total} целей · ${r.status}`;
      $("#bcStatus").textContent = r.status;
      renderBC(r);
      if (r.status !== "running") {
        clearInterval(state.bcPoll); state.bcPoll = null;
        resetBCUI(false);
        const blocked = (r.targets || []).filter(t => t.blocked).length;
        if (r.status === "cancelled") toast("Проверка отменена", "ok");
        else toast(`Проверка завершена: заблокировано ${blocked} из ${r.total}`, "ok");
      }
    } catch (e) { clearInterval(state.bcPoll); state.bcPoll = null; resetBCUI(true); toast(e.message, "err"); }
  };
  tick();
  state.bcPoll = setInterval(tick, 1000);
}
function renderBC(r) {
  const tb = $("#bcTable tbody"); tb.innerHTML = "";
  (r.targets || []).forEach(t => {
    const tr = document.createElement("tr");
    tr.className = t.blocked ? "blocked" : "reachable";
    tr.innerHTML = `
      <td>${esc(t.host)}</td>
      <td>${verdictBadge(t.verdict)}${t.err ? `<div class="args" title="${esc(t.err)}">${esc(t.err)}</div>` : ""}</td>
      <td class="num">${t.ttfb_ms ? t.ttfb_ms + " мс" : "—"}</td>
      <td class="num">${t.speed_bps ? kb(t.speed_bps) + " КБ/с" : "—"}</td>
      <td class="num">${t.code || "—"}</td>`;
    tb.appendChild(tr);
  });
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
  // run-config blob checklist (custom first, then system)
  const items = [];
  (b.custom || []).forEach(n => items.push({ value: n, label: n, sub: "свой" }));
  (b.system || []).forEach(n => items.push({ value: n, label: n }));
  renderChecklist("runBlobs", items);
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
      const st = await api("GET", "/api/auth/status"); // public; survives auth + restart
      if (st.version && st.version === target) { ok = true; break; }
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

/* ---------- auth ---------- */
function showLogin() {
  $("#loginOverlay").classList.remove("hidden");
  setTimeout(() => $("#loginPass").focus(), 50);
}
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#loginErr").textContent = "";
  try {
    await api("POST", "/api/auth/login", { user: $("#loginUser").value, password: $("#loginPass").value });
    $("#loginOverlay").classList.add("hidden");
    $("#btnLogout").classList.remove("hidden");
    boot();
  } catch (err) { $("#loginErr").textContent = err.message; }
});
$("#btnLogout").addEventListener("click", async () => {
  try { await api("POST", "/api/auth/logout"); } catch (_) {}
  location.reload();
});

/* ---------- geo ---------- */
async function loadGeo() {
  let files = [];
  try { files = await api("GET", "/api/geo") || []; } catch (e) { return; }
  state.geo = files;
  const wrap = $("#geoFiles"); wrap.innerHTML = "";
  files.forEach(f => wrap.appendChild(geoCard(f)));
  renderListGeo();
  fillGeoSelect("runGeoFile", "runGeoCat");
  fillGeoSelect("bcGeoFile", "bcGeoCat");
}
function geoCard(f) {
  const card = document.createElement("div"); card.className = "card";
  const cats = f.categories || [];
  const opts = cats.map(c => `<option value="${esc(c.name)}">${esc(c.name)} (${c.count})</option>`).join("");
  const listOpts = `<option value="">— новый список —</option>` +
    state.lists.map(l => `<option value="${esc(l.id)}">${esc(l.name || l.id)}</option>`).join("");
  card.innerHTML = `
    <div class="card-head geo-title"><h2>${esc(f.name)}</h2><span class="badge">${esc(f.kind)}</span>
      <span class="hint">${cats.length} категорий</span>
      <button class="btn btn-mini btn-ghost-danger" data-geodel style="margin-left:auto">Удалить</button></div>
    <div class="geo-row">
      <label class="field field-grow">Категория<select class="geo-cat">${opts}</select></label>
      <label class="field field-sm">Лимит<input class="geo-limit" type="number" min="0" value="25"></label>
      <label class="field field-grow">В список<select class="geo-list">${listOpts}</select></label>
      <label class="field field-grow geo-newname">Имя нового<input class="geo-newname-in" type="text" placeholder="${esc(f.name)}:категория"></label>
      <button class="btn btn-primary geo-import">Импортировать</button>
    </div>`;
  const listSel = card.querySelector(".geo-list"), newName = card.querySelector(".geo-newname");
  listSel.addEventListener("change", () => { newName.style.display = listSel.value ? "none" : ""; });
  card.querySelector("[data-geodel]").addEventListener("click", async () => {
    if (!confirm("Удалить geo-файл «" + f.name + "»?")) return;
    try { await api("DELETE", "/api/geo/" + encodeURIComponent(f.name)); loadGeo(); } catch (e) { toast(e.message, "err"); }
  });
  card.querySelector(".geo-import").addEventListener("click", async () => {
    const category = card.querySelector(".geo-cat").value;
    if (!category) { toast("Нет категорий в файле", "err"); return; }
    const req = {
      geo: f.name, category,
      limit: parseInt(card.querySelector(".geo-limit").value, 10) || 0,
      list_id: listSel.value,
      list_name: card.querySelector(".geo-newname-in").value.trim(),
    };
    try {
      const list = await api("POST", "/api/geo/import", req);
      toast(`Импортировано в «${list.name}» (${(list.domains || []).length} дом. / ${(list.ips || []).length} IP)`, "ok");
      await loadLists(); state.selected = list; renderListEditor();
    } catch (e) { toast(e.message, "err"); }
  });
  return card;
}
const geoDrop = $("#geoDrop"), geoInput = $("#geoFile");
async function uploadGeo(file) {
  if (!file) return;
  $("#geoName").textContent = "Загрузка: " + file.name;
  geoDrop.classList.add("busy");
  const fd = new FormData(); fd.append("file", file); fd.append("kind", $("#geoKind").value);
  try {
    const res = await fetch("/api/geo", { method: "POST", body: fd });
    if (res.status === 401) { showLogin(); throw new Error("Требуется вход"); }
    const d = await res.json(); if (!res.ok) throw new Error(d.error || res.statusText);
    $("#geoName").textContent = "✓ " + d.name; toast("Загружено: " + d.name, "ok"); await loadGeo();
  } catch (e) { $("#geoName").textContent = ""; toast(e.message, "err"); }
  finally { geoDrop.classList.remove("busy"); }
}
geoDrop.addEventListener("click", () => geoInput.click());
geoDrop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); geoInput.click(); } });
geoInput.addEventListener("change", () => { if (geoInput.files[0]) uploadGeo(geoInput.files[0]); });
["dragenter", "dragover"].forEach(ev => geoDrop.addEventListener(ev, (e) => { e.preventDefault(); geoDrop.classList.add("drag"); }));
geoDrop.addEventListener("dragleave", (e) => { if (!geoDrop.contains(e.relatedTarget)) geoDrop.classList.remove("drag"); });
geoDrop.addEventListener("drop", (e) => { e.preventDefault(); geoDrop.classList.remove("drag"); const f = e.dataTransfer.files[0]; if (f) uploadGeo(f); });

/* ---------- init ---------- */
async function boot() {
  try {
    const cfg = await api("GET", "/api/config");
    state.version = cfg.version || "";
    $("#verCurrent").textContent = cfg.version || "?";
    $("#envInfo").textContent = `iface ${(cfg.wan_ifaces || []).join(",")}`;
  } catch (e) { return; }
  await loadStrategies();
  await loadLists();
  await loadBlobs();
  await loadGeo();
  checkUpdate(false);
}
(async function init() {
  try {
    const st = await api("GET", "/api/auth/status");
    $("#btnLogout").classList.toggle("hidden", !(st.enabled && st.authed));
    if (st.enabled && !st.authed) { showLogin(); return; }
  } catch (e) { /* fall through to boot */ }
  boot();
})();

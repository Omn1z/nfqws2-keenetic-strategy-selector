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

// downloadFile fetches (with the auth cookie) and saves the response as a file.
async function downloadFile(url, filename, opts) {
  const res = await fetch(url, opts || {});
  if (res.status === 401) { showLogin(); throw new Error("Требуется вход"); }
  if (!res.ok) { let m = res.statusText; try { m = (await res.json()).error || m; } catch (_) {} throw new Error(m); }
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
function exportStrategy(name, l7, args) {
  if (!args) { toast("Нет аргументов для экспорта", "err"); return; }
  downloadFile("/api/strategies/export", (name || "strategy").replace(/[^\w-]+/g, "_") + ".zip",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, l7, args }) })
    .catch(e => toast(e.message, "err"));
}

const state = {
  lists: [], selected: null, strategies: [], geo: [],
  run: null, poll: null, results: [], sort: { key: "coef", dir: -1 }, resultsPage: 1, savedPage: 1,
  bc: null, bcPoll: null,
  tgws: null, tgwsPoll: null,
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
  sel.innerHTML = state.lists.map(l => `<option value="${esc(l.id)}">${esc(l.name || l.id)} (${(l.domains || []).length} дом. / ${(l.ips || []).length} IP)</option>`).join("");
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
  if (b.dataset.tab === "tgws") { loadTGWS(); startTGWSPolling(); } else { stopTGWSPolling(); }
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
        <div class="meta">${(l.domains || []).length} дом. · ${(l.ips || []).length} IP · ${(l.successful_strategies || []).length} рабочих</div>
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
  state.savedPage = 1;
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
  $("#addThread").classList.add("hidden");
  $("#startRun").disabled = false;
  if (full) { $("#progressWrap").classList.add("hidden"); $("#runStatus").textContent = ""; }
}
$("#addThread").addEventListener("click", async () => {
  if (!state.run) return;
  const next = (state.run.threads || 1) + 1;
  if (next > 8) { toast("Максимум 8 потоков", "err"); return; }
  try { const d = await api("POST", "/api/runs/" + state.run.id + "/threads", { threads: next }); toast("Потоков: " + d.threads, "ok"); }
  catch (e) { toast(e.message, "err"); }
});

function startPolling() {
  $("#progressWrap").classList.remove("hidden");
  $("#cancelRun").classList.remove("hidden");
  $("#addThread").classList.remove("hidden");
  $("#startRun").disabled = true;
  state.resultsPage = 1;
  if (state.poll) clearInterval(state.poll);
  const tick = async () => {
    try {
      const r = await api("GET", "/api/runs/" + state.run.id);
      state.run = r;
      const pct = r.total ? Math.round(r.done * 100 / r.total) : 0;
      $("#progressBar").style.width = pct + "%";
      const found = (r.results || []).filter(x => x.success).length;
      const errored = (r.results || []).filter(x => x.error).length;
      $("#progressText").textContent = `${r.done}/${r.total} стратегий · ${r.threads} потоков · найдено ${found} · с ошибкой ${errored} · ${r.status}`;
      $("#addThread").disabled = (r.threads || 0) >= 8;
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
  state.resultsPage = 1;
  renderResults();
}));
$("#resultsPageSize").addEventListener("change", () => { state.resultsPage = 1; renderResults(); });
$("#resultsPrev").addEventListener("click", () => { state.resultsPage--; renderResults(); });
$("#resultsNext").addEventListener("click", () => { state.resultsPage++; renderResults(); });

function renderResults() {
  const tb = $("#resultsTable tbody"); tb.innerHTML = "";
  const sorted = [...state.results].sort((a, b) => {
    const va = sortVal(a, state.sort.key), vb = sortVal(b, state.sort.key);
    return va < vb ? -state.sort.dir : va > vb ? state.sort.dir : 0;
  });
  const total = sorted.length;
  const sizeVal = $("#resultsPageSize").value;
  const size = sizeVal === "all" ? Math.max(total, 1) : parseInt(sizeVal, 10);
  const pages = Math.max(1, Math.ceil(total / size));
  if (state.resultsPage > pages) state.resultsPage = pages;
  if (state.resultsPage < 1) state.resultsPage = 1;
  const start = (state.resultsPage - 1) * size;
  sorted.slice(start, start + size).forEach(r => {
    const tr = document.createElement("tr");
    tr.className = r.success ? "ok" : "fail";
    const status = r.error ? `<span class="badge bad" title="${esc(r.error)}">ошибка</span>`
      : (r.success ? `<span class="badge ok">OK</span>` : `<span class="badge bad">нет</span>`);
    tr.innerHTML = `
      <td>${status}</td>
      <td>${esc(r.name || r.strategy_id)}<div class="args" title="${esc(r.args)}">${esc(r.args)}</div></td>
      <td class="num">${r.targets_ok}/${r.targets_total}</td>
      <td class="num">${r.avg_ttfb_ms ? r.avg_ttfb_ms + " мс" : "—"}</td>
      <td class="num">${r.avg_speed_bps ? kb(r.avg_speed_bps) + " КБ/с" : "—"}</td>
      <td class="num">${r.coefficient ? Math.round(r.coefficient) : "—"}</td>
      <td class="row-actions">${r.success ? `<button class="btn btn-mini" data-apply="${esc(r.args)}">Применить</button>` : ""}<button class="btn btn-mini" title="Экспорт (ZIP)" data-exp data-name="${esc(r.name || r.strategy_id)}" data-l7="${esc(r.l7 || "")}" data-args="${esc(r.args)}">⤓</button></td>`;
    tb.appendChild(tr);
  });
  $$("#resultsTable button[data-apply]").forEach(b => b.addEventListener("click", () => applyStrategy(b.dataset.apply)));
  $$("#resultsTable button[data-exp]").forEach(b => b.addEventListener("click", () => exportStrategy(b.dataset.name, b.dataset.l7, b.dataset.args)));

  const pager = $("#resultsPager");
  pager.classList.toggle("hidden", total === 0);
  if (total > 0) {
    $("#resultsPageInfo").textContent = `стр. ${state.resultsPage} из ${pages} · ${total} записей`;
    $("#resultsPrev").disabled = state.resultsPage <= 1;
    $("#resultsNext").disabled = state.resultsPage >= pages;
  }
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
  const all = (state.selected && state.selected.successful_strategies) || [];
  const total = all.length;
  if (total === 0) {
    tb.innerHTML = `<tr><td colspan="5" class="empty-cell">Пока нет рабочих стратегий — запустите прогон на этом списке.</td></tr>`;
    $("#savedPager").classList.add("hidden");
    return;
  }
  const sizeVal = $("#savedPageSize").value;
  const size = sizeVal === "all" ? Math.max(total, 1) : parseInt(sizeVal, 10);
  const pages = Math.max(1, Math.ceil(total / size));
  if (state.savedPage > pages) state.savedPage = pages;
  if (state.savedPage < 1) state.savedPage = 1;
  const start = (state.savedPage - 1) * size;
  all.slice(start, start + size).forEach(s => {
    const tr = document.createElement("tr"); tr.className = "ok";
    tr.innerHTML = `
      <td>${esc(s.name || s.strategy_id)}<div class="args" title="${esc(s.args)}">${esc(s.args)}</div></td>
      <td class="num">${s.avg_ttfb_ms} мс</td>
      <td class="num">${kb(s.avg_speed_bps)} КБ/с</td>
      <td class="num">${Math.round(s.coefficient)}</td>
      <td class="row-actions"><button class="btn btn-mini" data-apply="${esc(s.args)}">Применить</button><button class="btn btn-mini" title="Экспорт (ZIP)" data-exp data-name="${esc(s.name || s.strategy_id)}" data-l7="" data-args="${esc(s.args)}">⤓</button></td>`;
    tb.appendChild(tr);
  });
  $$("#savedTable button[data-apply]").forEach(b => b.addEventListener("click", () => applyStrategy(b.dataset.apply)));
  $$("#savedTable button[data-exp]").forEach(b => b.addEventListener("click", () => exportStrategy(b.dataset.name, b.dataset.l7, b.dataset.args)));
  const pager = $("#savedPager");
  pager.classList.remove("hidden");
  $("#savedPageInfo").textContent = `стр. ${state.savedPage} из ${pages} · ${total} записей`;
  $("#savedPrev").disabled = state.savedPage <= 1;
  $("#savedNext").disabled = state.savedPage >= pages;
}
$("#savedPageSize").addEventListener("change", () => { state.savedPage = 1; renderSaved(); });
$("#savedPrev").addEventListener("click", () => { state.savedPage--; renderSaved(); });
$("#savedNext").addEventListener("click", () => { state.savedPage++; renderSaved(); });

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
    o.value = l.id; o.textContent = `${l.name || l.id} (${(l.domains || []).length} дом. / ${(l.ips || []).length} IP)`;
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
      <td><div class="args" title="${esc(s.args)}">${esc(s.args)}</div></td>
      <td>${esc(s.source)}</td>
      <td class="row-actions"><button class="btn btn-mini" title="Экспорт (ZIP)" data-exp data-name="${esc(s.name || s.id)}" data-l7="${esc(s.l7 || "")}" data-args="${esc(s.args)}">⤓</button>${custom ? `<button class="btn btn-mini" data-edit="${esc(s.id)}">Изм.</button><button class="btn btn-mini btn-ghost-danger" data-del="${esc(s.id)}">×</button>` : ""}</td>`;
    tb.appendChild(tr);
  });
  $$("#stratTable button[data-edit]").forEach(b => b.addEventListener("click", () => editStrat(b.dataset.edit)));
  $$("#stratTable button[data-del]").forEach(b => b.addEventListener("click", () => delStrat(b.dataset.del)));
  $$("#stratTable button[data-exp]").forEach(b => b.addEventListener("click", () => exportStrategy(b.dataset.name, b.dataset.l7, b.dataset.args)));
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
$("#stratImport").addEventListener("click", () => $("#stratImportFile").click());
$("#stratImportFile").addEventListener("change", async () => {
  const f = $("#stratImportFile").files[0]; if (!f) return;
  const fd = new FormData(); fd.append("file", f);
  try {
    const res = await fetch("/api/strategies/import", { method: "POST", body: fd });
    if (res.status === 401) { showLogin(); throw new Error("Требуется вход"); }
    const d = await res.json(); if (!res.ok) throw new Error(d.error || res.statusText);
    await loadStrategies(); await loadBlobs();
    toast("Импортирована стратегия: " + (d.name || d.id), "ok");
  } catch (e) { toast(e.message, "err"); }
  $("#stratImportFile").value = "";
});

/* ---------- blobs ---------- */
let blobList = { custom: [], system: [] };
async function loadBlobs() {
  const b = await api("GET", "/api/blobs");
  blobList = { custom: b.custom || [], system: b.system || [] };
  renderBlobTable();
  // run-config blob checklist (custom first, then system)
  const items = [];
  blobList.custom.forEach(n => items.push({ value: n, label: n, sub: "свой" }));
  blobList.system.forEach(n => items.push({ value: n, label: n }));
  renderChecklist("runBlobs", items);
}
function renderBlobTable() {
  const tb = $("#blobTable tbody"); tb.innerHTML = "";
  const addRow = (name, custom) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="cb"><input type="checkbox" class="blob-cb" value="${esc(name)}"></td>
      <td class="mono">${esc(name)}</td>
      <td>${custom ? "свой" : "системный"}</td>
      <td>${custom ? `<button class="btn btn-mini btn-ghost-danger" data-delblob="${esc(name)}">×</button>` : ""}</td>`;
    tb.appendChild(tr);
  };
  blobList.custom.forEach(n => addRow(n, true));
  blobList.system.forEach(n => addRow(n, false));
  $$("#blobTable button[data-delblob]").forEach(b => b.addEventListener("click", () => deleteBlob(b.dataset.delblob)));
  $("#blobAll").checked = false;
  updateBlobBulk();
}
function selectedBlobs() { return $$("#blobTable .blob-cb:checked").map(c => c.value); }
function updateBlobBulk() {
  const hasCustom = selectedBlobs().some(n => blobList.custom.includes(n));
  $("#blobDeleteSel").classList.toggle("hidden", !hasCustom);
}
$("#blobTable").addEventListener("change", (e) => { if (e.target && e.target.classList.contains("blob-cb")) updateBlobBulk(); });
async function deleteBlob(name) {
  if (!confirm("Удалить блоб «" + name + "»?")) return;
  try { await api("DELETE", "/api/blobs/" + encodeURIComponent(name)); toast("Блоб удалён", "ok"); await loadBlobs(); }
  catch (e) { toast(e.message, "err"); }
}
$("#blobAll").addEventListener("change", () => { const on = $("#blobAll").checked; $$("#blobTable .blob-cb").forEach(c => { c.checked = on; }); updateBlobBulk(); });
$("#blobExportSel").addEventListener("click", () => {
  const names = selectedBlobs();
  if (!names.length) { toast("Выберите блобы для экспорта", "err"); return; }
  downloadFile("/api/blobs/export", "blobs.zip", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ names }) }).catch(e => toast(e.message, "err"));
});
$("#blobDeleteSel").addEventListener("click", async () => {
  const names = selectedBlobs().filter(n => blobList.custom.includes(n));
  if (!names.length) { toast("Выберите пользовательские блобы", "err"); return; }
  if (!confirm("Удалить выбранные блобы (" + names.length + ")?")) return;
  for (const n of names) { try { await api("DELETE", "/api/blobs/" + encodeURIComponent(n)); } catch (e) { toast(n + ": " + e.message, "err"); } }
  toast("Удалено: " + names.length, "ok"); await loadBlobs();
});
const blobDrop = $("#blobDrop"), blobInput = $("#blobFile");
async function uploadBlobs(files) {
  files = Array.from(files || []);
  if (!files.length) return;
  // Skip files that already exist as custom blobs (ZIPs are checked server-side).
  const existing = new Set(blobList.custom.map(n => n.toLowerCase()));
  const dups = [];
  const queue = files.filter(f => {
    if (/\.zip$/i.test(f.name)) return true;
    if (existing.has(f.name.toLowerCase())) { dups.push(f.name); return false; }
    return true;
  });
  if (dups.length) toast(`Пропущены дубликаты (${dups.length}): ` + dups.join(", "), "warn");
  if (!queue.length) { $("#blobName").textContent = "дубликаты пропущены: " + dups.length; return; }
  blobDrop.classList.add("busy");
  let ok = 0;
  for (const file of queue) {
    $("#blobName").textContent = "Загрузка: " + file.name;
    const zip = /\.zip$/i.test(file.name);
    const fd = new FormData(); fd.append("file", file);
    try {
      const res = await fetch(zip ? "/api/blobs/zip" : "/api/blobs", { method: "POST", body: fd });
      if (res.status === 401) { showLogin(); throw new Error("Требуется вход"); }
      const d = await res.json(); if (!res.ok) throw new Error(d.error || res.statusText);
      ok += zip ? (d.imported || 0) : 1;
    } catch (e) { toast(file.name + ": " + e.message, "err"); }
  }
  $("#blobName").textContent = "✓ загружено: " + ok + (dups.length ? " · пропущено дубликатов: " + dups.length : "");
  blobDrop.classList.remove("busy");
  if (ok) toast("Блобы загружены: " + ok, "ok");
  await loadBlobs();
}
blobDrop.addEventListener("click", () => blobInput.click());
blobDrop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); blobInput.click(); } });
blobInput.addEventListener("change", () => { uploadBlobs(blobInput.files); blobInput.value = ""; });
["dragenter", "dragover"].forEach(ev => blobDrop.addEventListener(ev, (e) => { e.preventDefault(); blobDrop.classList.add("drag"); }));
blobDrop.addEventListener("dragleave", (e) => { if (!blobDrop.contains(e.relatedTarget)) blobDrop.classList.remove("drag"); });
blobDrop.addEventListener("drop", (e) => { e.preventDefault(); blobDrop.classList.remove("drag"); uploadBlobs(e.dataTransfer.files); });

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

/* ---------- TG WS Proxy ---------- */
function parseDCRedirects(text) {
  const out = {};
  text.split("\n").forEach(line => {
    line = line.trim(); if (!line) return;
    const parts = line.split(/[=:]/);
    if (parts.length >= 2) {
      const dc = parseInt(parts[0].trim(), 10), ip = parts[1].trim();
      if (dc && ip) out[dc] = ip;
    }
  });
  return out;
}
function collectTGWS() {
  return {
    port: parseInt($("#tgwsPort").value, 10) || 1433,
    secret: $("#tgwsSecret").value.trim(),
    dc_redirects: parseDCRedirects($("#tgwsDC").value),
    fake_tls_domain: $("#tgwsFakeTLS").value.trim(),
    link_host: $("#tgwsLinkHost").value.trim(),
    pool_size: parseInt($("#tgwsPool").value, 10) || 0,
    buffer_size: parseInt($("#tgwsBuffer").value, 10) || 262144,
    cfproxy: $("#tgwsCF").checked,
    proxy_protocol: $("#tgwsPP").checked,
    cfproxy_user_domain: $("#tgwsCFUser").value.trim(),
    cfproxy_worker_domain: $("#tgwsCFWorker").value.trim(),
  };
}
async function loadTGWS() {
  try { renderTGWSFull(await api("GET", "/api/tgws")); } catch (e) { toast(e.message, "err"); }
}
function renderTGWSFull(st) {
  if (!st) return;
  state.tgws = st;
  const c = st.config || {};
  $("#tgwsEnabled").checked = !!c.enabled;
  $("#tgwsLink").value = st.link || "";
  $("#tgwsSecret").value = c.secret || "";
  $("#tgwsPort").value = c.port || 1433;
  $("#tgwsDC").value = Object.entries(c.dc_redirects || {}).map(([k, v]) => k + "=" + v).join("\n");
  $("#tgwsFakeTLS").value = c.fake_tls_domain || "";
  $("#tgwsLinkHost").value = c.link_host || "";
  $("#tgwsPool").value = (c.pool_size != null) ? c.pool_size : 4;
  $("#tgwsBuffer").value = c.buffer_size || 262144;
  $("#tgwsCF").checked = !!c.cfproxy;
  $("#tgwsPP").checked = !!c.proxy_protocol;
  $("#tgwsCFUser").value = c.cfproxy_user_domain || "";
  $("#tgwsCFWorker").value = c.cfproxy_worker_domain || "";
  renderTGWSLive(st);
}
function renderTGWSLive(st) {
  if (!st) return;
  const c = st.config || {};
  const badge = $("#tgwsState");
  badge.textContent = st.running ? "работает" : "остановлен";
  badge.className = "badge head-action " + (st.running ? "ok" : "bad");
  $("#tgwsStatus").textContent = st.running ? ("слушает порт " + c.port) : (c.enabled ? "не удалось запустить" : "");
  renderTGWSStats(st.stats);
}
function renderTGWSStats(s) {
  if (!s) return;
  const c = s.connections || {}, t = s.traffic || {}, w = s.ws || {};
  const v = (x) => (x == null ? 0 : x);
  $("#tgwsConn").textContent = v(c.total);
  $("#tgwsActive").textContent = v(c.active);
  $("#tgwsPaths").textContent = `${v(c.ws)} / ${v(c.tcp_fallback)} / ${v(c.cfproxy)}`;
  $("#tgwsBad").textContent = `${v(c.bad)} / ${v(c.masked)}`;
  $("#tgwsTraffic").textContent = `${t.human_up || "0.0B"} / ${t.human_down || "0.0B"}`;
  $("#tgwsPool").textContent = `${v(w.pool_hits)}/${v(w.pool_hits) + v(w.pool_misses)} · ${v(w.errors)}`;
}
function startTGWSPolling() {
  stopTGWSPolling();
  state.tgwsPoll = setInterval(async () => {
    try { renderTGWSLive(await api("GET", "/api/tgws")); } catch (e) { /* leave last view */ }
  }, 2000);
}
function stopTGWSPolling() { if (state.tgwsPoll) { clearInterval(state.tgwsPoll); state.tgwsPoll = null; } }

$("#tgwsEnabled").addEventListener("change", async () => {
  const on = $("#tgwsEnabled").checked;
  try { renderTGWSFull(await api("POST", on ? "/api/tgws/start" : "/api/tgws/stop", {})); toast(on ? "Прокси запущен" : "Прокси остановлен", "ok"); }
  catch (e) { toast(e.message, "err"); loadTGWS(); }
});
$("#tgwsSave").addEventListener("click", async () => {
  try { renderTGWSFull(await api("POST", "/api/tgws/config", collectTGWS())); toast("Настройки сохранены", "ok"); }
  catch (e) { toast(e.message, "err"); }
});
$("#tgwsNewSecret").addEventListener("click", async () => {
  if (!confirm("Сгенерировать новый секрет? Старые tg:// ссылки перестанут работать.")) return;
  try { await api("POST", "/api/tgws/secret", {}); await loadTGWS(); toast("Новый секрет сгенерирован", "ok"); }
  catch (e) { toast(e.message, "err"); }
});
$("#tgwsCopy").addEventListener("click", async () => {
  const v = $("#tgwsLink").value; if (!v) return;
  try { await navigator.clipboard.writeText(v); toast("Ссылка скопирована", "ok"); }
  catch (e) { $("#tgwsLink").select(); try { document.execCommand("copy"); toast("Ссылка скопирована", "ok"); } catch (_) { toast("Скопируйте вручную", "err"); } }
});

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

"use strict";

const $ = selector => document.querySelector(selector);
const esc = value => String(value ?? "").replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const snippet = value => esc(value).replace(/\x01/g, "<mark>").replace(/\x02/g, "</mark>");
const sizeLabel = value => {
  const units = ["B", "kB", "MB", "GB", "TB"];
  let amount = Number(value), index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index++; }
  return `${amount.toLocaleString("de-DE", {maximumFractionDigits: index ? 1 : 0})} ${units[index]}`;
};
const modifiedLabel = value => new Intl.DateTimeFormat("de-DE", {dateStyle:"medium",timeZone:"UTC"}).format(new Date(value * 1000));
function icon(name) {
  const paths = {
    download: '<path d="M12 3v12m-5-5 5 5 5-5"/><path d="M5 16v4h14v-4"/>',
    close: '<path d="m6 6 12 12M6 18 18 6"/>',
    file: '<path d="M14 2H5v20h14V7zM14 2v5h5M8 12h8M8 16h8"/>',
  };
  return `<svg class="action-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${paths[name]}</svg>`;
}
const statusLabel = row => ({pending:"Text wird erfasst…",ocr:row.attempts ? "Texterkennung wird erneut versucht…" : "Texterkennung läuft…",failed:"Text konnte noch nicht erfasst werden.","name-only":"Suche nach Dateinamen verfügbar."}[row.state] || "");
let session = null, offset = 0, listMode = false, timer, debounce, request, serial = 0, lastResult = "", activeDocument = null, initialFilters = null;
const pageSize = 40;

async function api(path, options = {}) {
  const response = await fetch(path, {...options,credentials:"same-origin",headers:{"Content-Type":"application/json",...(options.headers || {})}});
  let body = {};
  try { body = await response.json(); } catch (_) { /* Empty response. */ }
  if (response.status === 401) { showLogin(); throw new Error("Bitte erneut anmelden."); }
  if (!response.ok) throw Object.assign(new Error(body.error || "Anfrage fehlgeschlagen"), {status:response.status});
  return body;
}
function notice(message) {
  $("#toast").textContent = message; $("#toast").hidden = false;
  setTimeout(() => { $("#toast").hidden = true; }, 4000);
}
function showLogin() {
  session = null; activeDocument = null; lastResult = ""; clearInterval(timer); clearTimeout(debounce); request?.abort();
  $("#documents").replaceChildren();
  $("#document-preview").replaceChildren(); delete $("#document-preview").dataset.url;
  if ($("#document-dialog").open) $("#document-dialog").close();
  $("#portal-view").hidden = true; $("#login-view").hidden = false;
  $("#login-form input[name=username]").focus();
}
function showFiles(value) {
  session = value;
  $("#session-user").textContent = value.user;
  $("#admin-link").hidden = value.role !== "domain-admin";
  $("#login-view").hidden = true; $("#portal-view").hidden = false;
  const params = new URLSearchParams(location.search);
  initialFilters = {source:params.get("source") || "",type:params.get("type") || ""};
  offset = 0;
  for (const [id,key] of [["search-query","q"],["search-scope","scope"],["sort-filter","sort"]]) {
    if (params.has(key)) $("#" + id).value = params.get(key);
  }
  refresh(); clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden && session) { refresh(false); if (activeDocument) loadDetail(activeDocument, false); } }, 2000);
}
function filters() {
  return new URLSearchParams({q:$("#search-query").value,scope:$("#search-scope").value || "all",source:$("#source-filter").value,type:$("#type-filter").value,sort:$("#sort-filter").value || "recent",limit:pageSize,offset});
}
function updateOptions(select, items, firstLabel) {
  const current = select.value || (initialFilters && initialFilters[select.id === "source-filter" ? "source" : "type"]) || "";
  const html = `<option value="">${firstLabel}</option>` + items.map(item => `<option value="${esc(item.id)}">${esc(item.label)}</option>`).join("");
  if (select.innerHTML !== html) {
    select.innerHTML = html;
    select.value = current;
    if (!select.value) select.value = "";
  }
}
async function refresh(userAction = true) {
  if (!session) return;
  if (!userAction && request) return;
  request?.abort();
  const controller = new AbortController(); request = controller;
  const current = ++serial;
  if (userAction) $("#search-error").hidden = true;
  try {
    const params = filters();
    const result = await api("/api/documents?" + params, {signal:controller.signal});
    if (current !== serial || !session) return;
    history.replaceState({}, "", "/" + (params.get("q") || params.get("source") || params.get("type") ? "?" + params : ""));
    updateOptions($("#source-filter"), result.sources.map(source => ({id:source.id,label:source.kind === "private" ? "Mein Private-Ordner" : source.label})), "Alle Ordner");
    updateOptions($("#type-filter"), result.types.map(type => ({id:type,label:type.toUpperCase()})), "Alle Dateitypen");
    if (initialFilters) {
      const changed = $("#source-filter").value !== params.get("source") || $("#type-filter").value !== params.get("type");
      initialFilters = null;
      if (changed) { request = null; refresh(); return; }
    }
    $("#result-summary").textContent = `${result.total.toLocaleString("de-DE")} ${result.total === 1 ? "Datei" : "Dateien"}`;
    $("#index-progress").hidden = !result.pending;
    $("#index-progress").textContent = result.pending ? `Text wird für ${result.pending} ${result.pending === 1 ? "Datei" : "Dateien"} erfasst.` : "";
    $("#previous-page").disabled = offset === 0;
    $("#next-page").disabled = !result.hasMore;
    $("#page-label").textContent = result.total ? `Seite ${Math.floor(offset / pageSize) + 1}` : "";
    const signature = JSON.stringify(result.items);
    if (signature !== lastResult) {
      lastResult = signature;
      $("#documents").innerHTML = result.items.length ? result.items.map(row => `<article class="document-card">
        <button type="button" class="document-open" data-document="${esc(row.id)}" aria-label="Öffnen: ${esc(row.name)}">
          <div class="document-thumbnail">${row.hasPreview ? `<img src="/api/documents/${row.id}/preview?v=${row.version}" loading="lazy" alt="">` : `<div class="document-placeholder">${icon("file")}<span>${esc((row.extension || "Datei").toUpperCase())}</span></div>`}</div>
          <div class="document-description"><h2 title="${esc(row.name)}">${esc(row.name)}</h2><p class="document-path" title="${esc(row.path)}">${esc(row.path)}</p><p class="document-excerpt">${snippet(row.snippet || statusLabel(row))}</p></div>
        </button><footer><span title="${esc(row.source)}">${esc(row.kind === "private" ? "Private" : row.source)} · ${sizeLabel(row.size)}<small>${modifiedLabel(row.modified)} UTC</small></span><a class="button icon-button" href="/api/documents/${row.id}/download" download="${esc(row.name)}" aria-label="Herunterladen: ${esc(row.name)}" title="Herunterladen">${icon("download")}</a></footer>
      </article>`).join("") : '<div class="portal-empty"><h2>Keine Dateien gefunden</h2><p>Suchbegriff oder Filter ändern.</p></div>';
    }
    $("#search-error").hidden = true;
  } catch (error) {
    if (error.name !== "AbortError" && session) { $("#search-error").textContent = error.message; $("#search-error").hidden = false; }
  } finally { if (request === controller) request = null; }
}
async function loadDetail(id, open = true) {
  if (open) activeDocument = id;
  try {
    const row = await api("/api/documents/" + id);
    if (activeDocument !== id || !session) return;
    $("#document-title").textContent = row.name;
    $("#document-title").title = row.name;
    $("#document-location").textContent = `${row.source} / ${row.path} · ${sizeLabel(row.size)}${row.pages ? ` · ${row.pages} ${row.pages === 1 ? "Seite" : "Seiten"}` : ""}`;
    const isPdf = row.extension === "pdf";
    $("#document-dialog").classList.toggle("pdf-dialog", isPdf);
    $("#document-download").href = `/api/documents/${id}/download`;
    $("#document-download").download = row.name;
    $("#document-download").innerHTML = icon("download");
    $("#document-close").innerHTML = icon("close");
    const previewUrl = isPdf ? `/assets/vendor/pdfjs/6.3.289-app1/web/viewer.html?file=${encodeURIComponent(`/api/documents/${id}/content?v=${row.version}`)}#zoom=page-width` : row.hasPreview ? `/api/documents/${id}/preview?v=${row.version}` : "";
    if ($("#document-preview").dataset.url !== previewUrl) {
      $("#document-preview").dataset.url = previewUrl;
      $("#document-preview").innerHTML = isPdf ? `<iframe id="document-pdf-viewer" src="${esc(previewUrl)}" title="PDF-Vorschau" allowfullscreen sandbox="allow-scripts allow-same-origin allow-downloads allow-modals"></iframe>` : previewUrl ? `<img src="${previewUrl}" alt="Dokumentvorschau">` : `<div class="document-placeholder">${icon("file")}<p>Keine Bildvorschau verfügbar.</p></div>`;
    }
    if (open && !$("#document-dialog").open) $("#document-dialog").showModal();
  } catch (error) {
    if (activeDocument === id) { if ($("#document-dialog").open) $("#document-dialog").close(); activeDocument = null; if (session) notice(error.message); }
  }
}
$("#document-dialog").addEventListener("close", () => { activeDocument = null; $("#document-preview").replaceChildren(); delete $("#document-preview").dataset.url; });
$("#document-close").addEventListener("click", () => $("#document-dialog").close());
$("#documents").addEventListener("click", event => { const button = event.target.closest("[data-document]"); if (button) loadDetail(button.dataset.document); });
$("#documents").addEventListener("error", event => { if (event.target.tagName === "IMG") event.target.hidden = true; }, true);
$("#document-search").addEventListener("submit", event => { event.preventDefault(); clearTimeout(debounce); offset = 0; refresh(); });
$("#search-query").addEventListener("input", () => { clearTimeout(debounce); offset = 0; debounce = setTimeout(() => refresh(), 200); });
for (const id of ["search-scope", "source-filter", "type-filter", "sort-filter"]) $("#" + id).addEventListener("change", () => { offset = 0; refresh(); });
$("#reset-filters").addEventListener("click", () => { $("#search-query").value = ""; $("#search-scope").value = "all"; $("#source-filter").value = ""; $("#type-filter").value = ""; offset = 0; refresh(); });
$("#previous-page").addEventListener("click", () => { offset = Math.max(0, offset - pageSize); refresh(); });
$("#next-page").addEventListener("click", () => { offset += pageSize; refresh(); });
for (const [id,mode] of [["view-grid",false],["view-list",true]]) $("#" + id).addEventListener("click", () => {
  listMode = mode; $("#documents").classList.toggle("document-list", listMode);
  $("#view-grid").setAttribute("aria-pressed", String(!listMode)); $("#view-list").setAttribute("aria-pressed", String(listMode));
});
$("#login-form").addEventListener("submit", async event => {
  event.preventDefault(); const form = event.currentTarget, button = form.querySelector("button");
  $("#login-error").hidden = true; button.disabled = true;
  try { const data = new FormData(form); const value = await api("/api/login", {method:"POST",body:JSON.stringify({username:data.get("username"),password:data.get("password")})}); form.reset(); showFiles(value); }
  catch (error) { $("#login-error").textContent = error.message; $("#login-error").hidden = false; }
  finally { button.disabled = false; }
});
$("#logout").addEventListener("click", async () => { try { await api("/api/logout", {method:"POST",body:"{}"}); } finally { showLogin(); } });
api("/api/session").then(showFiles).catch(showLogin);

"use strict";

const state = { session: null, timer: null, groups: null, storage: null, activity: null };
const loginView = document.querySelector("#login-view");
const appView = document.querySelector("#app-view");
const content = document.querySelector("#content");
const nav = document.querySelector("#navigation");
const toast = document.querySelector("#toast");

const esc = value => String(value ?? "").replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const bytes = value => {
  let number = Number(value || 0);
  const units = ["B", "kB", "MB", "GB", "TB", "PB"];
  let unit = 0;
  while (Math.abs(number) >= 1024 && unit < units.length - 1) { number /= 1024; unit += 1; }
  const digits = number >= 100 || unit === 0 ? 0 : 1;
  return `${number.toLocaleString("de-DE", {minimumFractionDigits: digits, maximumFractionDigits: digits})} ${units[unit]}`;
};
const decimal = (value, digits = 1) => Number(value || 0).toLocaleString("de-DE", {minimumFractionDigits: digits, maximumFractionDigits: digits});
const utcTime = value => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const pad = number => String(number).padStart(2, "0");
  return `${pad(date.getUTCDate())}.${pad(date.getUTCMonth() + 1)}.${date.getUTCFullYear()} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`;
};
const actionLabel = value => ({read: "Lesen", write: "Schreiben", move: "Umbenennen", delete: "Löschen"}[value] || value || "—");
const nodeTypeLabel = value => ({group: "Gruppe", user: "Benutzer", computer: "Computer", unknown: "Unbekannt"}[value] || value);
const backupStateLabel = value => ({starting: "Startet", running: "Läuft", completed: "Abgeschlossen", failed: "Fehlgeschlagen", waiting: "Wartet", disabled: "Deaktiviert"}[value] || value || "Unbekannt");
function backupMessage(data) {
  const message = String(data.message || "");
  if (!message) {
    if (!data.enabled) return "Sicherungen sind nicht eingerichtet.";
    if (!data.automaticEnabled) return "Automatische Sicherungen sind ausgeschaltet; manueller Start ist verfügbar.";
    return `Täglich um ${String(data.scheduledHour).padStart(2, "0")}:00 UTC geplant.`;
  }
  if (message === "Starting backup") return "Sicherung wird gestartet.";
  if (message === "Creating consistent state database snapshot") return "Konsistenter Datenbankstand wird erstellt.";
  if (message === "Creating encrypted group archives") return "Verschlüsselte Gruppenarchive werden erstellt.";
  if (message.startsWith("Archiving group ")) return `Gruppenarchiv ${message.slice(16)} wird erstellt.`;
  if (message === "Measuring backup payload") return "Sicherungsumfang wird ermittelt.";
  if (message.startsWith("Backup payload: ")) return `Sicherungsumfang: ${message.slice(16)}`;
  if (message.startsWith("Syncing ")) return `${message.slice(8)} wird synchronisiert.`;
  const completed = message.match(/^Backup completed; (\d+) snapshot\(s\) retained$/);
  if (completed) return `Sicherung abgeschlossen; ${completed[1]} Sicherungsstände werden aufbewahrt.`;
  if (data.interrupted) return "Sicherung wurde durch einen Neustart oder Prozessabbruch unterbrochen.";
  if (data.state === "failed") return "Sicherung fehlgeschlagen. Einzelheiten stehen im Sicherungsprotokoll.";
  if (data.state === "completed") return "Sicherung abgeschlossen.";
  if (data.state === "running") return "Sicherung läuft.";
  if (data.state === "starting") return "Sicherung wird gestartet.";
  return "Kein Laufstatus verfügbar.";
}
const isoDay = date => date.toISOString().slice(0, 10);
const sum = (rows, field) => (rows || []).reduce((total, row) => total + Number(row[field] || 0), 0);

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {"Content-Type": "application/json", ...(options.headers || {})},
    credentials: "same-origin",
  });
  let body = {};
  try { body = await response.json(); } catch (_) { /* no body */ }
  if (response.status === 401 && path !== "/api/login") {
    showLogin();
    throw new Error("Die Sitzung ist abgelaufen. Bitte erneut anmelden.");
  }
  if (!response.ok) throw new Error(body.error || `Anfrage fehlgeschlagen (${response.status})`);
  return body;
}

function notice(message) {
  toast.textContent = message;
  toast.hidden = false;
  window.setTimeout(() => { toast.hidden = true; }, 4000);
}

function showLogin() {
  clearInterval(state.timer);
  state.session = null;
  appView.hidden = true;
  loginView.hidden = false;
  document.querySelector("#login-form input[name=username]").focus();
}

function showApp(session) {
  state.session = {user: session.user, expiresAt: session.expiresAt};
  document.querySelector("#session-user").textContent = session.user;
  loginView.hidden = true;
  appView.hidden = false;
  navigate(location.pathname === "/" ? "/overview" : location.pathname, true);
}

function setLoading() { content.innerHTML = '<div class="loading">Wird geladen…</div>'; }
function pageHead(title, intro, extra = "") {
  return `<header class="page-head"><div><h1>${esc(title)}</h1><p class="muted">${esc(intro)}</p></div>${extra}</header>`;
}
function empty(message) { return `<div class="empty">${esc(message)}</div>`; }
function badge(text, kind = "") { return `<span class="badge ${kind}">${esc(text)}</span>`; }

function routeFor(path) {
  if (path.startsWith("/storage/data")) return "storage-data";
  if (path.startsWith("/storage/users")) return "storage-users";
  if (path.startsWith("/shares")) return "shares";
  if (path.startsWith("/reconciliation")) return "reconciliation";
  if (path.startsWith("/activity/fslogix")) return "activity-fslogix";
  if (path.startsWith("/activity")) return "activity";
  if (path.startsWith("/trash")) return "trash";
  if (path.startsWith("/backup")) return "backup";
  if (path.startsWith("/report")) return "report";
  if (path.startsWith("/system")) return "system";
  return "overview";
}

async function navigate(path, replace = false) {
  clearInterval(state.timer);
  state.timer = null;
  const route = routeFor(path);
  if (replace) history.replaceState({}, "", path); else history.pushState({}, "", path);
  nav.querySelectorAll("a").forEach(link => link.classList.toggle("active", link.dataset.route === route));
  document.querySelector(".sidebar").classList.remove("open");
  setLoading();
  try {
    if (route === "overview") await renderOverview();
    if (route === "shares") await renderShares();
    if (route === "reconciliation") await renderReconciliation();
    if (route === "storage-data") await renderStorage("data");
    if (route === "storage-users") await renderStorage("users");
    if (route === "activity") await renderActivity();
    if (route === "activity-fslogix") await renderActivity("fslogix");
    if (route === "trash") await renderTrash();
    if (route === "backup") await renderBackup();
    if (route === "report") await renderReport();
    if (route === "system") await renderSystem();
    content.focus();
  } catch (error) {
    content.innerHTML = pageHead("Seite konnte nicht geladen werden", error.message) + `<section class="panel">${empty("Dienststatus prüfen und erneut versuchen.")}</section>`;
  }
}

function eventRows(events) {
  if (!events?.length) return '<tr><td colspan="7" class="empty">Keine passenden Ereignisse</td></tr>';
  return events.map(event => `<tr>
    <td class="timestamp">${esc(utcTime(event.timestamp))}</td>
    <td>${esc(event.user)}</td><td>${esc(event.clientIp)}</td><td>${esc(event.share)}</td>
    <td>${badge(actionLabel(event.action || event.operation))}</td>
    <td class="path">${esc(event.path || "—")}</td>
    <td>${event.success ? badge("Erfolgreich") : badge(event.result || "Fehlgeschlagen", "error")}</td>
  </tr>`).join("");
}

async function renderOverview() {
  const data = await api("/api/overview");
  const usage = data.usage || {};
  const totals = usage.totals || {};
  const backup = data.backup || {};
  content.innerHTML = pageHead("Übersicht", "Speicherbelegung, Aktivität und Sicherungsstatus.", `<span class="muted">Stand ${esc(utcTime(usage.scannedAt))}</span>`) + `
    <section class="cards">
      <article class="card"><span class="label">Daten</span><span class="value">${bytes(totals.dataBytes)}</span></article>
      <article class="card"><span class="label">Private + FSLogix</span><span class="value">${bytes(Number(totals.privateBytes || 0) + Number(totals.fslogixBytes || 0))}</span></article>
      <article class="card"><span class="label">Aktive Gruppen</span><span class="value">${esc(data.activeGroups)}</span></article>
      <article class="card"><span class="label">Ereignisse · 48 Std.</span><span class="value">${esc(data.eventCount)}</span></article>
    </section>
    <section class="split">
      <article class="panel"><div class="panel-head"><h2>Größte Datengruppen</h2><a href="/storage/data" data-nav>Alle anzeigen</a></div>${usageTable((usage.groups || []).slice(0, 7), "group")}</article>
      <article class="panel"><div class="panel-head"><h2>Sicherung</h2><a href="/backup" data-nav>Details</a></div>
        <div class="status-line">${badge(backupStateLabel(backup.state || (backup.enabled ? "waiting" : "disabled")), backup.state === "failed" ? "error" : "")}<span class="muted">${esc(backupMessage(backup))}</span></div>
        <progress class="progress-large" max="100" value="${Number(backup.percent || 0)}"></progress>
        <div class="numeric">${decimal(backup.percent)} % · ${bytes(backup.transferredBytes)} / ${bytes(backup.totalBytes)}</div>
      </article>
    </section>
    <section class="panel"><div class="panel-head"><h2>Letzte Dateiaktivitäten</h2><a href="/activity" data-nav>Protokoll öffnen</a></div>
      <div class="table-wrap"><table><thead><tr><th>Zeit (UTC)</th><th>Benutzer</th><th>Client</th><th>Freigabe</th><th>Aktion</th><th>Pfad</th><th>Ergebnis</th></tr></thead><tbody>${eventRows(data.recentEvents)}</tbody></table></div>
    </section>`;
  bindInternalLinks();
}

function usageTable(rows, type) {
  if (!rows.length) return empty("Die erste Speicherprüfung ist noch nicht abgeschlossen.");
  const maximum = Math.max(...rows.map(row => Number(type === "group" ? row.bytes : row.totalBytes)), 1);
  return `<div class="table-wrap"><table><thead><tr><th>${type === "group" ? "Gruppenordner" : "Benutzer"}</th>${type === "user" ? "<th>Private</th><th>FSLogix</th>" : ""}<th>Belegung</th><th></th></tr></thead><tbody>${rows.map(row => {
    const value = Number(type === "group" ? row.bytes : row.totalBytes);
    return `<tr><td><strong>${esc(row.name)}</strong></td>${type === "user" ? `<td class="numeric">${bytes(row.privateBytes)}</td><td class="numeric">${bytes(row.fslogixBytes)}</td>` : ""}<td class="numeric">${bytes(value)}</td><td class="usage-bar"><progress max="${maximum}" value="${value}"></progress></td></tr>`;
  }).join("")}</tbody></table></div>`;
}

function nodeMatches(node, query) {
  if (!query) return true;
  if (`${node.name} ${node.sam} ${node.type} ${nodeTypeLabel(node.type)}`.toLowerCase().includes(query)) return true;
  return (node.members || []).some(child => nodeMatches(child, query));
}

function treeNodes(nodes, query = "") {
  return nodes.filter(node => nodeMatches(node, query)).map(node => {
    const children = treeNodes(node.members || [], query);
    const title = `<span class="kind">${esc(nodeTypeLabel(node.type))}</span> <strong>${esc(node.name)}</strong>${node.sam && node.sam !== node.name ? ` <span class="muted">${esc(node.sam)}</span>` : ""}${node.cycle ? ` ${badge("Zyklus", "warn")}` : ""}`;
    return children ? `<details ${query ? "open" : ""}><summary>${title}</summary>${children}</details>` : `<div class="leaf">${title}</div>`;
  }).join("");
}

async function renderShares() {
  const data = await api("/api/groups");
  state.groups = data;
  const groups = data.groups || [];
  content.innerHTML = `<div class="shares-view">` + pageHead("Dateifreigaben", "FS_*-Ordnergruppen und ihre wirksamen verschachtelten Mitgliedschaften.", `<span class="muted">Verzeichnisstand ${esc(utcTime(data.fetchedAt))}</span>`) + `
    ${data.truncated ? `<p>${badge("Ergebnis gekürzt", "warn")} WEB_MAX_GROUP_NODES erhöhen, um alle Mitglieder anzuzeigen.</p>` : ""}
    <section class="split shares-split">
      <article class="panel"><div class="panel-head"><h2>Gruppenordner</h2><span>${groups.length}</span></div><input id="group-filter" type="search" placeholder="Gruppen oder Mitglieder filtern"><ul id="group-list" class="list"></ul></article>
      <article class="panel"><div id="tree-panel"></div></article>
    </section></div>`;
  const list = document.querySelector("#group-list");
  const tree = document.querySelector("#tree-panel");
  let selected = groups[0] || null;
  let query = "";
  const draw = () => {
    const visible = groups.filter(group => `${group.name} ${group.sam} ${group.folder}`.toLowerCase().includes(query) || group.members.some(node => nodeMatches(node, query)));
    if (selected && !visible.includes(selected)) selected = visible[0] || null;
    list.innerHTML = visible.length ? visible.map(group => `<li><button class="select-row ${group === selected ? "active" : ""}" data-guid="${esc(group.guid)}"><span><strong>${esc(group.folder)}</strong><br><span class="muted">${esc(group.sam)}</span></span><span>${group.userCount} Benutzer<br>${group.groupCount} Gruppen</span></button></li>`).join("") : empty("Keine Gruppe entspricht dem Filter.");
    if (!selected) tree.innerHTML = empty("Gruppenordner auswählen.");
    else tree.innerHTML = `<div class="panel-head"><div><h2>${esc(selected.folder)}</h2><span class="muted">${esc(selected.sam)} · ${selected.userCount} wirksame Benutzer</span></div>${selected.active ? badge("Aktiv") : badge("Archiviert", "warn")}</div><div class="tree">${treeNodes(selected.members, query) || empty("Keine direkten Mitglieder")}</div>`;
    list.querySelectorAll("button[data-guid]").forEach(button => button.addEventListener("click", () => { selected = groups.find(group => group.guid === button.dataset.guid); draw(); }));
  };
  document.querySelector("#group-filter").addEventListener("input", event => { query = event.target.value.trim().toLowerCase(); draw(); });
  draw();
}

async function renderStorage(type) {
  const data = await api("/api/storage");
  state.storage = data;
  let query = "";
  let sort = "size-desc";
  content.innerHTML = pageHead(type === "data" ? "Datenbelegung" : "Benutzerbelegung", type === "data" ? "Belegter Speicher je aktivem Gruppenordner unter /Data." : "Gemeinsame Belegung von /Private und /FSLogix je Benutzer.", `<span class="muted">Geprüft ${esc(utcTime(data.scannedAt))} in ${esc(data.scanSeconds || 0)} s</span>`) + `
    <section class="panel"><div class="toolbar"><input id="storage-filter" type="search" placeholder="${type === "data" ? "Gruppenordner" : "Benutzer"} filtern"><select id="storage-sort"><option value="size-desc">Größte zuerst</option><option value="size-asc">Kleinste zuerst</option><option value="name">Name</option></select></div><div id="storage-table"></div></section>`;
  const draw = () => {
    const source = [...(type === "data" ? data.groups || [] : data.users || [])];
    let rows = source.filter(row => row.name.toLowerCase().includes(query));
    const field = type === "data" ? "bytes" : "totalBytes";
    rows.sort((a, b) => sort === "name" ? a.name.localeCompare(b.name) : sort === "size-asc" ? Number(a[field]) - Number(b[field]) : Number(b[field]) - Number(a[field]));
    document.querySelector("#storage-table").innerHTML = `<p class="muted">${rows.length} Einträge · ${bytes(sum(rows, field))} angezeigt</p>${usageTable(rows, type === "data" ? "group" : "user")}`;
  };
  document.querySelector("#storage-filter").addEventListener("input", event => { query = event.target.value.trim().toLowerCase(); draw(); });
  document.querySelector("#storage-sort").addEventListener("change", event => { sort = event.target.value; draw(); });
  draw();
}

async function renderActivity(stream = "main") {
  const today = new Date();
  const yesterday = new Date(Date.now() - 86400000);
  const fslogix = stream === "fslogix";
  const endpoint = fslogix ? "/api/fslogix-activity" : "/api/activity";
  content.innerHTML = pageHead(
    fslogix ? "FSLogix-Protokoll" : "Aktivitätsprotokoll",
    fslogix
      ? "FSLogix-Profilcontainer-Aktivitäten getrennt vom regulären Dateiprotokoll durchsuchen."
      : "Lese-, Schreib-, Umbenennungs- und Löschvorgänge nach Datum, Identität, Freigabe, Ergebnis oder Pfad durchsuchen.",
  ) + `
    <section class="panel">
      <form id="activity-filter" class="filters">
        <label>Von (UTC)<input name="from" type="date" value="${isoDay(yesterday)}" required></label>
        <label>Bis (UTC)<input name="to" type="date" value="${isoDay(today)}" required></label>
        <label>Benutzer<input name="user" list="users-list" placeholder="Alle Benutzer"></label>
        <label>Freigabe<input name="share" list="shares-list" placeholder="Alle Freigaben"></label>
        <label>Aktion<select name="action"><option value="">Alle Aktionen</option><option value="read">Lesen</option><option value="write">Schreiben</option><option value="move">Umbenennen</option><option value="delete">Löschen</option></select></label>
        <label>Ergebnis<select name="result"><option value="">Alle Ergebnisse</option><option value="OK">Erfolgreich</option><option value="fail">Fehlgeschlagen</option></select></label>
        <label class="wide">Pfad enthält<input name="path" placeholder="Ordner oder Dateiname"></label>
        <button type="submit">Filter anwenden</button>
      </form>
      <datalist id="users-list"></datalist><datalist id="shares-list"></datalist>
      <p id="activity-summary" class="muted"></p>
      <div class="table-wrap"><table><thead><tr><th>Zeit (UTC)</th><th>Benutzer</th><th>Client</th><th>Freigabe</th><th>Aktion</th><th>Pfad</th><th>Ergebnis</th></tr></thead><tbody id="activity-rows"></tbody></table></div>
      <p><button id="load-more" hidden>Weitere laden</button></p>
    </section>`;
  const form = document.querySelector("#activity-filter");
  let cursor = 0;
  let loaded = 0;
  let matched = null;
  const load = async append => {
    const params = new URLSearchParams(new FormData(form));
    params.set("limit", "100");
    if (cursor) params.set("cursor", String(cursor));
    if (append) {
      params.set("count", "0");
      params.set("facets", "0");
    }
    const result = await api(`${endpoint}?${params}`);
    state.activity = result;
    const rows = document.querySelector("#activity-rows");
    if (append) rows.insertAdjacentHTML("beforeend", eventRows(result.events)); else rows.innerHTML = eventRows(result.events);
    loaded = append ? loaded + result.events.length : result.events.length;
    if (!append) matched = result.matchedExact ? result.matched : null;
    const shown = matched === null ? `${loaded.toLocaleString("de-DE")}${result.hasMore ? "+" : ""}` : matched.toLocaleString("de-DE");
    const indexNote = result.indexing?.ready === false ? ` · Indexaufbau ${Number(result.indexing.percent || 0).toLocaleString("de-DE")} %` : "";
    document.querySelector("#activity-summary").textContent = `${shown} passende Ereignisse${indexNote}`;
    const more = document.querySelector("#load-more");
    cursor = result.nextCursor || 0;
    more.hidden = !result.hasMore;
    if (!append) {
      for (const [id, values] of [["users-list", result.facets.users], ["shares-list", result.facets.shares]]) {
        document.querySelector(`#${id}`).innerHTML = values.filter(Boolean).map(value => `<option value="${esc(value)}">`).join("");
      }
    }
  };
  form.addEventListener("submit", async event => { event.preventDefault(); cursor = 0; try { await load(false); } catch (error) { notice(error.message); } });
  document.querySelector("#load-more").addEventListener("click", async () => { try { await load(true); } catch (error) { notice(error.message); } });
  await load(false);
}

async function renderTrash() {
  content.innerHTML = pageHead(
    "Papierkorb",
    "Gelöschte Dateien sieben Tage lang herunterladen oder am Originalpfad wiederherstellen.",
  ) + `
    <section class="panel">
      <form id="trash-filter" class="filters">
        <label>Freigabe<select name="share"><option value="">Alle Freigaben</option><option>Data</option><option>Private</option><option>FSLogix</option></select></label>
        <label class="wide">Pfad enthält<input name="path" placeholder="Ordner oder Dateiname"></label>
        <button type="submit">Aktualisieren</button>
      </form>
      <p id="trash-summary" class="muted"></p>
      <div class="table-wrap"><table><thead><tr><th>Gelöscht (UTC)</th><th>Benutzer</th><th>Freigabe</th><th>Originalpfad</th><th>Größe</th><th>Verfügbar bis</th><th>Aktionen</th></tr></thead><tbody id="trash-rows"></tbody></table></div>
    </section>`;
  const form = document.querySelector("#trash-filter");
  const load = async () => {
    const params = new URLSearchParams(new FormData(form));
    params.set("limit", "500");
    const result = await api(`/api/trash?${params}`);
    const body = document.querySelector("#trash-rows");
    if (!result.items.length) {
      body.innerHTML = '<tr><td colspan="7" class="empty">Keine gelöschten Dateien</td></tr>';
    } else {
      body.innerHTML = result.items.map(item => `<tr>
        <td class="timestamp">${esc(utcTime(item.deletedAt))}</td>
        <td>${esc(item.deletedBy)}</td>
        <td>${esc(item.share)}</td>
        <td class="path">${esc(item.path)}</td>
        <td class="numeric">${bytes(item.size)}</td>
        <td class="timestamp">${esc(utcTime(item.expiresAt))}</td>
        <td><div class="row-actions"><a class="button" href="/api/trash/download?id=${encodeURIComponent(item.id)}" download>Herunterladen</a><button type="button" data-restore="${esc(item.id)}">Wiederherstellen</button></div></td>
      </tr>`).join("");
    }
    const shown = result.items.length.toLocaleString("de-DE");
    const total = Number(result.matched || 0).toLocaleString("de-DE");
    const suffix = result.truncated ? ` · ${shown} von ${total} angezeigt` : "";
    document.querySelector("#trash-summary").textContent = `${total} Dateien · Aufbewahrung ${result.retentionDays} Tage${suffix}`;
  };
  form.addEventListener("submit", async event => {
    event.preventDefault();
    try { await load(); } catch (error) { notice(error.message); }
  });
  document.querySelector("#trash-rows").addEventListener("click", async event => {
    const button = event.target.closest("button[data-restore]");
    if (!button) return;
    if (!window.confirm("Datei am Originalpfad wiederherstellen?")) return;
    button.disabled = true;
    try {
      const result = await api("/api/trash/restore", {
        method: "POST",
        body: JSON.stringify({id: button.dataset.restore}),
      });
      notice(`${result.share}: ${result.path} wurde wiederhergestellt.`);
      await load();
    } catch (error) {
      notice(error.message);
      button.disabled = false;
    }
  });
  await load();
}

function triggerLabel(value) {
  return ({automatic: "Automatisch", web: "Weboberfläche", manual: "Befehlszeile", startup: "Systemstart"}[value] || value || "—");
}

function processIsActive(data) {
  return ["starting", "running"].includes(data?.state);
}

function backupMarkup(data) {
  const stateName = data.enabled ? (data.state || "waiting") : "disabled";
  const active = data.activeFiles || [];
  const automatic = data.automaticEnabled
    ? `Täglich um ${String(data.scheduledHour).padStart(2, "0")}:00 UTC`
    : data.enabled ? "Ausgeschaltet" : "Nicht eingerichtet";
  return `
    <section class="cards">
      <article class="card"><span class="label">Status</span><span class="value">${esc(backupStateLabel(stateName))}</span></article>
      <article class="card"><span class="label">Fortschritt</span><span class="value">${decimal(data.percent)} %</span></article>
      <article class="card"><span class="label">Übertragen</span><span class="value">${bytes(data.transferredBytes)}</span></article>
      <article class="card"><span class="label">Automatik</span><span class="value">${esc(automatic)}</span></article>
    </section>
    <section class="panel"><div class="panel-head"><h2>Aktueller Lauf</h2>${badge(backupStateLabel(stateName), stateName === "failed" ? "error" : "")}</div>
      <p>${esc(backupMessage(data))}</p>
      <progress class="progress-large" max="100" value="${Number(data.percent || 0)}"></progress>
      <div class="status-line"><strong>${bytes(data.transferredBytes)} / ${bytes(data.totalBytes)}</strong><span class="muted">${esc(data.currentSource || "")}</span><span class="muted">${esc(data.snapshot || "")}</span></div>
      <dl><dt>Auslöser</dt><dd>${esc(triggerLabel(data.trigger))}</dd><dt>Gestartet</dt><dd>${esc(utcTime(data.startedAt))}</dd><dt>Beendet</dt><dd>${esc(utcTime(data.finishedAt))}</dd></dl>
      ${active.length ? `<h3>Dateien in Bearbeitung</h3><div class="table-wrap"><table><thead><tr><th>Datei</th><th>Fortschritt</th><th>Übertragen</th></tr></thead><tbody>${active.map(file => `<tr><td class="path">${esc(file.path)}</td><td><progress max="100" value="${Number(file.percent || 0)}"></progress></td><td class="numeric">${bytes(file.transferredBytes)} / ${bytes(file.totalBytes)}</td></tr>`).join("")}</tbody></table></div>` : ""}
    </section>
    <section class="panel"><div class="panel-head"><h2>Sicherungsprotokoll</h2><span class="muted">Letzte ${data.log?.length || 0} Zeilen</span></div><pre id="backup-log" class="log">${esc((data.log || []).join("\n") || "Noch keine Ausgabe vorhanden.")}</pre></section>`;
}

async function renderBackup() {
  content.innerHTML = pageHead(
    "Sicherungen",
    "Sicherungen manuell starten sowie Fortschritt und Ausgabe verfolgen.",
    '<button id="start-backup" type="button">Sicherung jetzt starten</button>'
  ) + '<div id="backup-body"></div>';
  const button = document.querySelector("#start-backup");
  const body = document.querySelector("#backup-body");
  let logLines = [];
  let previousActive = false;
  let polling = false;
  const refresh = async includeLog => {
    try {
      const currentLog = document.querySelector("#backup-log");
      const previousScrollTop = currentLog?.scrollTop || 0;
      const data = await api(includeLog ? "/api/backup" : "/api/backup?log=0");
      if (!body.isConnected || !button.isConnected) return null;
      if (Array.isArray(data.log)) logLines = data.log;
      data.log = logLines;
      body.innerHTML = backupMarkup(data);
      button.disabled = !data.manualEnabled || processIsActive(data);
      button.title = data.manualEnabled ? "" : "Es ist kein Sicherungsziel eingerichtet.";
      const logView = document.querySelector("#backup-log");
      if (logView) {
        logView.scrollTop = includeLog ? logView.scrollHeight : previousScrollTop;
      }
      return data;
    } catch (error) {
      notice(error.message);
      return null;
    }
  };
  const poll = async () => {
    if (polling) return;
    polling = true;
    try {
      const status = await refresh(false);
      if (!status) return;
      const active = processIsActive(status);
      if (active || previousActive) {
        const complete = await refresh(true);
        previousActive = complete ? processIsActive(complete) : active;
      } else {
        previousActive = false;
      }
    } finally {
      polling = false;
    }
  };
  button.addEventListener("click", async () => {
    if (!window.confirm("Sicherung jetzt starten?")) return;
    button.disabled = true;
    try {
      await api("/api/actions/backup", {method: "POST", body: "{}"});
      notice("Sicherung wurde gestartet.");
      await poll();
    } catch (error) {
      notice(error.message);
      button.disabled = false;
    }
  });
  const initial = await refresh(true);
  if (!body.isConnected || !button.isConnected) return;
  previousActive = processIsActive(initial);
  state.timer = window.setInterval(() => { void poll(); }, 2000);
}

const reconciliationStateLabel = value => ({
  starting: "Startet",
  running: "Läuft",
  completed: "Abgeschlossen",
  failed: "Fehlgeschlagen",
  waiting: "Wartet",
}[value] || value || "Unbekannt");

const reconciliationPhaseLabel = value => ({
  starting: "Vorbereitung",
  winbind: "Domänenzwischenspeicher",
  directory: "Active Directory",
  database: "Freigabendatenbank",
  "data-permissions": "Datenberechtigungen",
  fslogix: "FSLogix",
  private: "Private Ordner",
  samba: "Samba-Konfiguration",
  completed: "Abgeschlossen",
  failed: "Fehlgeschlagen",
  waiting: "Wartet",
}[value] || value || "—");

function reconciliationMarkup(data) {
  const stateName = data.state || "waiting";
  const phase = reconciliationPhaseLabel(data.phase);
  const current = data.currentItem ? ` · ${data.currentItem}` : "";
  const message = stateName === "failed"
    ? (data.message || "Der Freigabenabgleich ist fehlgeschlagen.")
    : `${phase}${current}`;
  return `
    <section class="cards">
      <article class="card"><span class="label">Status</span><span class="value">${esc(reconciliationStateLabel(stateName))}</span></article>
      <article class="card"><span class="label">Fortschritt</span><span class="value">${decimal(data.percent)} %</span></article>
      <article class="card"><span class="label">Gestartet</span><span class="value">${esc(utcTime(data.startedAt))}</span></article>
      <article class="card"><span class="label">Automatik</span><span class="value">Alle ${esc(data.scheduledIntervalMinutes || 5)} Minuten</span></article>
    </section>
    <section class="panel"><div class="panel-head"><h2>Aktueller Abgleich</h2>${badge(reconciliationStateLabel(stateName), stateName === "failed" ? "error" : "")}</div>
      <p>${esc(message)}</p>
      <progress class="progress-large" max="100" value="${Number(data.percent || 0)}"></progress>
      <dl><dt>Phase</dt><dd>${esc(phase)}</dd><dt>Auslöser</dt><dd>${esc(triggerLabel(data.trigger))}</dd><dt>Beendet</dt><dd>${esc(utcTime(data.finishedAt))}</dd></dl>
    </section>
    <section class="panel"><div class="panel-head"><h2>Abgleichsprotokoll</h2><span class="muted">Letzte ${data.log?.length || 0} Zeilen</span></div><pre id="reconciliation-log" class="log">${esc((data.log || []).join("\n") || "Noch keine Ausgabe vorhanden.")}</pre></section>`;
}

async function renderReconciliation() {
  content.innerHTML = pageHead(
    "Freigabenabgleich",
    "Freigaben, Gruppenordner und Berechtigungen sofort mit Active Directory abgleichen.",
    '<button id="start-reconciliation" type="button">Freigaben jetzt abgleichen</button>'
  ) + '<div id="reconciliation-body"></div>';
  const button = document.querySelector("#start-reconciliation");
  const body = document.querySelector("#reconciliation-body");
  let logLines = [];
  let previousActive = false;
  let polling = false;
  const refresh = async includeLog => {
    try {
      const currentLog = document.querySelector("#reconciliation-log");
      const previousScrollTop = currentLog?.scrollTop || 0;
      const data = await api(
        includeLog ? "/api/reconciliation" : "/api/reconciliation?log=0"
      );
      if (!body.isConnected || !button.isConnected) return null;
      if (Array.isArray(data.log)) logLines = data.log;
      data.log = logLines;
      body.innerHTML = reconciliationMarkup(data);
      button.disabled = processIsActive(data);
      const logView = document.querySelector("#reconciliation-log");
      if (logView) {
        logView.scrollTop = includeLog ? logView.scrollHeight : previousScrollTop;
      }
      return data;
    } catch (error) {
      notice(error.message);
      return null;
    }
  };
  const poll = async () => {
    if (polling) return;
    polling = true;
    try {
      const status = await refresh(false);
      if (!status) return;
      const active = processIsActive(status);
      if (active || previousActive) {
        const complete = await refresh(true);
        previousActive = complete ? processIsActive(complete) : active;
      } else {
        previousActive = false;
      }
    } finally {
      polling = false;
    }
  };
  button.addEventListener("click", async () => {
    if (!window.confirm("Freigaben jetzt mit Active Directory abgleichen?")) return;
    button.disabled = true;
    try {
      await api("/api/actions/reconciliation", {method: "POST", body: "{}"});
      notice("Freigabenabgleich wurde gestartet.");
      await poll();
    } catch (error) {
      notice(error.message);
      button.disabled = false;
    }
  });
  const initial = await refresh(true);
  if (!body.isConnected || !button.isConnected) return;
  previousActive = processIsActive(initial);
  state.timer = window.setInterval(() => { void poll(); }, 1500);
}

async function renderReport() {
  content.innerHTML = pageHead("PDF-Bericht", "Vollständiger, druckbarer Stand der Dateiserver-Konfiguration und Belegung.") + `
    <section class="panel">
      <h2>Enthaltene Informationen</h2>
      <ul>
        <li>Speicherbelegung von Daten-, Private- und FSLogix-Bereichen</li>
        <li>Alle Dateifreigabegruppen mit vollständiger Mitgliedschaftshierarchie</li>
        <li>Aktueller Sicherungsstatus und laufende Dateiübertragungen</li>
        <li>Systemprüfungen und TLS-Zertifikatsdaten</li>
      </ul>
      <p>Aktivitätsprotokoll und Sicherungsprotokoll sind ausdrücklich nicht enthalten.</p>
      <p><button id="create-report" type="button">PDF erstellen</button></p>
      <p id="report-status" class="muted" role="status">Die Erstellung erfolgt vollständig in diesem Browser mit Typst.</p>
    </section>`;
  const button = document.querySelector("#create-report");
  const status = document.querySelector("#report-status");
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      status.textContent = "Berichtsdaten werden geladen…";
      const data = await api("/api/report");
      status.textContent = "Typst wird geladen…";
      const {createPdfReport} = await import("/assets/report.mjs");
      const result = await createPdfReport(data, message => { status.textContent = message; });
      status.textContent = `PDF erstellt: ${result.filename} (${bytes(result.size)})`;
    } catch (error) {
      status.textContent = `PDF konnte nicht erstellt werden: ${error.message}`;
    } finally {
      button.disabled = false;
    }
  });
}

async function renderSystem() {
  const data = await api("/api/system");
  const usage = data.usage || {};
  content.innerHTML = pageHead("System", "Status von Diensten, Zertifikat, Protokollerfassung und Speicherprüfung.", `<span class="muted">Serverzeit ${esc(utcTime(data.serverTime))}</span>`) + `
    <section class="panel"><div class="panel-head"><h2>Dienstprüfungen</h2><span>${esc(data.hostname)}</span></div><div class="check-list">
      <div class="check"><span>Domänenvertrauen</span>${data.checks.domainTrust ? badge("In Ordnung") : badge("Fehlgeschlagen", "error")}</div>
      <div class="check"><span>Samba-Konfiguration</span>${data.checks.sambaConfig ? badge("Gültig") : badge("Fehlgeschlagen", "error")}</div>
      <div class="check"><span>Aktivitätsdatenbank</span><strong>${data.audit.days} Tage · ${bytes(data.audit.bytes)}</strong></div>
      <div class="check"><span>Speicherprüfung</span><strong>${usage.scannedAt ? esc(utcTime(usage.scannedAt)) : "Ausstehend"}</strong></div>
    </div></section>
    <section class="split">
      <article class="panel"><h2>TLS-Zertifikat</h2><dl><dt>Allgemeiner Name</dt><dd>${esc(data.tls.subject?.commonName || "—")}</dd><dt>Aussteller</dt><dd>${esc(data.tls.issuer?.commonName || "—")}</dd><dt>Gültig bis</dt><dd>${esc(utcTime(data.tls.notAfter))}</dd><dt>Namen</dt><dd>${esc((data.tls.sans || []).map(value => value[1]).join(", ") || "—")}</dd></dl></article>
      <article class="panel"><h2>Protokollspeicherung</h2><dl><dt>Ältester UTC-Tag</dt><dd>${esc(data.audit.oldest || "—")}</dd><dt>Neuester UTC-Tag</dt><dd>${esc(data.audit.newest || "—")}</dd><dt>Datenbankgröße</dt><dd>${bytes(data.audit.bytes)}</dd></dl><p class="muted">Ereignisse werden dauerhaft und indexiert in der gemeinsamen SQLite-Datenbank gespeichert.</p></article>
    </section>`;
}

function bindInternalLinks() {
  content.querySelectorAll("a[data-nav]").forEach(link => link.addEventListener("click", event => { event.preventDefault(); navigate(link.pathname); }));
}

document.querySelector("#login-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button");
  const error = document.querySelector("#login-error");
  error.hidden = true; button.disabled = true;
  try {
    const values = new FormData(form);
    const session = await api("/api/login", {method: "POST", body: JSON.stringify({username: values.get("username"), password: values.get("password")})});
    form.reset();
    showApp(session);
  } catch (reason) { error.textContent = reason.message; error.hidden = false; }
  finally { button.disabled = false; }
});

document.querySelector("#logout").addEventListener("click", async () => { try { await api("/api/logout", {method: "POST", body: "{}"}); } finally { showLogin(); } });
document.querySelector("#menu-toggle").addEventListener("click", () => document.querySelector(".sidebar").classList.toggle("open"));
nav.addEventListener("click", event => { const link = event.target.closest("a"); if (link) { event.preventDefault(); navigate(link.pathname); } });
window.addEventListener("popstate", () => navigate(location.pathname, true));

api("/api/session").then(showApp).catch(showLogin);

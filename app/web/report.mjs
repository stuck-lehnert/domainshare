"use strict";

const TYPE_LABELS = {group: "Gruppe", user: "Benutzer", computer: "Computer", unknown: "Unbekannt"};
const BACKUP_LABELS = {starting: "Startet", running: "Läuft", completed: "Abgeschlossen", failed: "Fehlgeschlagen", waiting: "Wartet", disabled: "Deaktiviert"};

function typstString(value) {
  return '"' + String(value ?? "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t") + '"';
}

function formatBytes(value) {
  let number = Number(value || 0);
  const units = ["B", "kB", "MB", "GB", "TB", "PB"];
  let unit = 0;
  while (Math.abs(number) >= 1024 && unit < units.length - 1) {
    number /= 1024;
    unit += 1;
  }
  const digits = number >= 100 || unit === 0 ? 0 : 1;
  return number.toLocaleString("de-DE", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }) + " " + units[unit];
}

function formatDecimal(value, digits = 1) {
  return Number(value || 0).toLocaleString("de-DE", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

function formatUtc(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const pad = number => String(number).padStart(2, "0");
  return [
    pad(date.getUTCDate()),
    ".",
    pad(date.getUTCMonth() + 1),
    ".",
    date.getUTCFullYear(),
    " ",
    pad(date.getUTCHours()),
    ":",
    pad(date.getUTCMinutes()),
    ":",
    pad(date.getUTCSeconds()),
    " UTC",
  ].join("");
}

function fileTimestamp(value) {
  const date = new Date(value);
  const valid = Number.isNaN(date.getTime()) ? new Date() : date;
  const pad = number => String(number).padStart(2, "0");
  return [
    valid.getUTCFullYear(),
    "-",
    pad(valid.getUTCMonth() + 1),
    "-",
    pad(valid.getUTCDate()),
    "T",
    pad(valid.getUTCHours()),
    pad(valid.getUTCMinutes()),
    pad(valid.getUTCSeconds()),
    "Z",
  ].join("");
}

function backupLabel(value, enabled) {
  const state = value || (enabled ? "waiting" : "disabled");
  return BACKUP_LABELS[state] || state || "Unbekannt";
}

function backupMessage(data) {
  const message = String(data.message || "");
  if (!message) {
    if (!data.enabled) return "Sicherungen sind nicht eingerichtet.";
    if (!data.automaticEnabled) {
      return "Automatische Sicherungen sind ausgeschaltet; manueller Start ist verfügbar.";
    }
    return "Täglich um " + String(data.scheduledHour).padStart(2, "0") + ":00 UTC geplant.";
  }
  if (message === "Starting backup") return "Sicherung wird gestartet.";
  if (message === "Creating consistent state database snapshot") {
    return "Konsistenter Datenbankstand wird erstellt.";
  }
  if (message === "Creating encrypted group archives") {
    return "Verschlüsselte Gruppenarchive werden erstellt.";
  }
  if (message.startsWith("Archiving group ")) {
    return "Gruppenarchiv " + message.slice(16) + " wird erstellt.";
  }
  if (message === "Measuring backup payload") return "Sicherungsumfang wird ermittelt.";
  if (message.startsWith("Backup payload: ")) return "Sicherungsumfang: " + message.slice(16);
  if (message.startsWith("Syncing ")) return message.slice(8) + " wird synchronisiert.";
  const completed = message.match(/^Backup completed; (\d+) snapshot\(s\) retained$/);
  if (completed) return "Sicherung abgeschlossen; " + completed[1] + " Sicherungsstände werden aufbewahrt.";
  if (data.interrupted) return "Sicherung wurde durch einen Neustart oder Prozessabbruch unterbrochen.";
  if (data.state === "failed") return "Sicherung fehlgeschlagen.";
  if (data.state === "completed") return "Sicherung abgeschlossen.";
  if (data.state === "running") return "Sicherung läuft.";
  if (data.state === "starting") return "Sicherung wird gestartet.";
  return message;
}

function textCell(value, weight = "") {
  const option = weight ? 'weight: "' + weight + '", ' : "";
  return "[#text(" + option + typstString(value) + ")]";
}

function reportTable(columns, aligns, headers, rows) {
  const cells = [];
  for (const row of rows) {
    for (const value of row) cells.push(textCell(value));
  }
  return [
    "#table(",
    "  columns: (" + columns.join(", ") + ",),",
    "  align: (" + aligns.join(", ") + ",),",
    "  inset: (x: 4pt, y: 3pt),",
    "  stroke: 0.35pt + luma(75%),",
    "  table.header(" + headers.map(value => textCell(value, "semibold")).join(", ") + "),",
    cells.length ? "  " + cells.join(",\n  ") + "," : "",
    ")",
  ].filter(Boolean).join("\n");
}

function keyValueTable(rows) {
  return reportTable(["34%", "66%"], ["left", "left"], ["Angabe", "Wert"], rows);
}

function treeRows(nodes, depth = 0, result = []) {
  for (const node of nodes || []) {
    const type = TYPE_LABELS[node.type] || node.type || "Unbekannt";
    result.push(
      "#tree-row(" +
      depth + ", " +
      typstString(type) + ", " +
      typstString(node.name || node.sam || "Unbekannt") + ", " +
      typstString(node.sam || "") + ", " +
      (node.cycle ? "true" : "false") +
      ")"
    );
    treeRows(node.members || [], depth + 1, result);
  }
  return result;
}

export function buildReportSource(data) {
  const generatedAt = data.generatedAt || new Date().toISOString();
  const storage = data.storage || {};
  const totals = storage.totals || {};
  const groupsSnapshot = data.groups || {};
  const groups = groupsSnapshot.groups || [];
  const backup = data.backup || {};
  const system = data.system || {};
  const tls = system.tls || {};
  const checks = system.checks || {};
  const totalUserBytes = Number(totals.privateBytes || 0) + Number(totals.fslogixBytes || 0);
  const totalBytes = Number(totals.dataBytes || 0) + totalUserBytes;
  const sans = (tls.sans || [])
    .map(value => Array.isArray(value) ? value[1] : value)
    .filter(Boolean)
    .join(", ") || "—";

  const parts = [
    '#set document(title: "Dateiserver-Bericht", author: "Dateiserver")',
    '#set page(paper: "a4", margin: (x: 15mm, top: 14mm, bottom: 17mm), footer: context align(center, text(size: 7pt, fill: luma(45%))[Seite #counter(page).display("1")]))',
    '#set text(font: "Libertinus Serif", size: 9pt, lang: "de")',
    "#set par(leading: 0.58em)",
    "#set heading(numbering: none)",
    '#let tree-row(depth, kind, name, sam, cycle) = block(width: 100%, above: 1.8pt, below: 1.8pt, breakable: false)[#grid(columns: (depth * 9pt + 8pt, 44pt, 1fr), column-gutter: 4pt, align: (left, left, left), [#text(size: 7.5pt, fill: luma(45%))[#if depth == 0 [•] else [>]]], [#text(size: 7.5pt, fill: luma(40%))[#kind]], [#name#if sam != "" and sam != name [#text(size: 7.5pt, fill: luma(40%))[ (#sam)]]#if cycle [#text(size: 7.5pt)[ (Zyklus)]]])]',
    "",
    '#text(size: 22pt, weight: "semibold")[Dateiserver-Bericht]',
    "#v(5pt)",
    keyValueTable([
      ["Server", system.hostname || "—"],
      ["Erstellt", formatUtc(generatedAt)],
      ["Verzeichnisstand", formatUtc(groupsSnapshot.fetchedAt)],
      ["Dateifreigabegruppen", String(groups.length)],
      ["Verzeichnisabfrage gekürzt", groupsSnapshot.truncated ? "Ja" : "Nein"],
      ["Speicherstand", formatUtc(storage.scannedAt)],
      ["Serverzeit", formatUtc(system.serverTime)],
    ]),
    "",
    "#v(8pt)",
    "#text(size: 8pt)[Aktivitätsprotokoll und Sicherungsprotokoll sind nicht Bestandteil dieses Berichts.]",
    "",
    "= Speicherbelegung",
    keyValueTable([
      ["Daten", formatBytes(totals.dataBytes)],
      ["Private", formatBytes(totals.privateBytes)],
      ["FSLogix", formatBytes(totals.fslogixBytes)],
      ["Private + FSLogix", formatBytes(totalUserBytes)],
      ["Gesamt", formatBytes(totalBytes)],
      ["Prüfdauer", formatDecimal(storage.scanSeconds, 3) + " s"],
    ]),
    "",
    "== Datenbelegung je Gruppenordner",
    (storage.groups || []).length
      ? reportTable(
        ["1fr", "auto"],
        ["left", "right"],
        ["Gruppenordner", "Belegung"],
        storage.groups.map(row => [row.name || "—", formatBytes(row.bytes)])
      )
      : "Noch keine Speicherprüfung vorhanden.",
    "",
    "== Benutzerbelegung",
    (storage.users || []).length
      ? reportTable(
        ["1fr", "auto", "auto", "auto"],
        ["left", "right", "right", "right"],
        ["Benutzer", "Private", "FSLogix", "Gesamt"],
        storage.users.map(row => [
          row.name || "—",
          formatBytes(row.privateBytes),
          formatBytes(row.fslogixBytes),
          formatBytes(row.totalBytes),
        ])
      )
      : "Noch keine Speicherprüfung vorhanden.",
    "",
    "= Dateifreigaben und Mitgliedschaften",
    groupsSnapshot.truncated
      ? "#text(weight: \"semibold\")[Hinweis: Die Verzeichnisabfrage wurde gekürzt; die nachfolgende Hierarchie ist nicht vollständig.]"
      : "Die nachfolgenden Hierarchien zeigen alle wirksamen verschachtelten Mitgliedschaften.",
  ];

  for (const group of groups) {
    parts.push("");
    parts.push("#heading(level: 2, " + typstString(group.folder || group.name || group.sam || "Unbekannt") + ")");
    parts.push(keyValueTable([
      ["Freigabename", group.name || "—"],
      ["Ordner", group.folder || "—"],
      ["Ordnergruppe", group.sam || "—"],
      ["Objekt-GUID", group.guid || "—"],
      ["Status", group.active ? "Aktiv" : "Archiviert"],
      ["Wirksame Benutzer", String(group.userCount || 0)],
      ["Enthaltene Gruppen", String(group.groupCount || 0)],
    ]));
    const rows = treeRows(group.members || []);
    parts.push(rows.length ? rows.join("\n") : "Keine direkten Mitglieder.");
  }

  const backupState = backupLabel(backup.state, backup.enabled);
  parts.push("");
  parts.push("= Sicherung");
  parts.push(keyValueTable([
    ["Eingerichtet", backup.enabled ? "Ja" : "Nein"],
    ["Automatik", backup.automaticEnabled ? "Aktiv" : "Ausgeschaltet"],
    [
      "Geplanter Start",
      backup.automaticEnabled
        ? String(backup.scheduledHour ?? 0).padStart(2, "0") + ":00 UTC"
        : "—",
    ],
    ["Status", backupState],
    ["Fortschritt", formatDecimal(backup.percent) + " %"],
    ["Übertragen", formatBytes(backup.transferredBytes) + " / " + formatBytes(backup.totalBytes)],
    ["Gestartet", formatUtc(backup.startedAt)],
    ["Beendet", formatUtc(backup.finishedAt)],
    ["Sicherungsstand", backup.snapshot || "—"],
    ["Aktuelle Quelle", backup.currentSource || "—"],
    ["Statusmeldung", backupMessage(backup)],
  ]));

  if ((backup.activeFiles || []).length) {
    parts.push("");
    parts.push("== Dateien in Bearbeitung");
    parts.push(reportTable(
      ["1fr", "auto", "auto"],
      ["left", "right", "right"],
      ["Datei", "Fortschritt", "Übertragen"],
      backup.activeFiles.map(file => [
        file.path || "—",
        formatDecimal(file.percent) + " %",
        formatBytes(file.transferredBytes) + " / " + formatBytes(file.totalBytes),
      ])
    ));
  }

  parts.push("");
  parts.push("= System");
  parts.push(keyValueTable([
    ["Domänenvertrauen", checks.domainTrust ? "In Ordnung" : "Fehlgeschlagen"],
    ["Samba-Konfiguration", checks.sambaConfig ? "Gültig" : "Fehlgeschlagen"],
  ]));
  parts.push("");
  parts.push("== TLS-Zertifikat");
  parts.push(keyValueTable([
    ["Allgemeiner Name", (tls.subject || {}).commonName || "—"],
    ["Aussteller", (tls.issuer || {}).commonName || "—"],
    ["Gültig bis", formatUtc(tls.notAfter)],
    ["Namen", sans],
  ]));
  parts.push("");
  parts.push("#text(size: 8pt)[Dieser Bericht wurde vollständig im Browser mit Typst erzeugt.]");

  return parts.join("\n");
}

let compilerPromise;

async function getCompiler() {
  if (!compilerPromise) {
    compilerPromise = (async () => {
      const module = await import("/assets/vendor/typst/0.6.0-csp1/typst.mjs");
      module.$typst.setCompilerInitOptions({
        getModule: () => ({module_or_path: "/assets/vendor/typst/0.6.0-csp1/compiler.wasm"}),
      });
      module.$typst.use(
        module.TypstSnippet.disableDefaultFontAssets(),
        module.TypstSnippet.preloadFontFromUrl("/assets/vendor/typst/0.6.0-csp1/LibertinusSerif-Regular.otf"),
        module.TypstSnippet.preloadFontFromUrl("/assets/vendor/typst/0.6.0-csp1/LibertinusSerif-Semibold.otf")
      );
      return module.$typst;
    })();
  }
  return compilerPromise;
}

export async function createPdfReport(data, progress = () => {}) {
  progress("Typst-Compiler wird im Browser geladen…");
  const compiler = await getCompiler();
  progress("PDF wird im Browser gesetzt…");
  const pdf = await compiler.pdf({mainContent: buildReportSource(data)});
  if (!(pdf instanceof Uint8Array) || pdf.length < 5) {
    throw new Error("Typst hat keine gültige PDF-Datei erzeugt.");
  }

  const filename = "dateiserver-bericht-" + fileTimestamp(data.generatedAt) + ".pdf";
  const url = URL.createObjectURL(new Blob([pdf], {type: "application/pdf"}));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  return {filename, size: pdf.length};
}

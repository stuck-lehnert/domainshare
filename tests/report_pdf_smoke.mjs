import fs from "node:fs";

globalThis.window = globalThis;

const report = await import(new URL("../app/web/report.mjs", import.meta.url));
const typst = await import(new URL("../app/web/vendor/typst/typst.mjs", import.meta.url));
globalThis.Function = () => {
  throw new Error("JavaScript dynamic code generation is disabled by CSP");
};
const vendor = new URL("../app/web/vendor/typst/", import.meta.url);
const binary = name => new Uint8Array(fs.readFileSync(new URL(name, vendor)));

typst.$typst.setCompilerInitOptions({
  getModule: () => ({module_or_path: binary("compiler.wasm")}),
});
typst.$typst.use(
  typst.TypstSnippet.disableDefaultFontAssets(),
  typst.TypstSnippet.preloadFontData(binary("LibertinusSerif-Regular.otf")),
  typst.TypstSnippet.preloadFontData(binary("LibertinusSerif-Semibold.otf"))
);

const data = {
  generatedAt: "2026-08-01T20:27:05+00:00",
  storage: {
    scannedAt: "2026-08-01T20:20:00+00:00",
    scanSeconds: 1.25,
    totals: {dataBytes: 1048576, privateBytes: 2048, fslogixBytes: 4096},
    groups: [{name: "Forschung & Entwicklung", bytes: 1048576}],
    users: [{name: "ludwig.lehnert", privateBytes: 2048, fslogixBytes: 4096, totalBytes: 6144}],
  },
  groups: {
    fetchedAt: "2026-08-01T20:21:00+00:00",
    truncated: false,
    groups: [{
      folder: "Forschung [2026] #1",
      sam: "FS_Forschung",
      active: true,
      userCount: 1,
      groupCount: 2,
      members: [{
        type: "group",
        name: "Domänen-Benutzer",
        sam: "Domain Users",
        members: [{
          type: "group",
          name: "Forschung und Entwicklung – interne Projektmitglieder",
          sam: "Forschung_Entwicklung_Intern",
          members: [{type: "user", name: "Ludwig \"Test\" Lehnert", sam: "ludwig.lehnert", members: []}],
        }],
      }],
    }],
  },
  backup: {
    enabled: true,
    scheduledHour: 2,
    state: "completed",
    percent: 100,
    transferredBytes: 1054720,
    totalBytes: 1054720,
    startedAt: "2026-08-01T02:00:00+00:00",
    finishedAt: "2026-08-01T02:01:00+00:00",
    snapshot: "2026-08-01T020000Z",
    message: "Backup completed; 3 snapshot(s) retained",
    activeFiles: [],
    log: ["DARF NICHT IN DIE PDF"],
  },
  system: {
    hostname: "files.example.test",
    serverTime: "2026-08-01T20:27:05+00:00",
    checks: {domainTrust: true, sambaConfig: true},
    tls: {
      subject: {commonName: "files.example.test"},
      issuer: {commonName: "Interne CA"},
      notAfter: "2027-08-01T00:00:00+00:00",
      sans: [["DNS", "files.example.test"]],
    },
    audit: {secret: "DARF EBENFALLS NICHT IN DIE PDF"},
  },
};

const source = report.buildReportSource(data);
if (!source.includes('title: "DomainShare-Bericht", author: "DomainShare"')) {
  throw new Error("report metadata is missing the DomainShare name");
}

if (source.includes("DARF NICHT") || source.includes("DARF EBENFALLS NICHT")) {
  throw new Error("log data leaked into Typst source");
}
if (
  source.includes("[- ]") ||
  !source.includes("columns: (depth * 9pt + 8pt, 44pt, 1fr)") ||
  !source.includes("above: 1.8pt, below: 1.8pt")
) {
  throw new Error("group hierarchy is not rendered as an indented row grid");
}
const pdf = await typst.$typst.pdf({mainContent: source});
if (!pdf || new TextDecoder().decode(pdf.slice(0, 5)) !== "%PDF-") {
  throw new Error("Typst did not produce a PDF");
}
if (process.env.REPORT_SMOKE_OUTPUT) {
  fs.writeFileSync(process.env.REPORT_SMOKE_OUTPUT, pdf);
}
console.log("client Typst PDF smoke test passed (" + pdf.length + " bytes)");

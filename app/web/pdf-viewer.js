"use strict";

// Configure the upstream generic viewer before its application starts.
const target = window.parent.document;
function configureViewer(event) {
  if (event.detail?.source !== window) return;
  const options = window.PDFViewerApplicationOptions;
  const app = window.PDFViewerApplication;
  const file = new URLSearchParams(location.search).get("file") || "";
  const match = file.match(/^\/api\/documents\/([a-f0-9]{32})\/content(?:\?v=[a-f0-9]{16})?$/);
  if (!match) history.replaceState({}, "", location.pathname + "?file=");
  options.setAll({
    defaultUrl: "", disablePreferences: true, disableHistory: true,
    localeProperties: {lang: "de"}, viewerCssTheme: 1,
    enableScripting: false, annotationEditorMode: -1, annotationMode: 1,
    enableComment: false, enableAltText: false, enableGuessAltText: false,
    enableAltTextModelDownload: false, enableHighlightFloatingButton: false,
    enableWebGPU: false, defaultZoomValue: "page-width",
  });
  // Downloads use the original endpoint and its fresh access checks.
  const download = async () => {
    if (!match) return;
    const link = document.createElement("a");
    link.href = `/api/documents/${match[1]}/download`;
    link.download = app._docFilename || "";
    document.body.append(link); link.click(); link.remove();
  };
  app.download = app.save = app.downloadOrSave = download;
  const run = app.run.bind(app);
  app.run = async config => {
    await run(config);
    if (app._openFileInput) app._openFileInput.disabled = true;
  };
  const open = app.open.bind(app);
  app.open = async args => {
    if (!match || args?.url !== file) return;
    try { await open(args); }
    catch (error) {
      // PDF.js already shows these loading errors. Revocation is handled by
      // the parent dialog's permission refresh, rather than an unhandled promise.
      if (!["ResponseException", "InvalidPDFException", "PasswordException", "UnknownErrorException", "AbortException"].includes(error.name)) throw error;
    }
  };
}
target.addEventListener("webviewerloaded", configureViewer);
window.addEventListener("pagehide", () => target.removeEventListener("webviewerloaded", configureViewer), {once: true});
document.addEventListener("drop", event => { event.preventDefault(); event.stopImmediatePropagation(); }, true);

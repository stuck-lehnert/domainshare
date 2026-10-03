// Exercise the real portal frontend with deterministic permission-filtered responses.
import fs from "node:fs";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import {createRequire} from "node:module";
import {fileURLToPath} from "node:url";
const require = createRequire(import.meta.url);
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const root = fileURLToPath(new URL("../app/web/", import.meta.url));
const out = process.env.SCREENSHOT_DIR || fs.mkdtempSync(path.join(os.tmpdir(), "adfs-portal-review-"));
fs.mkdirSync(out,{recursive:true});
const sources=[{id:'data:finance',label:'Finanzen',kind:'data'},{id:'data:projects',label:'Projekte',kind:'data'},{id:'private:alice',label:'Private',kind:'private'}];
const fixtures=[
 ['Rechnung Oktober 2026.pdf','pdf','data:finance','Rechnung für Büroausstattung\nReferenz FINANZ742\nGesamtbetrag 1.500,00 EUR',true],
 ['Projektplan für die Einführung des neuen Dokumentenportals und die Schulung aller Mitarbeiter.docx','docx','data:projects','Projektplan mit Schulung und Zeitplan. Start im Oktober.',false],
 ['Meine Notizen.txt','txt','private:alice','Meine persönlichen Notizen. Termin zur Budgetplanung am Mittwoch.',false],
 ['Umsatzübersicht.csv','csv','data:finance','Quartal,Umsatz\nQ1,120000\nQ2,135000',false],
 ['Gescanntes Protokoll.pdf','pdf','data:projects','',true]
].map(([name,extension,sourceId,text,hasPreview],index)=>({id:(index+1).toString(16).padStart(32,'0'),name,extension,sourceId,text,path:'Dokumente/'+name,source:sources.find(source=>source.id===sourceId).label,kind:sources.find(source=>source.id===sourceId).kind,size:143360+index*1024,modified:1791023400-index*86400,state:index===4?'ocr':'ready',pages:extension==='pdf'?3:0,hasPreview,version:'aaaaaaaaaaaaaaaa',snippet:text}));
// A small native three-page PDF exercises the real viewer, including its find bar.
function viewerPdf() {
 const objects=['<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R 5 0 R 7 0 R] /Count 3 >>'];
 for(let page=1;page<=3;page++){
  const content=`BT /F1 24 Tf 72 720 Td (PDFVIEWER742 - Page ${page}) Tj ET`;
  objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 9 0 R >> >> /Contents ${page*2+2} 0 R >>`);
  objects.push(`<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`);
 }
 objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
 let pdf='%PDF-1.7\n', offsets=[0];
 objects.forEach((object,index)=>{offsets.push(Buffer.byteLength(pdf));pdf+=`${index+1} 0 obj\n${object}\nendobj\n`;});
 const offset=Buffer.byteLength(pdf);pdf+=`xref\n0 10\n0000000000 65535 f \n`;
 offsets.slice(1).forEach(value=>{pdf+=`${String(value).padStart(10,'0')} 00000 n \n`;});
 return Buffer.from(pdf+`trailer\n<< /Size 10 /Root 1 0 R >>\nstartxref\n${offset}\n%%EOF\n`);
}
const pdf=viewerPdf();
let role='user', loggedIn=true, deniedId='', pendingRequests=[], errors=[];
const browser=await chromium.launch({headless:true});
try {
 const page=await browser.newPage({viewport:{width:1500,height:1050}});
 page.on('pageerror',error=>errors.push(error.message));
 await page.route('http://adfs.test/**',async route=>{
  const url=new URL(route.request().url()); let body,type='application/json',status=200;
  if(url.pathname==='/api/session'){
   if(!loggedIn){status=401;body={error:'Anmeldung erforderlich'};}else body={user:'EXAMPLE\\alice',role,expiresAt:9999999999};
  }else if(url.pathname==='/api/login'){loggedIn=true;body={user:'EXAMPLE\\alice',role,expiresAt:9999999999};}
  else if(url.pathname==='/api/logout'){loggedIn=false;body={ok:true};}
  else if(url.pathname==='/api/documents'){
   pendingRequests.push(url.searchParams.get('q'));
   const query=(url.searchParams.get('q')||'').toLowerCase(),scope=url.searchParams.get('scope');
   let rows=fixtures.filter(row=>row.id!==deniedId);
   if(query)rows=rows.filter(row=>(scope==='name'?row.name:scope==='content'?row.text:row.name+' '+row.text).toLowerCase().includes(query));
   if(url.searchParams.get('source'))rows=rows.filter(row=>row.sourceId===url.searchParams.get('source'));
   if(url.searchParams.get('type'))rows=rows.filter(row=>row.extension===url.searchParams.get('type'));
   body={items:rows,total:rows.length,hasMore:false,sources,types:['pdf','docx','txt','csv'],pending:rows.filter(row=>row.state==='ocr').length};
  }else if(url.pathname.startsWith('/api/documents/')){
   const parts=url.pathname.split('/'),row=fixtures.find(row=>row.id===parts[3]);
   if(!row||row.id===deniedId){status=404;body={error:'Datei nicht verfügbar'};}
   else if(parts[4]==='preview'){
    type='image/svg+xml';body=Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="700" height="940" viewBox="0 0 700 940"><rect width="700" height="940" fill="white"/><text x="70" y="100" font-family="Arial" font-size="30">RECHNUNG</text><text x="70" y="160" font-family="Arial" font-size="18">Oktober 2026 · FINANZ742</text><path d="M70 200h560M70 500h560" stroke="#aaa"/><text x="70" y="275" font-family="Arial" font-size="20">Büroausstattung</text><text x="70" y="350" font-family="Arial" font-size="18">3 × Bildschirm</text><text x="480" y="350" font-family="Arial" font-size="18">1.500,00 EUR</text><text x="70" y="560" font-family="Arial" font-size="20">Gesamtbetrag: 1.500,00 EUR</text></svg>`);
   }else if(parts[4]==='content'){type='application/pdf';body=pdf;}else body=row;
  }else if(url.pathname.startsWith('/assets/vendor/pdfjs/6.3.289-app1/')){
   const relative=url.pathname.slice('/assets/vendor/pdfjs/6.3.289-app1/'.length);
   const filename=root+'vendor/pdfjs/6.3.289-app1/'+relative;
   type=({'.html':'text/html','.mjs':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.ftl':'text/plain','.json':'application/json','.wasm':'application/wasm','.ttf':'font/ttf'})[path.extname(filename)]||'application/octet-stream';
   body=fs.readFileSync(filename);
  }else if(url.pathname==='/assets/pdf-viewer.js'){type='text/javascript';body=fs.readFileSync(root+'pdf-viewer.js');}
  else if(url.pathname==='/assets/pdf-viewer.css'){type='text/css';body=fs.readFileSync(root+'pdf-viewer.css');}
  else if(url.pathname==='/assets/portal.js'){type='text/javascript';body=fs.readFileSync(root+'portal.js');}
  else if(url.pathname==='/assets/styles.css'){type='text/css';body=fs.readFileSync(root+'styles.css');}
  else {type='text/html';body=fs.readFileSync(root+'portal.html');}
  await route.fulfill({status,contentType:type,body:Buffer.isBuffer(body)?body:JSON.stringify(body)});
 });
 const shot=async name=>{await page.waitForFunction(()=>Array.from(document.images).filter(img=>img.loading!=='lazy'||img.getBoundingClientRect().top<innerHeight).every(img=>img.complete));await page.screenshot({path:path.join(out,name+'.png'),fullPage:!await page.locator('#document-dialog').isVisible()});};
 const all=()=>page.waitForFunction(()=>document.querySelectorAll('.document-card').length===5);
 await page.goto('http://adfs.test/');await all();
 assert.equal(await page.locator('#admin-link').isHidden(),true);
 assert.equal(await page.locator('nav a[href^="/admin"]').count(),0);
 assert.equal(await page.locator('#source-filter').textContent().then(text=>text.includes('Mein Private-Ordner')),true);
 assert.match(await page.locator('#index-progress').innerText(),/1 Datei/);
 await shot('01-portal-desktop');
 await page.locator('#search-query').fill('FINANZ742');
 await page.waitForFunction(()=>document.querySelectorAll('.document-card').length===1);
 assert.match(await page.locator('.document-card').innerText(),/Rechnung Oktober/);
 await page.locator('#search-scope').selectOption('content');
 await page.locator('[data-document]').click();
 await page.locator('#document-dialog').waitFor({state:'visible'});
 assert.equal(await page.locator('.document-text, #document-content').count(),0);
 const viewer=page.frameLocator('#document-pdf-viewer');
 await viewer.locator('.page canvas').first().waitFor();
 assert.deepEqual(await page.locator('#document-dialog').boundingBox(),{x:0,y:0,width:1500,height:1050});
 await viewer.locator('#pageNumber').fill('2');await viewer.locator('#pageNumber').press('Enter');
 await page.waitForFunction(()=>document.querySelector('#document-pdf-viewer').contentWindow.PDFViewerApplication.page===2);
 await page.waitForTimeout(2500);
 assert.equal(await viewer.locator('#pageNumber').inputValue(),'2','Detail polling must preserve the selected page');
 const scale=await page.evaluate(()=>document.querySelector('#document-pdf-viewer').contentWindow.PDFViewerApplication.pdfViewer.currentScale);
 await viewer.locator('#zoomInButton').click();
 await page.waitForFunction(old=>document.querySelector('#document-pdf-viewer').contentWindow.PDFViewerApplication.pdfViewer.currentScale>old,scale);
 await viewer.locator('#viewFindButton').click();await viewer.locator('#findInput').fill('PDFVIEWER742');
 await viewer.locator('#findResultsCount').filter({hasText:/3/}).waitFor();
 assert.equal(await page.locator('#document-download').getAttribute('href'),'/api/documents/'+fixtures[0].id+'/download');
 await shot('02-portal-document-preview');
 await page.locator('#document-close').click();
 await page.locator('#reset-filters').click();await all();
 await page.locator(`[data-document="${fixtures[1].id}"]`).click();
 await page.locator('#document-dialog').waitFor({state:'visible'});
 assert.equal(await page.locator('.document-text, #document-content, #document-pdf-viewer').count(),0);
 assert.equal(await page.locator('#document-dialog').innerText().then(text=>text.includes('Projektplan mit Schulung')),false);
 assert.ok((await page.locator('#document-dialog').boundingBox()).height<400,'Files without a visual preview should have a compact dialog');
 await shot('02b-office-without-document-text');
 for(const extension of ['md','odt']) {
  await page.locator('#document-close').click();fixtures[1].extension=extension;
  await page.locator(`[data-document="${fixtures[1].id}"]`).click();
  await page.locator('#document-dialog').waitFor({state:'visible'});
  assert.equal(await page.locator('.document-text, #document-content, #document-pdf-viewer').count(),0);
  assert.equal(await page.locator('#document-dialog').innerText().then(text=>text.includes('Projektplan mit Schulung')),false);
 }
 fixtures[1].extension='docx';
 await page.locator('#document-close').click();
 await page.locator('#source-filter').selectOption('private:alice');
 await page.waitForFunction(()=>document.querySelectorAll('.document-card').length===1);
 assert.match(await page.locator('.document-card').innerText(),/Meine Notizen/);
 await page.locator('#reset-filters').click();await all();
 await page.locator('#view-list').click();
 assert.equal(await page.locator('#documents').evaluate(element=>element.classList.contains('document-list')),true);
 await shot('03-portal-list');
 // A background OCR completion becomes searchable without reloading.
 fixtures[4].text='Erkanntes Protokoll mit dem Suchwort SCANLIVE742';fixtures[4].snippet=fixtures[4].text;fixtures[4].state='ready';
 await page.locator('#search-query').fill('SCANLIVE742');
 await page.waitForFunction(()=>document.querySelectorAll('.document-card').length===1);
 await page.locator('[data-document]').click();
 await page.locator('#document-dialog').waitFor({state:'visible'});
 assert.equal(await page.locator('.document-text, #document-content').count(),0);
 deniedId=fixtures[4].id;
 await page.locator('#document-dialog').waitFor({state:'hidden',timeout:6000});
 assert.match(await page.locator('#toast').innerText(),/nicht verfügbar/);
 deniedId=''; await page.locator('#reset-filters').click();await all();
 await page.locator('#view-grid').click();
 for(const width of [900,390]){
  await page.setViewportSize({width,height:width===390?844:1000});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Portal overflows at '+width);
  await shot('04-portal-'+width);
 }
 await page.locator('[data-document]').first().click();
 await page.locator('#document-dialog').waitFor({state:'visible'});
 assert.equal(await page.evaluate(()=>document.querySelector('#document-dialog').scrollWidth>document.querySelector('#document-dialog').clientWidth),false);
 await page.frameLocator('#document-pdf-viewer').locator('.page canvas').first().waitFor();
 assert.deepEqual(await page.locator('#document-dialog').boundingBox(),{x:0,y:0,width:390,height:844});
 await shot('05-portal-mobile-document');await page.locator('#document-close').click();
 await page.locator('#logout').click();await page.locator('#login-view').waitFor({state:'visible'});
 await page.locator('#login-form input[name=username]').fill('alice');
 await page.locator('#login-form input[name=password]').fill('password');
 await page.locator('#login-form button').click();await all();
 assert.equal(await page.locator('#admin-link').isHidden(),true);
 role='domain-admin';await page.goto('http://adfs.test/');await all();
 assert.equal(await page.locator('#admin-link').getAttribute('href'),'/admin/overview');
 assert.equal(await page.locator('#admin-link').isVisible(),true);
 assert.ok(pendingRequests.includes('FINANZ742')&&pendingRequests.includes('SCANLIVE742'));
 assert.deepEqual(errors,[]);
 console.log('PASS: user login, admin separation, live content search, own-private filter, preview/download links, OCR refresh, revocation, grid/list, desktop/mobile.');
 console.log('Screenshots: '+out);
} finally {await browser.close();}

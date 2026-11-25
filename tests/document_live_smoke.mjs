// Called by the disposable AD/Samba E2E stack with its local test credentials.
import fs from "node:fs";
import {createRequire} from "node:module";
import assert from "node:assert/strict";
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||"playwright");
const out=process.env.SCREENSHOT_DIR||'/tmp/domainshare-documents-live-review';fs.mkdirSync(out,{recursive:true});
const host=process.env.PREVIEW_HTTPS_HOST;
const origin=`https://${host}:${process.env.PREVIEW_HTTPS_PORT}`;
const browser=await chromium.launch({headless:true,args:[`--host-resolver-rules=MAP ${host} 127.0.0.1`,"--ignore-certificate-errors"]});
try{
 const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1500,height:1050}});
 const page=await context.newPage();const errors=[];page.on('pageerror',error=>errors.push(error.message));
 await page.goto(origin+'/');
 await page.locator('#login-view').waitFor({state:'visible'});
 await page.locator('input[name=username]').fill('alice');await page.locator('input[name=password]').fill(process.env.PREVIEW_USER_PASSWORD);
 await page.locator('#login-form button').click();await page.locator('.document-card').first().waitFor();
 assert.equal(await page.locator('#admin-link').isHidden(),true);
 await page.screenshot({path:out+'/01-live-user-files.png',fullPage:true});
 await page.locator('#search-query').fill('SCANNEDUNIQUE742');
 await page.waitForFunction(()=>document.querySelectorAll('.document-card').length===1);
 await page.locator('[data-document]').click();await page.locator('#document-dialog').waitFor({state:'visible'});
 await page.frameLocator('#document-pdf-viewer').locator('.page canvas').first().waitFor();
 assert.equal(await page.locator('.document-text, #document-content').count(),0);
 assert.deepEqual(await page.locator('#document-dialog').boundingBox(),{x:0,y:0,width:1500,height:1050});
 await page.screenshot({path:out+'/02-live-scan-ocr-preview.png',fullPage:false});
 await page.locator('#document-close').click();
 const downloadStarted=page.waitForEvent('download');
 await page.locator('.document-card a[download]').click();
 const download=await downloadStarted;assert.equal(await download.failure(),null);assert.equal(download.suggestedFilename(),'scanned-invoice.pdf');
 const original=fs.readFileSync(await download.path());assert.equal(original.subarray(0,5).toString(),'%PDF-');
 await page.locator('#search-query').fill('digital-invoice.pdf');
 await page.locator('.document-card').filter({hasText:'digital-invoice.pdf'}).waitFor();
 await page.locator('[data-document]').click();
 const viewer=page.frameLocator('#document-pdf-viewer');
 await viewer.locator('.page canvas').first().waitFor();
 assert.equal(await page.evaluate(()=>document.querySelector('#document-pdf-viewer').contentWindow.PDFViewerApplication.pagesCount),3);
 await viewer.locator('#pageNumber').fill('2');await viewer.locator('#pageNumber').press('Enter');
 await page.waitForFunction(()=>document.querySelector('#document-pdf-viewer').contentWindow.PDFViewerApplication.page===2);
 await page.waitForTimeout(2500);assert.equal(await viewer.locator('#pageNumber').inputValue(),'2');
 await viewer.locator('#zoomInButton').click();
 await viewer.locator('#viewFindButton').click();await viewer.locator('#findInput').fill('NATIVEINVOICE742');
 await viewer.locator('#findResultsCount').filter({hasText:/1/}).waitFor();
 await page.screenshot({path:out+'/02b-live-interactive-pdf-viewer.png',fullPage:false});
 await page.setViewportSize({width:390,height:844});
 assert.deepEqual(await page.locator('#document-dialog').boundingBox(),{x:0,y:0,width:390,height:844});
 await page.screenshot({path:out+'/02c-live-mobile-pdf-viewer.png',fullPage:false});
 await page.locator('#document-close').click();
 // Real seeded JPEG/PNG files exercise the image parser and responsive dialog together.
 for(const name of ['portrait-4000x6000.jpg','landscape-6000x4000.png','small-320x240.png','private-portrait.jpg']){
  await page.setViewportSize({width:1500,height:1050});
  await page.locator('#search-query').fill(name);
  const card=page.locator('.document-card').filter({hasText:name});
  await card.waitFor();await card.locator('[data-document]').click();
  await page.locator('#document-preview img').waitFor();
  await page.waitForFunction(()=>{const img=document.querySelector('#document-preview img');return img?.complete&&img.naturalWidth>0;});
  for(const [device,viewport] of [['desktop',{width:1500,height:1050}],['mobile',{width:390,height:844}]]){
   await page.setViewportSize(viewport);
   const metrics=await page.evaluate(()=>{
    const dialog=document.querySelector('#document-dialog'),preview=document.querySelector('#document-preview'),img=preview.querySelector('img');
    const bounds=img.getBoundingClientRect(),area=preview.getBoundingClientRect();
    return {ratio:bounds.width/bounds.height,naturalRatio:img.naturalWidth/img.naturalHeight,
     fits:bounds.width>0&&bounds.height>0&&bounds.left>=area.left&&bounds.top>=area.top&&bounds.right<=area.right+1&&bounds.bottom<=area.bottom+1,
     scrolls:[dialog,preview].some(element=>element.scrollHeight>element.clientHeight+1||element.scrollWidth>element.clientWidth+1)};
   });
   assert.ok(metrics.fits,`${name} must fit the ${device} preview`);
   assert.ok(Math.abs(metrics.ratio-metrics.naturalRatio)<0.01,'Image must preserve its aspect ratio');
   assert.equal(metrics.scrolls,false,'Image dialog must not require scrolling');
   await page.screenshot({path:`${out}/02d-image-${name}-${device}.png`,fullPage:false});
  }
  await page.locator('#document-close').click();
 }
 const imageText=await page.evaluate(async()=>{const response=await fetch('/api/documents?q=IMAGEPREVIEW742&scope=content');return response.json();});
 assert.equal(imageText.total,0,'Image fixtures must not be OCRed or content-indexed');
 await page.locator('#reset-filters').click();
 await page.waitForFunction(()=>document.querySelectorAll('.document-card').length>1);
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.screenshot({path:out+'/03-live-mobile-files.png',fullPage:true});
 await page.goto(origin+'/admin/access');await page.waitForURL(origin+'/');await page.locator('.document-card').first().waitFor();
 assert.equal(await page.locator('#admin-link').isHidden(),true);
 const adminContext=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1500,height:1050}});
 const admin=await adminContext.newPage();await admin.goto(origin+'/admin/access');
 await admin.locator('#login-view').waitFor({state:'visible'});
 await admin.locator('input[name=username]').fill(process.env.PREVIEW_ADMIN_USER);
 await admin.locator('input[name=password]').fill(process.env.PREVIEW_ADMIN_PASSWORD);
 await admin.locator('#login-form button').click();await admin.locator('[data-user-rule]').first().waitFor();
 assert.equal(new URL(admin.url()).pathname,'/admin/access');
 assert.equal(await admin.locator('nav a[href="/admin/access"]').count(),1);
 await admin.screenshot({path:out+'/04-live-admin-access.png',fullPage:true});
 await admin.locator('a[href="/admin/documents"]').click();
 await admin.locator('#document-worker-control').waitFor();
 await admin.waitForFunction(()=>!document.querySelector('#document-worker-control').disabled);
 await admin.screenshot({path:out+'/05-live-document-index.png',fullPage:true});
 await admin.locator('#document-worker-control').click();
 await admin.waitForFunction(()=>document.querySelector('#document-worker-control')?.textContent==='Fortsetzen' && document.querySelector('#document-worker-state')?.textContent==='Angehalten');
 await admin.screenshot({path:out+'/06-live-document-index-paused.png',fullPage:true});
 await admin.locator('#document-worker-control').click();
 await admin.waitForFunction(()=>document.querySelector('#document-worker-control')?.textContent==='Anhalten');
 await admin.setViewportSize({width:390,height:844});
 await admin.screenshot({path:out+'/07-live-document-index-mobile.png',fullPage:true});
 await admin.goto(origin+'/');await admin.locator('.document-card').first().waitFor();
 assert.equal(await admin.locator('#admin-link').isVisible(),true);
 assert.deepEqual(errors,[]);
 console.log('PASS: live user/admin login, OCR search/preview, original PDF download, shared/private JPEG/PNG previews, mobile layout, /admin boundary, index monitoring and pause/resume.');
 console.log('Screenshots: '+out);
}finally{await browser.close();}

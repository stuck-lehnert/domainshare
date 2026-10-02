// Run with an installed Playwright package. PLAYWRIGHT_MODULE can point to an external installation.
// SCREENSHOT_DIR optionally selects where the browser captures are written.
import fs from "node:fs";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import {createRequire} from "node:module";
import {fileURLToPath} from "node:url";
const require = createRequire(import.meta.url);
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const root = fileURLToPath(new URL("../app/web/", import.meta.url));
const out = process.env.SCREENSHOT_DIR || fs.mkdtempSync(path.join(os.tmpdir(), "adfs-ui-review-"));
fs.mkdirSync(out, {recursive: true});
const data={initialized:true,fetchedAt:new Date().toISOString(),users:[
 {sid:'alice',sam:'alice',name:'Alice Schneider',available:true},
 {sid:'bob',sam:'bob',name:'Robert Müller',available:true},
 {sid:'carol',sam:'carol',name:'Carol Fischer',available:true},
 ...Array.from({length:77},(_,i)=>({sid:'user-'+i,sam:'mitarbeiter.'+String(i+1).padStart(2,'0'),name:'Mitarbeiter '+(i+1),available:true}))
],folders:[
 {id:'invoices',name:'Rechnungen',active:true,permissions:[{kind:'user',principalId:'alice',level:2},{kind:'user',principalId:'bob',level:1},{kind:'user',principalId:'carol',level:0}]},
 {id:'projects',name:'Projektunterlagen',active:true,permissions:[{kind:'user',principalId:'carol',level:3}]},
 {id:'archive',name:'Abschluss 2024',active:false,permissions:[]}
]};
let nextId=0, failSave=false; const requests=[],errors=[];
(async()=>{
 const browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1500,height:1050}});
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('http://adfs.test/**',async route=>{
  const url=new URL(route.request().url());let body,type='application/json',status=200;
  if(url.pathname==='/api/session')body={user:'EXAMPLE\\admin',expiresAt:9999999999};
  else if(url.pathname==='/api/access'){
   if(route.request().method()==='POST'){
    const change=route.request().postDataJSON();requests.push(change);
    if(failSave){failSave=false;return route.fulfill({status:409,contentType:type,body:JSON.stringify({error:'Freigabenabgleich läuft; bitte erneut versuchen'})});}
    if(change.action==='set-permissions')data.folders.find(f=>f.id===change.id).permissions=change.permissions;
    if(change.action==='create-folder')data.folders.push({id:'folder-'+(++nextId),name:change.name,active:true,permissions:[]});
    if(change.action==='archive-folder'||change.action==='restore-folder')data.folders.find(f=>f.id===change.id).active=change.action==='restore-folder';
   }body=data;
  } else if(url.pathname==='/assets/app.js'){body=fs.readFileSync(root+'/app.js');type='text/javascript';}
  else if(url.pathname==='/assets/styles.css'){body=fs.readFileSync(root+'/styles.css');type='text/css';}
  else {body=fs.readFileSync(root+'/index.html');type='text/html';}
  await route.fulfill({status,contentType:type,body:Buffer.isBuffer(body)?body:JSON.stringify(body)});
 });
 const settled=()=>page.waitForFunction(()=>document.querySelector('#access-message')?.textContent==='Gespeichert. Die Änderungen sind wirksam.'&&!document.querySelector('#access-create').disabled);
 const shot=async name=>page.screenshot({path:out+'/'+name+'.png',fullPage:true});
 const checkSharedStyle=async()=>{
  const differences=await page.evaluate(()=>{
   const mismatches=[];
   const compare=(actual,reference,properties)=>{
    const a=getComputedStyle(document.querySelector(actual)),b=getComputedStyle(document.querySelector(reference));
    for(const property of properties)if(a[property]!==b[property])mismatches.push(`${actual}: ${property} ${a[property]} != ${b[property]}`);
   };
   const controls=['fontFamily','fontSize','color','backgroundColor','borderTopColor','borderTopWidth','borderTopStyle','borderRadius','boxShadow','padding'];
   compare('#access-create','#login-form button',controls);
   compare('#access-search','#login-form input[name=username]',controls);
   const listReference=document.createElement('button');
   listReference.id='shared-list-reference';listReference.className='select-row active';
   document.body.append(listReference);
   compare('.access-list-item.active','#shared-list-reference',['backgroundColor','fontWeight']);
   listReference.remove();
   if(document.querySelector('.access-level-options'))compare('.access-level-options button[aria-pressed="true"]','nav a.active',['backgroundColor','fontWeight']);
   if(document.querySelector('.access-dialog')){
    compare('.access-dialog input','#login-form input[name=username]',controls);
    compare('.access-dialog button[type=submit]','#login-form button',controls);
   }
   return mismatches;
  });
  assert.deepEqual(differences,[],'Access controls differ from the established admin styles');
 };
 await page.goto('http://adfs.test/access');await page.locator('[data-user-rule]').first().waitFor();
 assert.equal(await page.locator('[data-tab=groups], [data-group-rule]').count(),0);
 assert.doesNotMatch(await page.locator('#content').innerText(),/Gruppe/);
 assert.equal(await page.locator('#access-users .access-matrix-row').count(),80);
 await checkSharedStyle();
 await shot('01-desktop-benutzerrechte');
 assert.equal(await page.locator('#access-save').isDisabled(),true);
 await page.locator('#access-user-search').fill('alice');
 await page.locator('[data-user-rule=alice][data-level="3"]').click();
 assert.equal(await page.locator('#access-save').isEnabled(),true);
 await page.locator('#access-user-search').fill('bob');
 await page.locator('[data-user-rule=bob][data-level="2"]').click();
 await page.locator('#access-user-search').fill('');
 await page.selectOption('#access-user-filter','granted');
 assert.equal(await page.locator('#access-users .access-matrix-row').count(),2);
 assert.equal(await page.locator('[data-user-rule=alice][data-level="3"]').getAttribute('aria-pressed'),'true');
 assert.match(await page.locator('#access-user-count').innerText(),/ungespeicherten/);
 await shot('02-desktop-mit-zugriff');
 let dialogs=0;
 page.on('dialog',async d=>{dialogs++;await d.dismiss();});
 await page.locator('[data-select=projects]').click();
 assert.match(await page.locator('.access-detail-head h2').innerText(),/Rechnungen/);
 assert.equal(dialogs,1);
 await page.selectOption('#folder-status','archived');
 assert.equal(await page.locator('#folder-status').inputValue(),'active');
 assert.equal(dialogs,2);
 await page.locator('a[data-route="storage-data"]').click();
 assert.equal(new URL(page.url()).pathname,'/access');
 assert.equal(dialogs,3);
 failSave=true;await page.locator('#access-save').click();
 await page.locator('.access-message.failure').waitFor();
 assert.equal(await page.locator('[data-user-rule=alice][data-level="3"]').getAttribute('aria-pressed'),'true');
 assert.equal(await page.locator('#access-save').isEnabled(),true);
 await shot('03-desktop-fehler-erhaelt-entwurf');
 await page.locator('#access-save').click();await settled();
 assert.match(await page.locator('.access-detail-head h2').innerText(),/Rechnungen/);
 assert.equal(await page.locator('#access-user-filter').inputValue(),'granted');
 assert.equal(requests.at(-1).permissions.find(r=>r.principalId==='alice').level,3);
 assert.ok(requests.at(-1).permissions.every(r=>r.kind==='user'));
 await page.locator('[data-user-rule=bob][data-level="0"]').click();
 assert.equal(await page.locator('#access-users .access-matrix-row').count(),1);
 await page.selectOption('#access-user-filter','hidden');
 assert.equal(await page.locator('[data-user-rule=bob][data-level="0"]').getAttribute('aria-pressed'),'true');
 await page.locator('#access-discard').click();
 await page.selectOption('#access-user-filter','granted');
 assert.equal(await page.locator('[data-user-rule=bob][data-level="2"]').getAttribute('aria-pressed'),'true');
 assert.equal(await page.locator('#access-save').isDisabled(),true);
 await page.locator('[data-select=projects]').click();
 await page.locator('#access-user-search').fill('alice');
 assert.equal(await page.locator('[data-user-rule=alice][data-level="0"]').getAttribute('aria-pressed'),'true');
 await page.locator('[data-user-rule=alice][data-level="1"]').click();
 await page.locator('#access-save').click();await settled();
 await page.locator('[data-select=invoices]').click();
 assert.equal(await page.locator('[data-user-rule=alice][data-level="3"]').getAttribute('aria-pressed'),'true');
 await page.locator('#access-create').click();
 await page.locator('.access-dialog input').fill('Neue Ablage');
 await checkSharedStyle();await shot('04-desktop-ordner-anlegen');
 await page.locator('.access-dialog button[type=submit]').click();await settled();
 assert.match(await page.locator('.access-detail-head h2').innerText(),/Neue Ablage/);
 assert.equal(await page.locator('#access-users button[aria-pressed=true][data-level="0"]').count(),80);
 await page.locator('#access-archive').click();
 await page.locator('.access-dialog button[type=submit]').click();await settled();
 assert.equal(await page.locator('#folder-status').inputValue(),'archived');
 assert.equal(await page.locator('[data-user-rule]').first().isDisabled(),true);
 await page.locator('#access-archive').click();
 await page.locator('.access-dialog button[type=submit]').click();await settled();
 assert.equal(await page.locator('#folder-status').inputValue(),'active');
 await page.locator('[data-select=invoices]').click();
 await page.selectOption('#access-user-filter','granted');
 for(const width of [1200,900,390]){
  await page.setViewportSize({width,height:width===390?844:1000});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Horizontal overflow at '+width);
  assert.equal(await page.evaluate(()=>{
   const section=document.querySelector('#access-detail .access-section');
   const footer=document.querySelector('.access-savebar');
   return footer.getBoundingClientRect().top >= section.getBoundingClientRect().bottom-1;
  }),true,'Save controls cover form content at '+width);
  await checkSharedStyle();
  await shot('05-benutzerrechte-'+width);
 }
 await page.selectOption('#access-user-filter','all');
 await page.locator('#access-user-search').fill('mitarbeiter.77');
 assert.equal(await page.locator('#access-users .access-matrix-row').count(),1);
 await page.locator('[data-user-rule=user-76][data-level="1"]').click();
 await page.locator('#access-user-search').fill('');
 await page.selectOption('#access-user-filter','granted');
 assert.equal(await page.locator('[data-user-rule=user-76][data-level="1"]').getAttribute('aria-pressed'),'true');
 await shot('06-mobile-benutzersuche');
 await page.locator('#access-discard').click();
 // Cached users who left AD stay visible only while they have an assignment.
 data.users.push({sid:'departed',sam:'ehemalig',name:'Ehemaliger Benutzer',available:false},
                 {sid:'unassigned',sam:'unzugeordnet',name:'Nicht zugeordnet',available:false});
 data.folders.find(f=>f.id==='invoices').permissions.push({kind:'user',principalId:'departed',level:1});
 await page.setViewportSize({width:1500,height:1050});
 await page.goto('http://adfs.test/access');
 await page.locator('[data-user-rule=departed]').first().waitFor();
 assert.equal(await page.locator('[data-user-rule=unassigned]').count(),0);
 await page.locator('#access-user-search').fill('ehemalig');
 assert.match(await page.locator('#access-users').innerText(),/Nicht mehr im AD/);
 await page.locator('[data-user-rule=departed][data-level="0"]').click();
 await page.locator('#access-save').click();await settled();
 assert.equal(await page.locator('[data-user-rule=departed]').count(),0);
 // An installation with only archived folders opens the matching list.
 data.folders.forEach(f=>f.active=false);
 await page.goto('http://adfs.test/access');
 await page.locator('#access-archive').waitFor();
 assert.equal(await page.locator('#folder-status').inputValue(),'archived');
 assert.equal(await page.locator('[data-select].active').count(),1);
 assert.equal(await page.locator('[data-user-rule]').first().isDisabled(),true);
 assert.equal(await page.locator('#access-save').isDisabled(),true);
 data.folders.length=0;
 await page.setViewportSize({width:1500,height:1050});
 await page.goto('http://adfs.test/access');
 await page.locator('#access-create').waitFor();
 assert.match(await page.locator('#access-detail').innerText(),/Ersten Ordner anlegen/);
 await shot('07-desktop-leere-installation');
 assert.deepEqual(errors,[]);
 console.log('PASS: individual permissions, no groups, user search/filter persistence, unsaved-change protection, failure/retry, independent folders, create/archive/restore, desktop/mobile layout, shared admin styling.');
 console.log('Screenshots: '+out);
 await browser.close();
})().catch(error=>{console.error(error);process.exit(1)});

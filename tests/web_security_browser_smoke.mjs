// Real Chromium cookies and real HTTPS handlers, including a same-site attacker.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createRequire} from 'node:module';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';

const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root=fileURLToPath(new URL('../',import.meta.url));
const fixture=spawn(process.env.PYTHON || 'python3',['-m','tests.web_security_browser_fixture'],{cwd:root,stdio:['ignore','pipe','pipe']});
let browser;
let logs='';
fixture.stderr.on('data',chunk=>{logs+=chunk;});
try {
 const port=await new Promise((resolve,reject)=>{
  const lines=createInterface({input:fixture.stdout});
  const timeout=setTimeout(()=>reject(new Error('HTTPS fixture did not start: '+logs)),10000);
  lines.on('line',line=>{if(line.startsWith('{')){clearTimeout(timeout);resolve(JSON.parse(line).port);}});
  fixture.once('exit',code=>{clearTimeout(timeout);reject(new Error('Fixture exited: '+code+' '+logs));});
 });
 const target=`https://files.example.test:${port}`;
 const evil=`https://evil.example.test:${port}`;
 browser=await chromium.launch({headless:true,
  ...(process.env.CHROMIUM_EXECUTABLE_PATH?{executablePath:process.env.CHROMIUM_EXECUTABLE_PATH}:{}),
  args:['--no-proxy-server','--host-resolver-rules=MAP files.example.test 127.0.0.1, MAP evil.example.test 127.0.0.1']});
 const context=await browser.newContext({ignoreHTTPSErrors:true});
 const page=await context.newPage();
 await page.goto(target+'/healthz');
 const login=await page.evaluate(async()=>{
  const response=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':'login'},
   body:JSON.stringify({username:'admin',password:'fixture-password'})});
  return {status:response.status,...await response.json()};
 });
 assert.equal(login.status,200);
 assert.ok(login.csrfToken);
 const cookie=(await context.cookies(target)).find(item=>item.name==='domainshare_session');
 assert.equal(cookie.httpOnly,true);assert.equal(cookie.secure,true);assert.equal(cookie.sameSite,'Strict');
 const control=async action=>page.evaluate(async({action,csrf})=>{
  const response=await fetch('/admin/api/documents/control',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({action})});
  return {status:response.status,...await response.json()};
 },{action,csrf:login.csrfToken});
 assert.equal((await control('pause')).paused,true);
 assert.equal((await control('resume')).paused,false);
 const attacker=await context.newPage();
 await attacker.goto(evil+'/test-attacker');
 await attacker.evaluate(async target=>{
  await fetch(target+'/admin/api/documents/control',{method:'POST',mode:'no-cors',credentials:'include',
   headers:{'Content-Type':'text/plain'},body:JSON.stringify({action:'pause'})}).catch(()=>undefined);
  await fetch(target+'/api/logout',{method:'POST',mode:'no-cors',credentials:'include',
   headers:{'Content-Type':'text/plain'},body:'{}'}).catch(()=>undefined);
 },target);
 // Prove that SameSite=Strict actually sent the admin cookie in this attack.
 const observations=await page.evaluate(async()=>await (await fetch('/test-observations')).json());
 assert.equal(observations.length,2);
 assert.ok(observations.every(item=>item.cookie && item.type==='text/plain'));
 assert.equal(await page.evaluate(async()=> (await (await fetch('/admin/api/documents/status')).json()).paused),false);
 assert.equal(await page.evaluate(async()=> (await fetch('/api/session')).status),200);
 assert.equal(await page.evaluate(async()=> (await fetch('/admin/api/documents/control',{method:'POST',
  headers:{'Content-Type':'application/json'},body:'{"action":"pause"}'})).status),403);
 assert.equal(await page.evaluate(async csrf=> (await fetch('/api/logout',{method:'POST',
  headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:'{}'})).status,login.csrfToken),200);
 assert.equal(await page.evaluate(async()=> (await fetch('/api/session')).status),401);
 assert.equal(await page.evaluate(async token=> (await fetch('/admin/api/documents/status',{
  headers:{Authorization:'Bearer '+token}})).status,login.token),401);
 console.log('PASS: real HTTPS login, session-bound CSRF, same-site sibling attack with admin cookie, pause/resume, logout and bearer replay.');
} finally {
 if(browser) await browser.close();
 fixture.kill('SIGTERM');
}

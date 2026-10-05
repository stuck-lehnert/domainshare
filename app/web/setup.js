(() => {
  let token = '', snapshot = null, polling = false;
  const content = document.querySelector('#setup-content'), errorBox = document.querySelector('#setup-error'), status = document.querySelector('#setup-status');
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
  const showError = error => { errorBox.textContent = error.message; errorBox.hidden = false; };
  async function api(path, options = {}) {
    const response = await fetch('/api/bootstrap/' + path, {...options, headers:{'Content-Type':'application/json', 'X-Setup-Token':token}, credentials:'same-origin'});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Einrichtung konnte nicht geladen werden');
    return result;
  }
  async function refresh() {
    snapshot = await api('settings');
    status.textContent = snapshot.services?.message || '';
    if (snapshot.phase === 'groups' && !content.querySelector('#setup-groups')) await renderGroups();
  }
  async function renderGroups() {
    const {groups} = await api('groups');
    const fields = snapshot.sections.find(item => item.id === 'groups').fields.map(field => ({...field, value:field.value || groups.find(group => group.sid.endsWith(field.key === 'DOMAIN_ADMINS_SID' ? '-512' : '-513'))?.sid || groups[0]?.sid || ''}));
    content.innerHTML = `<section class="panel"><h2>Gruppen auswählen</h2><p>Diese Gruppen steuern SMB-Anmeldung, Verwaltung und FSLogix. Dateizugriffe werden später individuell pro Benutzer zugeordnet.</p><form id="setup-groups" class="stack">${fields.map(field => ConfigurationUI.fieldMarkup(field, groups, true)).join('')}<label>Administratorkonto für die erste Anmeldung<input name="username" value="${esc(snapshot.sections.find(item => item.id === 'domain').fields.find(field => field.key === 'JOIN_USER').value)}" autocomplete="username" required></label><label>Passwort<input name="password" type="password" autocomplete="current-password" required></label><button type="submit">Einrichtung abschließen</button></form></section>`;
    content.querySelector('form').onsubmit = async event => {
      event.preventDefault(); const form = event.currentTarget, button = form.querySelector('button'); button.disabled = true; errorBox.hidden = true;
      try {
        await refresh();
        await api('finish', {method:'POST', body:JSON.stringify({revision:snapshot.revision, values:ConfigurationUI.readValues(form, fields), username:form.elements.username.value, password:form.elements.password.value})});
        form.elements.password.value = ''; token = ''; status.textContent = 'Einrichtung abgeschlossen. Dienste werden gestartet.';
        content.innerHTML = '<section class="panel"><a href="/">Zur Anmeldung</a></section>';
        polling = false;
      } catch (error) { showError(error); button.disabled = false; }
    };
  }
  function renderDomain() {
    const essentials = new Set(['REALM','WORKGROUP','DOMAIN','JOIN_USER','JOIN_PASSWORD','NETBIOS_NAME','SAMBA_HOSTNAME','WEB_HOSTNAME','WEB_TLS_MODE','AD_DNS_IP','AD_DNS_NAME']);
    const fields = snapshot.sections.filter(section => ['domain','network','tls'].includes(section.id)).flatMap(section => section.fields);
    const hostname = fields.find(field => field.key === 'WEB_HOSTNAME');
    if (hostname.value === 'localhost') hostname.value = location.hostname;
    content.innerHTML = `<section class="panel"><h2>Domäne und Server</h2><form id="setup-domain" class="stack">${fields.filter(field => essentials.has(field.key)).map(field => ConfigurationUI.fieldMarkup(field, [], true)).join('')}<details><summary>LDAP- und Zertifikatseinstellungen</summary><div class="stack settings-advanced">${fields.filter(field => !essentials.has(field.key)).map(field => ConfigurationUI.fieldMarkup(field, [], true)).join('')}</div></details><button type="submit">Domäne beitreten</button></form></section><details class="panel"><summary>Bestehende Installation übernehmen</summary><p>Die bisherige .env-Datei einmalig importieren. Dateien, bestehender Domänenbeitritt, Rechte und Sicherungen bleiben erhalten.</p><form id="setup-import" class="stack"><label>Bisherige Konfigurationsdatei<input type="file" name="legacy" required></label><button type="submit">Konfiguration importieren</button></form></details>`;
    const form = content.querySelector('#setup-domain'); ConfigurationUI.tlsVisibility(form);
    form.onsubmit = async event => {
      event.preventDefault(); errorBox.hidden = true; const button = form.querySelector('[type=submit]'); button.disabled = true;
      try {
        await refresh();
        snapshot = await api('domain', {method:'POST', body:JSON.stringify({revision:snapshot.revision, values:ConfigurationUI.readValues(form, fields)})});
        form.elements.JOIN_PASSWORD.value = ''; status.textContent = 'Domänenbeitritt läuft. Bei einem Fehler können Sie die Angaben korrigieren und erneut versuchen.';
        polling = true;
      } catch (error) { showError(error); }
      finally { button.disabled = false; }
    };
    content.querySelector('#setup-import').onsubmit = async event => {
      event.preventDefault(); errorBox.hidden = true;
      try { const text = await event.currentTarget.elements.legacy.files[0].text(); await api('import', {method:'POST', body:JSON.stringify({text})}); token = ''; location.assign('/'); }
      catch (error) { showError(error); }
    };
  }
  document.querySelector('#setup-unlock form').onsubmit = async event => {
    event.preventDefault(); const form = event.currentTarget; errorBox.hidden = true; token = form.elements.code.value;
    try { await refresh(); form.elements.code.value = ''; document.querySelector('#setup-unlock').hidden = true; content.hidden = false; if (snapshot.phase !== 'groups') renderDomain(); polling = snapshot.phase !== 'unconfigured'; }
    catch (error) { token = ''; showError(error); }
  };
  setInterval(async () => { if (polling && token) { try { await refresh(); } catch (error) { showError(error); } } }, 3000);
  api('status').then(result => { if (result.configured) location.replace('/'); }).catch(showError);
})();

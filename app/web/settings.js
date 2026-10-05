/* Configuration controls share the application's existing form styles. */
(() => {
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
  const labels = {'self-signed':'Selbstsigniert', acme:'ACME', ca:'Smallstep CA', files:'Zertifikat und Schlüssel hochladen'};
  function fieldMarkup(field, groups = [], bootstrap = false) {
    const {key, kind, label, value, configured} = field;
    const id = 'setting-' + key;
    let input;
    if (kind === 'bool') return `<label class="settings-check"><input id="${id}" name="${key}" type="checkbox" ${value ? 'checked' : ''}>${esc(label)}</label>`;
    if (kind === 'group') {
      const options = [...groups];
      if (value && !options.some(group => group.sid === value)) options.push({sid:value, name:value});
      input = `<select id="${id}" name="${key}" required>${options.map(group => `<option value="${esc(group.sid)}" ${group.sid === value ? 'selected' : ''}>${esc(group.name)}</option>`).join('')}</select>`;
    } else if (kind === 'choice') input = `<select id="${id}" name="${key}">${field.choices.map(option => `<option value="${esc(option)}" ${value === option ? 'selected' : ''}>${esc(labels[option] || option)}</option>`).join('')}</select>`;
    else if (kind.includes('pem')) input = `<textarea id="${id}" name="${key}" rows="5" spellcheck="false" autocomplete="off" placeholder="${configured ? 'Gespeichert; leer lassen zum Beibehalten' : '-----BEGIN …-----'}">${esc(value)}</textarea>`;
    else input = `<input id="${id}" name="${key}" type="${kind === 'int' ? 'number' : ['secret', 'secreturl'].includes(kind) ? 'password' : 'text'}" value="${esc(value)}" ${kind === 'int' ? `min="${field.minimum}" max="${field.maximum}" step="1"` : ''} ${!bootstrap && ['REALM','WORKGROUP'].includes(key) ? 'readonly' : ''} ${field.required ? 'required' : ''} autocomplete="${kind === 'secret' ? 'new-password' : 'off'}" placeholder="${configured ? 'Gespeichert; leer lassen zum Beibehalten' : key === 'BACKUP_DESTINATION' ? 'sftp://benutzer:passwort@server/pfad' : ''}">`;
    const hint = field.summary ? `<small class="muted">Aktuelles Ziel: ${esc(field.summary)}</small>` : key === 'BACKUP_DESTINATION' ? '<small class="muted">Unterstützt rsync, SFTP, SMB und WebDAV. Zugangsdaten in der Adresse bitte URL-kodieren.</small>' : '';
    input = input.replace(/^<(input|select|textarea)\b/, `<$1 aria-label="${esc(label)}"`);
    const clear = configured && ['secret','secretpem'].includes(kind) ? `<label class="settings-check"><input name="clear-${key}" type="checkbox">Gespeicherten Wert löschen</label>` : '';
    return `<div data-setting="${key}"><label>${esc(label)}${input}${hint}</label>${clear}</div>`;
  }
  function readValues(form, fields) {
    const values = {};
    for (const field of fields) {
      const input = form.elements.namedItem(field.key);
      if (!input || input.disabled) continue;
      if (form.elements.namedItem('clear-' + field.key)?.checked) { values[field.key] = ''; continue; }
      if (['secret','secreturl','secretpem'].includes(field.kind) && !input.value) continue;
      values[field.key] = field.kind === 'bool' ? input.checked : field.kind === 'int' ? Number(input.value) : input.value;
    }
    return values;
  }
  function tlsVisibility(form) {
    const mode = form.elements.namedItem('WEB_TLS_MODE');
    if (!mode) return;
    const update = () => form.querySelectorAll('[data-setting]').forEach(label => {
      const key = label.dataset.setting;
      const active = key.startsWith('ACME_') ? mode.value === 'acme' : key.startsWith('TLS_CA_') ? mode.value === 'ca' : ['WEB_TLS_CERT_PEM','WEB_TLS_KEY_PEM'].includes(key) ? mode.value === 'files' : true;
      label.hidden = !active;
      label.querySelectorAll('input,textarea,select').forEach(input => { input.disabled = !active; });
    });
    mode.addEventListener('change', update); update();
  }
  async function recoveryDialog(api, configuration, refreshed) {
    const result = await api('/api/settings/backup-key/generate', {method:'POST', body:'{}'});
    const oldKey = configuration.encryption.keyId || configuration.encryption.legacy;
    const dialog = document.createElement('dialog');
    dialog.className = 'access-dialog settings-key-dialog';
    dialog.setAttribute('aria-labelledby', 'recovery-title');
    dialog.innerHTML = `<h2 id="recovery-title">Wiederherstellungsphrase notieren</h2><p>Diese Phrase wird nur jetzt angezeigt. Sie entschlüsselt die vollständige Sicherung, einschließlich Zugangsdaten und Serverzustand. Bewahren Sie sie getrennt vom Server auf.</p><ol class="recovery-words">${result.phrase.split(' ').map(word => `<li>${esc(word)}</li>`).join('')}</ol><p class="muted">Schlüsselkennung: ${esc(result.keyId)}</p><form class="stack"><label class="settings-check"><input name="written" type="checkbox" required>Ich habe alle 24 Wörter in der richtigen Reihenfolge sicher notiert.</label>${oldKey ? '<p class="error">Alte Sicherungen bleiben erhalten und benötigen weiterhin ihre alte Phrase bzw. ihr altes Passwort. Geht diese Information verloren, sind die darin gespeicherten Daten nicht wiederherstellbar.</p><label class="settings-check"><input name="old" type="checkbox" required>Ich bewahre auch die bisherige Phrase bzw. das bisherige Passwort auf.</label>' : ''}<p class="error" role="alert" hidden></p><div class="access-dialog-actions"><button type="button" data-close>Abbrechen</button><button type="submit">Schlüssel aktivieren</button></div></form>`;
    // The phrase stays in this dialog only; it is never stored in browser storage.
    result.phrase = '';
    document.body.append(dialog);
    dialog.addEventListener('close', () => { dialog.replaceChildren(); dialog.remove(); }, {once:true});
    dialog.querySelector('[data-close]').onclick = () => dialog.close();
    dialog.querySelector('form').onsubmit = async event => {
      event.preventDefault(); const form = event.currentTarget, button = form.querySelector('[type=submit]'); button.disabled = true;
      try {
        await api('/api/settings/backup-key/activate', {method:'POST', body:JSON.stringify({nonce:result.nonce, writtenDown:form.elements.written.checked, acknowledgeOldBackups:oldKey ? form.elements.old.checked : false})});
        dialog.close(); await refreshed();
      } catch (error) { const target = form.querySelector('[role=alert]'); target.textContent = error.message; target.hidden = false; button.disabled = false; }
    };
    dialog.showModal();
  }
  async function mount(host, {api, notice, section = '', initialSection = '', onDirty = () => {}}) {
    const data = await api('/api/settings' + (section ? '?section=' + section : ''));
    if (!host.isConnected) return;
    let selected = section || initialSection || data.sections[0].id;
    const render = async () => {
      const current = data.sections.find(item => item.id === selected);
      let groups = [];
      if (selected === 'groups') groups = (await api('/api/settings/groups')).groups;
      if (!host.isConnected) return;
      host.innerHTML = `${!section ? `<div class="settings-tabs" role="group" aria-label="Einstellungen">${data.sections.map(item => `<button type="button" data-section="${item.id}" aria-pressed="${item.id === selected}">${esc(item.label)}</button>`).join('')}</div>` : ''}<section class="panel"><h2>${esc(current.label)}</h2><form class="stack settings-form">${current.fields.map(field => fieldMarkup(field, groups)).join('')}${selected === 'backup' ? `<div class="settings-encryption"><strong>Verschlüsselungsschlüssel</strong><p>${data.encryption.keyId ? 'Aktiver Schlüssel: ' + esc(data.encryption.keyId) : data.encryption.legacy ? 'Bisheriges Archivpasswort übernommen. Eine neue Phrase aktiviert die Verschlüsselung aller Sicherungsdaten.' : 'Noch kein Wiederherstellungsschlüssel eingerichtet.'}</p><button type="button" data-generate>${data.encryption.keyId || data.encryption.legacy ? 'Neue Wiederherstellungsphrase erzeugen' : 'Wiederherstellungsphrase erzeugen'}</button></div><label class="settings-check"><input type="checkbox" name="clearDestination">Sicherungsziel entfernen und Sicherungen deaktivieren</label>` : ''}<p class="error" role="alert" hidden></p><div class="toolbar"><button type="submit">Änderungen speichern</button><span class="muted" role="status"></span></div></form></section>`;
      const form = host.querySelector('form'); tlsVisibility(form);
      form.addEventListener('input', () => onDirty(true));
      host.querySelectorAll('[data-section]').forEach(button => { button.onclick = async () => {
        if (form.dataset.dirty === 'true' && !confirm('Ungespeicherte Änderungen verwerfen?')) return;
        onDirty(false); selected = button.dataset.section; await render();
      }; });
      form.addEventListener('input', () => { form.dataset.dirty = 'true'; });
      if (selected === 'backup') host.querySelector('[data-generate]').onclick = async () => {
        try {
          const draft = form.dataset.dirty === 'true' ? readValues(form, current.fields) : null;
          const clearDestination = form.elements.clearDestination?.checked;
          await recoveryDialog(api, data, async () => {
            onDirty(false);
            await mount(host, {api, notice, section, initialSection:selected, onDirty});
            if (draft) {
              draft.BACKUP_ENCRYPTION_ENABLED = true;
              const next = host.querySelector('form');
              for (const [key, value] of Object.entries(draft)) {
                const input = next.elements.namedItem(key);
                if (input) { if (input.type === 'checkbox') input.checked = value; else input.value = value; }
              }
              if (next.elements.clearDestination) next.elements.clearDestination.checked = clearDestination;
              next.dataset.dirty = 'true'; onDirty(true);
            }
            notice('Verschlüsselungsschlüssel aktiviert.');
          });
        } catch (error) { notice(error.message); }
      };
      form.onsubmit = async event => {
        event.preventDefault(); const button = form.querySelector('[type=submit]'); button.disabled = true;
        const errorBox = form.querySelector('[role=alert]'); errorBox.hidden = true;
        try {
          const values = readValues(form, current.fields);
          if (form.elements.clearDestination?.checked) { values.BACKUP_DESTINATION = ''; values.BACKUP_AUTO_ENABLED = false; }
          const saved = await api('/api/settings', {method:'POST', body:JSON.stringify({revision:data.revision, values})});
          onDirty(false); form.dataset.dirty = 'false';
          Object.assign(data, saved);
          form.querySelector('[role=status]').textContent = saved.restartRequired ? 'Gespeichert. Dienste starten neu; anschließend die Seite neu laden.' : 'Gespeichert.';
          form.querySelectorAll('input[type=password],textarea[name=WEB_TLS_KEY_PEM]').forEach(input => { input.value = ''; });
        } catch (error) { errorBox.textContent = error.message; errorBox.hidden = false; }
        finally { button.disabled = false; }
      };
    };
    await render();
  }
  window.ConfigurationUI = {mount, fieldMarkup, readValues, tlsVisibility};
})();

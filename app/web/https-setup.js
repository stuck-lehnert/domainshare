(() => {
  const form = document.querySelector('#https-form'), status = document.querySelector('#https-status'), errorBox = document.querySelector('#https-error'), next = document.querySelector('#https-next');
  form.elements.hostname.value = location.hostname;
  form.onsubmit = async event => {
    event.preventDefault(); errorBox.hidden = true; const button = form.querySelector('button'); button.disabled = true;
    try {
      const root = form.elements.root.files[0];
      const response = await fetch('/api/https/configure', {method:'POST', headers:{'Content-Type':'application/json', 'X-HTTPS-Setup-Code':form.elements.code.value}, body:JSON.stringify({WEB_HOSTNAME:form.elements.hostname.value, ACME_CA_SERVER:form.elements.acme.value, ACME_CA_CERTIFICATES_PEM:root ? await root.text() : ''})});
      const data = await response.json(); if (!response.ok) throw new Error(data.error);
      form.elements.code.value = ''; status.textContent = 'ACME-Zertifikat wird angefordert …';
    } catch (error) { errorBox.textContent = error.message; errorBox.hidden = false; }
    finally { button.disabled = false; }
  };
  setInterval(async () => {
    try {
      const data = await (await fetch('/api/https/status')).json(); status.textContent = data.message || '';
      next.hidden = !(data.state === 'ready' || data.configured);
      if (!next.hidden) { next.href = data.httpsUrl; }
    } catch { status.textContent = 'Dienst wird neu gestartet …'; }
  }, 2000);
})();

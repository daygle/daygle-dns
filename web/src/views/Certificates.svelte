<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { formatDate } from '../datetime.svelte.js';

  // Opens Settings on a tab (null for viewers, who cannot).
  let { onOpenSettings = null } = $props();

  let certs = $state([]);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state(null);
  let notice = $state(null);
  let warning = $state(null);

  // Add/replace dialog (null when closed). `replacing` is the name of the
  // certificate being replaced, which fixes the name and the upload mode.
  let form = $state(null);
  let formError = $state(null);

  // ACME (Let's Encrypt) settings, and its dialog (null when closed).
  let acme = $state(null);
  let acmeForm = $state(null);
  let acmeError = $state(null);

  const me = getStoredUser();
  const isViewer = me?.role === 'viewer';
  const DAY = 86400000;
  const SOON_DAYS = 30;

  async function load() {
    error = null;
    try {
      certs = await api.certificates();
      if (!isViewer && !acme) acme = await api.acmeSettings();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    load();
  });

  // Follow certificates being requested from the CA.
  const requesting = $derived(certs.some((c) => c.acme?.status === 'pending'));
  $effect(() => {
    if (!requesting) return;
    const id = setInterval(load, 2000);
    return () => clearInterval(id);
  });

  // Which CA the settings point at, for the dialog's picker.
  function caChoice(settings) {
    const dir = (settings.directory || '').trim();
    if (!dir || dir === acme?.lets_encrypt) return 'letsencrypt';
    if (dir === acme?.lets_encrypt_staging) return 'staging';
    return 'custom';
  }

  function openAcme() {
    acmeError = null;
    const s = acme?.settings || {};
    acmeForm = { ...s, ca: caChoice(s), renew_days: s.renew_days || 30 };
  }

  function acmePayload(f) {
    return {
      email: (f.email || '').trim(),
      directory: f.ca === 'letsencrypt' ? '' : f.ca === 'staging' ? acme.lets_encrypt_staging : (f.directory || '').trim(),
      agree_terms: !!f.agree_terms,
      ca_certificate: f.ca === 'custom' ? (f.ca_certificate || '') : '',
      renew_days: Number(f.renew_days) || 30,
    };
  }

  async function saveAcme(e) {
    e.preventDefault();
    acmeError = null;
    busy = true;
    try {
      acme = await api.saveAcmeSettings(acmePayload(acmeForm));
      acmeForm = null;
      notice = 'Let\'s Encrypt settings saved.';
    } catch (err) {
      acmeError = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  async function renew(cert) {
    busy = true;
    notice = warning = error = null;
    try {
      await api.renewCertificate(cert.name);
      notice = `Renewing '${cert.name}'...`;
      await load();
    } catch (err) {
      error = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  function caName() {
    const dir = acme?.directory_url || '';
    if (dir === acme?.lets_encrypt) return 'Let\'s Encrypt';
    if (dir === acme?.lets_encrypt_staging) return 'Let\'s Encrypt (Staging)';
    return 'the ACME CA';
  }

  function openAdd() {
    notice = warning = null;
    formError = null;
    form = {
      replacing: null, mode: 'self', name: '', serverName: '', certPem: '', keyPem: '',
      domains: '', challenge: 'http', email: acme?.settings?.email || '', agree: !!acme?.settings?.agree_terms,
    };
  }

  function openReplace(cert) {
    notice = warning = null;
    formError = null;
    form = { replacing: cert.name, mode: 'upload', name: cert.name, serverName: '', certPem: '', keyPem: '' };
  }

  function closeForm() {
    if (!busy) form = null;
  }

  function readFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ''));
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }

  async function pickFile(input, field) {
    const file = input.files?.[0];
    if (!file) return;
    try {
      const text = (await readFile(file)).trim() + '\n';
      if (field === 'cert') form.certPem = text;
      else form.keyPem = text;
    } catch (e) {
      formError = `Could not read ${file.name}: ${e}`;
    }
  }

  async function saveCert(e) {
    e.preventDefault();
    formError = null;
    const name = form.name.trim();
    if (!name) {
      formError = 'Give the certificate a name.';
      return;
    }
    if (!form.replacing && certs.some((c) => c.name === name)) {
      formError = `There is already a certificate named '${name}'. Use Replace on it to upload a renewal.`;
      return;
    }
    if (form.mode === 'upload' && (!form.certPem.trim() || !form.keyPem.trim())) {
      formError = 'Both the certificate and its private key are needed.';
      return;
    }
    if (form.mode === 'self' && !form.serverName.trim()) {
      formError = 'Enter the name clients will use to reach this server.';
      return;
    }
    if (form.mode === 'acme') {
      await requestAcme(name);
      return;
    }
    busy = true;
    try {
      const payload = form.mode === 'self'
        ? { name, server_name: form.serverName.trim() }
        : { name, cert_pem: form.certPem.trim() + '\n', key_pem: form.keyPem.trim() + '\n' };
      const saved = await api.createCertificate(payload);
      const used = saved?.in_use?.length ? ` The ${listJoin(saved.in_use)} listener${saved.in_use.length === 1 ? ' uses' : 's use'} it now.` : '';
      notice = form.replacing
        ? `Certificate '${name}' replaced.${used}`
        : form.mode === 'self'
          ? `Self-signed certificate '${name}' created.`
          : `Certificate '${name}' uploaded.`;
      const st = status(saved || {});
      if (st.kind === 'expired' || st.kind === 'future') warning = `Note: ${st.text.toLowerCase()} - clients will reject it.`;
      form = null;
      await load();
    } catch (err) {
      formError = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  async function requestAcme(name) {
    const domains = form.domains.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean);
    if (!domains.length) {
      formError = 'Enter the domain names the certificate is for.';
      return;
    }
    if (!form.agree) {
      formError = `Accept the terms of service of ${caName()} to continue.`;
      return;
    }
    busy = true;
    try {
      if (!acme.settings.agree_terms || (form.email.trim() && form.email.trim() !== acme.settings.email)) {
        acme = await api.saveAcmeSettings({ ...acme.settings, email: form.email.trim(), agree_terms: true });
      }
      await api.requestAcmeCertificate({ name, domains, challenge: form.challenge });
      notice = `Requesting '${name}' from ${caName()}. This usually takes under a minute.`;
      form = null;
      await load();
    } catch (err) {
      formError = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  async function remove(cert) {
    if (!confirm(`Delete certificate '${cert.name}'?`)) return;
    busy = true;
    notice = warning = error = null;
    try {
      await api.deleteCertificate(cert.name);
      notice = `Certificate '${cert.name}' deleted.`;
      await load();
    } catch (err) {
      error = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  // Validity state for the Expires column.
  function status(cert) {
    if (!cert.not_after) return { kind: 'unknown', text: 'Unknown' };
    const now = Date.now();
    const end = Date.parse(cert.not_after);
    const start = Date.parse(cert.not_before);
    if (start > now) return { kind: 'future', text: `Not Valid Until ${formatDate(start)}` };
    if (end <= now) return { kind: 'expired', text: 'Expired' };
    const days = Math.floor((end - now) / DAY);
    if (days > 365 * 100) return { kind: 'ok', text: 'Does Not Expire' };
    if (days < SOON_DAYS) return { kind: 'soon', text: days === 0 ? 'Expires Today' : `Expires in ${days} Day${days === 1 ? '' : 's'}` };
    return { kind: 'ok', text: 'Valid' };
  }

  function covers(cert) {
    const names = (cert.names || []).filter(Boolean);
    if (names.length) return names;
    return cert.server_name ? [cert.server_name] : [];
  }

  // ["DoT", "DoH", "DoQ"] -> "DoT, DoH and DoQ".
  function listJoin(items) {
    return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
  }

  const attention = $derived(certs.filter((c) => ['expired', 'soon', 'future'].includes(status(c).kind) && c.in_use?.length));
</script>

<PageHeader icon={icons.certificates} title="Certificates">
  {#snippet tagline()}
    TLS certificates for this web console (HTTPS) and the encrypted DNS
    listeners (DNS over TLS, HTTPS and QUIC). Get one from Let's Encrypt
    (renewed automatically), create a self-signed one, or upload one from
    any certificate authority. Private keys stay on the server and are
    never sent back to the browser.
  {/snippet}
</PageHeader>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if warning}
  <div class="card warn-card" style="margin-bottom: 14px">{warning}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}
{#each attention as cert (cert.name)}
  <div class="card warn-card" class:expired={status(cert).kind !== 'soon'} style="margin-bottom: 14px">
    <strong>{cert.name}</strong> is used by {listJoin(cert.in_use)} and
    {status(cert).kind === 'expired' ? 'has expired' : status(cert).text.toLowerCase()}.
    {#if !isViewer}
      {#if cert.acme}It renews automatically; use <strong>Renew Now</strong> to try straight away.{:else}Upload a renewed certificate with <strong>Replace</strong>.{/if}
    {/if}
  </div>
{/each}
{#each certs.filter((c) => c.acme?.status === 'failed') as cert (cert.name)}
  <div class="card warn-card expired" style="margin-bottom: 14px">
    <strong>{cert.name}</strong> could not be {cert.not_after ? 'renewed' : 'issued'}: {cert.acme.last_error}
  </div>
{/each}

<div class="card">
  <div class="spread" style="margin-bottom: 10px">
    <h3 style="margin: 0">Certificates ({certs.length})</h3>
    {#if !isViewer}
      <div class="row" style="gap: 8px">
        <button class="secondary" onclick={openAcme} disabled={!acme}>Let's Encrypt Settings</button>
        <button onclick={openAdd}>Add Certificate</button>
      </div>
    {/if}
  </div>

  {#if loading}
    <p class="muted">Loading...</p>
  {:else if certs.length === 0}
    <p class="muted">
      No certificates yet.
      {#if !isViewer}Create a self-signed one to get started, or upload one from your certificate authority.{/if}
    </p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>For</th><th>Issued By</th><th>Expires</th><th>Used By</th>{#if !isViewer}<th class="num">Actions</th>{/if}</tr>
        </thead>
        <tbody>
          {#each certs as cert (cert.name)}
            {@const st = status(cert)}
            <tr>
              <td><strong>{cert.name}</strong></td>
              <td>
                {#each covers(cert) as n (n)}<div><code>{n}</code></div>{:else}<span class="muted">-</span>{/each}
              </td>
              <td>
                {#if cert.self_signed}
                  <span class="pill" title="Clients must be told to trust this certificate">Self-Signed</span>
                {:else if cert.issuer}
                  {cert.issuer}
                {:else if !cert.acme}
                  <span class="muted">-</span>
                {/if}
                {#if cert.acme}
                  <div class="acme">
                    {#if cert.acme.status === 'pending'}
                      <span class="pill warn">{cert.not_after ? 'Renewing...' : 'Requesting...'}</span>
                    {:else if cert.acme.status === 'failed'}
                      <span class="pill err" title={cert.acme.last_error}>{cert.not_after ? 'Renewal Failed' : 'Request Failed'}</span>
                    {:else}
                      <span class="muted">Renews Automatically</span>
                    {/if}
                  </div>
                {/if}
              </td>
              <td class="nowrap">
                {#if cert.not_after && st.text !== 'Does Not Expire'}<div>{formatDate(cert.not_after)}</div>{/if}
                <span
                  class="pill"
                  class:ok={st.kind === 'ok'}
                  class:err={st.kind === 'expired' || st.kind === 'future'}
                  class:warn={st.kind === 'soon'}
                >{st.text}</span>
              </td>
              <td>
                {#if cert.in_use?.length}
                  {#each cert.in_use as l (l)}<span class="pill used">{l}</span>{/each}
                {:else}
                  <span class="muted">Not Used</span>
                {/if}
              </td>
              {#if !isViewer}
                <td class="num">
                  <div class="row" style="gap: 6px; justify-content: flex-end; flex-wrap: nowrap">
                    {#if cert.acme}
                      <button class="secondary" disabled={busy || cert.acme.status === 'pending'} onclick={() => renew(cert)} title="Ask the CA for a new certificate now">{cert.not_after ? 'Renew Now' : 'Retry'}</button>
                    {:else}
                      <button class="secondary" onclick={() => openReplace(cert)} title="Upload a renewed certificate under this name">Replace</button>
                    {/if}
                    <button
                      class="danger"
                      disabled={busy || cert.in_use?.length > 0}
                      title={cert.in_use?.length ? `Used by ${cert.in_use.join(', ')}: choose another certificate in Settings first` : 'Delete'}
                      aria-label="Delete {cert.name}"
                      onclick={() => remove(cert)}
                    >✕</button>
                  </div>
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  <div class="spread foot">
    <p class="muted help" style="margin: 0">
      Choose the web console's certificate in Settings → General, and the
      encrypted DNS listeners' in Settings → Encrypted DNS. Replacing a
      certificate in use applies at once. For the web console, upload one
      issued for the name you browse to, so browsers trust it.
    </p>
    {#if onOpenSettings}
      <div class="row" style="gap: 8px">
        <button class="secondary" onclick={() => onOpenSettings('general')}>Web Console Settings</button>
        <button class="secondary" onclick={() => onOpenSettings('listeners')}>Encrypted DNS Settings</button>
      </div>
    {/if}
  </div>
</div>

{#if form}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeForm()}>
    <form class="card modal" role="dialog" aria-modal="true" aria-labelledby="cert-title" onsubmit={saveCert}>
      <div class="spread modal-title">
        <h3 id="cert-title" style="margin: 0">{form.replacing ? `Replace Certificate - ${form.replacing}` : 'Add Certificate'}</h3>
        <button type="button" class="secondary" style="padding: 2px 10px" onclick={closeForm} aria-label="Close">✕</button>
      </div>
      {#if formError}<p class="dialog-error">{formError}</p>{/if}

      {#if !form.replacing}
        <div class="choices" role="radiogroup" aria-label="Certificate source">
          <label class="choice" class:on={form.mode === 'self'}>
            <input type="radio" bind:group={form.mode} value="self" />
            <span>
              <strong>Generate Self-Signed</strong>
              <small>Quick and free. Clients will only accept it if they are told to trust it, so it suits testing and private networks.</small>
            </span>
          </label>
          <label class="choice" class:on={form.mode === 'acme'}>
            <input type="radio" bind:group={form.mode} value="acme" />
            <span>
              <strong>Let's Encrypt</strong>
              <small>Free and trusted everywhere, issued and renewed automatically. The names must be reachable from the internet.</small>
            </span>
          </label>
          <label class="choice" class:on={form.mode === 'upload'}>
            <input type="radio" bind:group={form.mode} value="upload" />
            <span>
              <strong>Upload Certificate</strong>
              <small>From any certificate authority. Trusted by clients automatically; you replace it before it expires.</small>
            </span>
          </label>
        </div>
        <label class="full">
          <span>Name</span>
          <input type="text" bind:value={form.name} placeholder="lan-dns" autocomplete="off" spellcheck="false" />
        </label>
        <p class="muted help">How the certificate is listed and picked in Settings.</p>
      {:else}
        <p class="muted help" style="margin-top: 0">
          Upload the renewed certificate and its key. Listeners using
          '{form.replacing}' switch to it straight away.
        </p>
      {/if}

      {#if form.mode === 'acme'}
        <label class="full">
          <span>Domain Names (one per line)</span>
          <textarea rows="3" bind:value={form.domains} placeholder={'dns.example.com\n*.example.com'} spellcheck="false"></textarea>
        </label>
        <div class="choices two" role="radiogroup" aria-label="How to prove the names are yours">
          <label class="choice" class:on={form.challenge === 'http'}>
            <input type="radio" bind:group={form.challenge} value="http" />
            <span>
              <strong>Web Console (HTTP)</strong>
              <small>{caName()} connects to each name on port 80, which must reach this console's HTTP listener (directly, or forwarded by your router).</small>
            </span>
          </label>
          <label class="choice" class:on={form.challenge === 'dns'}>
            <input type="radio" bind:group={form.challenge} value="dns" />
            <span>
              <strong>DNS Zone Hosted Here</strong>
              <small>A temporary TXT record in the name's zone on this server, which must be the zone's public DNS server. Needed for wildcards (*.example.com).</small>
            </span>
          </label>
        </div>
        {#if !acme?.settings?.agree_terms}
          <label class="full">
            <span>Email for Expiry Notices (Optional)</span>
            <input type="email" bind:value={form.email} placeholder="you@example.com" autocomplete="email" />
          </label>
          <label class="check full">
            <input type="checkbox" bind:checked={form.agree} />
            <span>I accept the terms of service of {caName()}{#if caName().startsWith('Let')}{' '}(<a href="https://letsencrypt.org/repository/" target="_blank" rel="noopener">Subscriber Agreement</a>){/if}.</span>
          </label>
        {/if}
        <p class="muted help">
          The certificate is renewed {acme?.settings?.renew_days || 30} days before it expires, and listeners
          using it switch to the renewal straight away.
        </p>
      {:else if form.mode === 'self'}
        <label class="full">
          <span>Server Name</span>
          <input type="text" bind:value={form.serverName} placeholder="dns.example.com" autocomplete="off" spellcheck="false" />
        </label>
        <p class="muted help">The name clients use to reach this server; the certificate is issued for it (and for localhost).</p>
      {:else}
        <div class="grid2">
          <label>
            <span>Certificate (PEM)</span>
            <input type="file" accept=".pem,.crt,.cer" onchange={(e) => pickFile(e.currentTarget, 'cert')} />
            <textarea rows="5" bind:value={form.certPem} placeholder="-----BEGIN CERTIFICATE-----&#10;... or paste here" spellcheck="false"></textarea>
          </label>
          <label>
            <span>Private Key (PEM)</span>
            <input type="file" accept=".pem,.key" onchange={(e) => pickFile(e.currentTarget, 'key')} />
            <textarea rows="5" bind:value={form.keyPem} placeholder="-----BEGIN PRIVATE KEY-----&#10;... or paste here" spellcheck="false"></textarea>
          </label>
        </div>
        <p class="muted help">
          Use the full chain (your certificate first, then the intermediates;
          Let's Encrypt calls it <code>fullchain.pem</code>) and the matching
          private key. The pair is checked before it is saved.
        </p>
      {/if}

      <div class="row actions">
        <button type="submit" disabled={busy || !form.name.trim()}>
          {busy ? 'Saving...' : form.replacing ? 'Replace Certificate' : form.mode === 'self' ? 'Create Certificate' : form.mode === 'acme' ? 'Request Certificate' : 'Upload Certificate'}
        </button>
        <button type="button" class="secondary" onclick={closeForm} disabled={busy}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

{#if acmeForm}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && !busy && (acmeForm = null)}>
    <form class="card modal" role="dialog" aria-modal="true" aria-labelledby="acme-title" onsubmit={saveAcme}>
      <div class="spread modal-title">
        <h3 id="acme-title" style="margin: 0">Let's Encrypt Settings</h3>
        <button type="button" class="secondary" style="padding: 2px 10px" onclick={() => (acmeForm = null)} aria-label="Close">✕</button>
      </div>
      {#if acmeError}<p class="dialog-error">{acmeError}</p>{/if}
      <label>
        <span>Certificate Authority</span>
        <select bind:value={acmeForm.ca}>
          <option value="letsencrypt">Let's Encrypt</option>
          <option value="staging">Let's Encrypt Staging (for testing, not trusted)</option>
          <option value="custom">Another ACME CA</option>
        </select>
      </label>
      {#if acmeForm.ca === 'custom'}
        <label class="full">
          <span>Directory URL</span>
          <input type="url" bind:value={acmeForm.directory} placeholder="https://ca.internal/acme/acme/directory" spellcheck="false" />
        </label>
        <label class="full">
          <span>CA Root Certificate (PEM, if not publicly trusted)</span>
          <textarea rows="4" bind:value={acmeForm.ca_certificate} placeholder="-----BEGIN CERTIFICATE-----" spellcheck="false"></textarea>
        </label>
      {/if}
      <div class="grid2">
        <label>
          <span>Email for Expiry Notices (Optional)</span>
          <input type="email" bind:value={acmeForm.email} placeholder="you@example.com" autocomplete="email" />
        </label>
        <label>
          <span>Renew Days Before Expiry</span>
          <input type="number" min="1" max="60" bind:value={acmeForm.renew_days} />
        </label>
      </div>
      <label class="check full">
        <input type="checkbox" bind:checked={acmeForm.agree_terms} />
        <span>I accept the CA's terms of service{#if acmeForm.ca !== 'custom'}{' '}(<a href="https://letsencrypt.org/repository/" target="_blank" rel="noopener">Let's Encrypt Subscriber Agreement</a>){/if}.</span>
      </label>
      <p class="muted help">
        Certificates are checked twice a day and renewed automatically. A
        private CA such as step-ca works too: give its ACME directory and,
        if browsers do not trust it, its root certificate.
      </p>
      <div class="row actions">
        <button type="submit" disabled={busy}>{busy ? 'Saving...' : 'Save Settings'}</button>
        <button type="button" class="secondary" onclick={() => (acmeForm = null)} disabled={busy}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

<style>
  .check { flex-direction: row; align-items: flex-start; gap: 8px; }
  .check input { width: auto; margin-top: 2px; }
  .check span { color: var(--text); }
  .acme { margin-top: 4px; font-size: 0.8rem; }
  .choices.two { margin-top: 12px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  .full { margin-top: 12px; }
  .help { max-width: 90ch; }
  .nowrap { white-space: nowrap; }
  .nowrap div { margin-bottom: 4px; }
  .pill.used { border-color: var(--accent); margin-right: 4px; }
  .pill.warn { color: #e0a34e; border-color: #e0a34e; }
  .warn-card { border-color: #e0a34e; }
  .warn-card.expired { border-color: var(--danger); }
  .foot { margin-top: 12px; gap: 12px; flex-wrap: wrap; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px; }
  textarea { font: 0.8rem/1.4 ui-monospace, 'Cascadia Code', Consolas, monospace; width: 100%; }
  input[type='file'] { font-size: 0.8rem; }
  .choices { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  .choices.two { grid-template-columns: 1fr 1fr; }
  .choice {
    flex-direction: row;
    align-items: flex-start;
    gap: 8px;
    padding: 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    cursor: pointer;
  }
  .choice.on { border-color: var(--accent); background: rgb(91 140 255 / 0.1); }
  .choice input { width: auto; margin-top: 3px; }
  .choice span { display: flex; flex-direction: column; gap: 4px; }
  .choice strong { color: var(--text); font-weight: 600; }
  .choice small { color: var(--muted); font-size: 0.78rem; line-height: 1.35; }
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 10; }
  .modal { width: min(680px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
  .modal-title { margin-bottom: 12px; }
  .actions { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border); }
  @media (max-width: 640px) {
    .grid2, .choices { grid-template-columns: 1fr; }
  }
</style>

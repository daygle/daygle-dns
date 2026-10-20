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

  const me = getStoredUser();
  const isViewer = me?.role === 'viewer';
  const DAY = 86400000;
  const SOON_DAYS = 30;

  async function load() {
    error = null;
    try {
      certs = await api.certificates();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    load();
  });

  function openAdd() {
    notice = warning = null;
    formError = null;
    form = { replacing: null, mode: 'self', name: '', serverName: '', certPem: '', keyPem: '' };
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
    TLS certificates for the encrypted DNS listeners (DNS over TLS, HTTPS and
    QUIC). Create a self-signed certificate, or upload one issued by a
    certificate authority. Private keys stay on the server and are never sent
    back to the browser.
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
    {#if !isViewer}Upload a renewed certificate with <strong>Replace</strong>.{/if}
  </div>
{/each}

<div class="card">
  <div class="spread" style="margin-bottom: 10px">
    <h3 style="margin: 0">Certificates ({certs.length})</h3>
    {#if !isViewer}
      <button onclick={openAdd}>Add Certificate</button>
    {/if}
  </div>

  {#if loading}
    <p class="muted">Loading…</p>
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
                {:else}
                  <span class="muted">-</span>
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
                    <button class="secondary" onclick={() => openReplace(cert)} title="Upload a renewed certificate under this name">Replace</button>
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
      Choose which certificate each listener uses in Settings → Encrypted
      DNS. Replacing a certificate in use applies at once.
    </p>
    {#if onOpenSettings}
      <button class="secondary" onclick={() => onOpenSettings('listeners')}>Open Encrypted DNS Settings</button>
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
          <label class="choice" class:on={form.mode === 'upload'}>
            <input type="radio" bind:group={form.mode} value="upload" />
            <span>
              <strong>Upload Certificate</strong>
              <small>From a certificate authority such as Let's Encrypt. Trusted by clients automatically.</small>
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

      {#if form.mode === 'self'}
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
            <textarea rows="5" bind:value={form.certPem} placeholder="-----BEGIN CERTIFICATE-----&#10;… or paste here" spellcheck="false"></textarea>
          </label>
          <label>
            <span>Private Key (PEM)</span>
            <input type="file" accept=".pem,.key" onchange={(e) => pickFile(e.currentTarget, 'key')} />
            <textarea rows="5" bind:value={form.keyPem} placeholder="-----BEGIN PRIVATE KEY-----&#10;… or paste here" spellcheck="false"></textarea>
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
          {busy ? 'Saving…' : form.replacing ? 'Replace Certificate' : form.mode === 'self' ? 'Create Certificate' : 'Upload Certificate'}
        </button>
        <button type="button" class="secondary" onclick={closeForm} disabled={busy}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

<style>
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
  .choices { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
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

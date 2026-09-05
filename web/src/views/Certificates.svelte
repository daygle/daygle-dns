<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDate } from '../datetime.svelte.js';

  let certs = $state([]);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state(null);
  let notice = $state(null);

  // New-certificate form.
  let showForm = $state(false);
  let mode = $state('self'); // 'self' = generate self-signed, 'upload' = paste PEM pair
  let newName = $state('');
  let newServerName = $state('');
  let newCertPem = $state('');
  let newKeyPem = $state('');
  let formError = $state(null);

  const me = getStoredUser();
  const isViewer = me?.role === 'viewer';

  function resetForm() {
    newName = '';
    newServerName = '';
    newCertPem = '';
    newKeyPem = '';
    formError = null;
  }

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
      if (field === 'cert') newCertPem = (await readFile(file)).trim() + '\n';
      else newKeyPem = (await readFile(file)).trim() + '\n';
    } catch (e) {
      formError = `Could not read ${file.name}: ${e}`;
    }
  }

  async function saveCert(e) {
    e.preventDefault();
    formError = null;
    const name = newName.trim();
    if (!name) {
      formError = 'Name is required.';
      return;
    }
    if (mode === 'upload' && (!newCertPem.trim() || !newKeyPem.trim())) {
      formError = 'Both the certificate and the private key are required.';
      return;
    }
    if (mode === 'self' && !newServerName.trim()) {
      formError = 'A server name is required (it becomes the certificate CN / SAN).';
      return;
    }
    busy = true;
    try {
      const payload = mode === 'self'
        ? { name, server_name: newServerName.trim() }
        : { name, cert_pem: newCertPem.trim() + '\n', key_pem: newKeyPem.trim() + '\n' };
      await api.createCertificate(payload);
      notice = mode === 'self'
        ? `Self-signed certificate '${name}' created.`
        : `Certificate '${name}' uploaded.`;
      showForm = false;
      resetForm();
      await load();
    } catch (err) {
      formError = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  async function remove(cert) {
    if (!confirm(`Delete certificate '${cert.name}'? Listeners using it must be changed first.`)) return;
    busy = true;
    error = null;
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
</script>

<h1>Certificates</h1>
<p class="muted" style="max-width: 75ch">
  TLS certificates used by the DNS over TLS / HTTPS / QUIC listeners. Create a
  self-signed certificate here, or upload a certificate + private key pair
  (e.g. one issued by a CA). The PEM material is stored in the server database
  and never returned to the browser. Pick a certificate for each listener on
  the <strong>Settings</strong> page.
</p>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

<div class="card">
  <div class="spread" style="margin-bottom: 10px">
    <h3 style="margin: 0">Managed Certificates</h3>
    {#if !isViewer}
      <button onclick={() => { showForm = !showForm; if (!showForm) resetForm(); }}>
        {showForm ? 'Close' : 'New Certificate'}
      </button>
    {/if}
  </div>

  {#if showForm}
    <form class="card" style="background: var(--panel-2); margin-bottom: 14px" onsubmit={saveCert}>
      <div class="row" style="gap: 16px; flex-wrap: wrap">
        <label class="radio-label">
          <input type="radio" bind:group={mode} value="self" />
          <span>Generate self-signed</span>
        </label>
        <label class="radio-label">
          <input type="radio" bind:group={mode} value="upload" />
          <span>Upload certificate + key</span>
        </label>
      </div>

      <div class="form-grid" style="margin-top: 12px">
        <label>
          <span>Name</span>
          <input type="text" bind:value={newName} placeholder="lan-dns" autocomplete="off" />
        </label>
        {#if mode === 'self'}
          <label>
            <span>Server Name (CN / SAN)</span>
            <input type="text" bind:value={newServerName} placeholder="dns.example.com" autocomplete="off" />
          </label>
        {/if}
      </div>

      {#if mode === 'upload'}
        <div class="row" style="gap: 16px; margin-top: 12px; flex-wrap: wrap">
          <label class="file-label">
            <span>Certificate (PEM)</span>
            <input type="file" accept=".pem,.crt,.cer,.p7b" onchange={(e) => pickFile(e.currentTarget, 'cert')} />
          </label>
          <label class="file-label">
            <span>Private Key (PEM)</span>
            <input type="file" accept=".pem,.key" onchange={(e) => pickFile(e.currentTarget, 'key')} />
          </label>
        </div>
        <div class="form-grid pem-grid">
          <label>
            <span>Certificate PEM (or paste)</span>
            <textarea rows="5" bind:value={newCertPem} placeholder="-----BEGIN CERTIFICATE-----&#10;..." spellcheck="false"></textarea>
          </label>
          <label>
            <span>Private Key PEM (or paste)</span>
            <textarea rows="5" bind:value={newKeyPem} placeholder="-----BEGIN PRIVATE KEY-----&#10;..." spellcheck="false"></textarea>
          </label>
        </div>
      {/if}

      {#if formError}<div class="form-error">{formError}</div>{/if}
      <div class="row" style="margin-top: 12px">
        <button type="submit" disabled={busy || !newName.trim()}>
          {busy ? 'Saving…' : mode === 'self' ? 'Create Self-Signed' : 'Upload'}
        </button>
        <button type="button" class="secondary" onclick={() => { showForm = false; resetForm(); }}>Cancel</button>
      </div>
    </form>
  {/if}

  {#if loading}
    <p class="muted">Loading…</p>
  {:else if certs.length === 0}
    <p class="muted">
      No certificates yet.
      {#if !isViewer}Create a self-signed one, or upload your certificate + key.{/if}
    </p>
  {:else}
    <table>
      <thead>
        <tr><th>Name</th><th>Server Name</th><th>Created</th><th>In Use</th><th></th></tr>
      </thead>
      <tbody>
        {#each certs as cert (cert.name)}
          <tr>
            <td><code>{cert.name}</code></td>
            <td>{cert.server_name || '—'}</td>
            <td class="muted">{formatDate(cert.created_at)}</td>
            <td>
              {#if cert.in_use && cert.in_use.length > 0}
                <span class="pill ok">{cert.in_use.join(', ')}</span>
              {:else}
                <span class="muted">—</span>
              {/if}
            </td>
            <td class="row" style="justify-content: flex-end; gap: 6px">
              {#if !isViewer}
                <button
                  class="danger"
                  style="padding: 4px 10px"
                  disabled={busy || (cert.in_use && cert.in_use.length > 0)}
                  title={cert.in_use && cert.in_use.length > 0 ? 'Change the listener on Settings first' : undefined}
                  onclick={() => remove(cert)}
                >Delete</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-size: 0.8rem; font-weight: 600; }
  .row { display: flex; align-items: center; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  .radio-label { flex-direction: row; align-items: center; gap: 6px; font-size: 0.9rem; }
  .radio-label span { color: var(--text); }
  .file-label { font-size: 0.85rem; }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .pem-grid { grid-template-columns: 1fr 1fr; margin-top: 12px; }
  textarea {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 8px;
    font: 0.8rem/1.4 ui-monospace, 'Cascadia Code', Consolas, monospace;
    color: inherit;
    resize: vertical;
  }
  .form-error { margin-top: 10px; color: var(--danger); font-size: 0.85rem; }
</style>
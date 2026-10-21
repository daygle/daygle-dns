<script>
  import { onMount } from 'svelte';
  import { api, formatApiError } from '../api.js';
  import { formatDate } from '../datetime.svelte.js';

  // Personal API tokens for the signed-in account (Account page): scripts
  // send one as `Authorization: Bearer <token>`. A token is shown once, when
  // made.
  let { readOnlyAccount = false } = $props();

  let tokens = $state([]);
  let loading = $state(true);
  let name = $state('');
  let readOnly = $state(false);
  let expires = $state('0');
  let created = $state(null);
  let busy = $state(false);
  let error = $state(null);

  onMount(load);

  async function load() {
    try {
      tokens = await api.apiTokens();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      loading = false;
    }
  }

  async function create(e) {
    e.preventDefault();
    busy = true;
    error = null;
    try {
      created = await api.createApiToken({
        name: name.trim(),
        read_only: readOnly || readOnlyAccount,
        expires_in_days: Number(expires),
      });
      name = '';
      readOnly = false;
      await load();
    } catch (err) {
      error = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  async function revoke(token) {
    if (!confirm(`Revoke the API token '${token.name}'? Scripts using it stop working at once.`)) return;
    busy = true;
    error = null;
    try {
      await api.deleteApiToken(token.id);
      if (created?.id === token.id) created = null;
      await load();
    } catch (err) {
      error = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  const when = (secs) => (secs ? formatDate(new Date(secs * 1000)) : null);
</script>

<div class="card panel">
  <h3 style="margin: 0">API Tokens</h3>
  <p class="modal-note">
    For scripts and tools that use the API as you: send the token as
    <code>Authorization: Bearer &lt;token&gt;</code>. A token keeps working
    until it expires or you revoke it, even after the server restarts, and
    skips two-factor login, so keep it as safe as a password. For
    Prometheus, make a read-only token and scrape
    <code>/api/metrics/prometheus</code>.
  </p>

  {#if created}
    <div class="created">
      <strong>Copy the token for '{created.name}' now: it is not shown again.</strong>
      <div class="secret-row">
        <code class="secret">{created.token}</code>
        <button type="button" class="secondary" onclick={() => navigator.clipboard?.writeText(created.token)}>Copy</button>
      </div>
    </div>
  {/if}

  <form onsubmit={create}>
    <div class="grid">
      <label>
        <span>Name</span>
        <input type="text" bind:value={name} placeholder="backup script" maxlength="64" />
      </label>
      <label>
        <span>Expires</span>
        <select bind:value={expires}>
          <option value="30">In 30 Days</option>
          <option value="90">In 90 Days</option>
          <option value="365">In 1 Year</option>
          <option value="0">Never</option>
        </select>
      </label>
    </div>
    <label class="check">
      <input type="checkbox" bind:checked={readOnly} disabled={readOnlyAccount} />
      <span>Read-Only (can look but not change anything){#if readOnlyAccount}: always, for a read-only account{/if}</span>
    </label>
    {#if error}<div class="form-error">{error}</div>{/if}
    <div class="modal-actions">
      <button type="submit" disabled={busy || !name.trim()}>{busy ? 'Creating…' : 'Create Token'}</button>
    </div>
  </form>

  <div class="list">
    {#if loading}
      <p class="muted">Loading…</p>
    {:else if tokens.length === 0}
      <p class="muted">No API tokens yet.</p>
    {:else}
      {#each tokens as t (t.id)}
        <div class="token">
          <div>
            <strong>{t.name}</strong>
            {#if t.read_only}<span class="pill">Read-Only</span>{/if}
            <div class="muted small">
              Created {when(t.created_at)} ·
              {t.last_used_at ? `Last used ${when(t.last_used_at)}` : 'Never used'} ·
              {t.expires_at ? (t.expires_at * 1000 < Date.now() ? 'Expired' : `Expires ${when(t.expires_at)}`) : 'Never expires'}
            </div>
          </div>
          <button type="button" class="danger" disabled={busy} onclick={() => revoke(t)}>Revoke</button>
        </div>
      {/each}
    {/if}
  </div>
</div>

<style>
  .panel { max-width: 720px; display: flex; flex-direction: column; gap: 12px; }
  .panel form { display: flex; flex-direction: column; gap: 10px; }
  .modal-note { margin: 0; font-size: 0.85rem; color: var(--muted); line-height: 1.45; }
  .form-error { color: var(--danger); font-size: 0.85rem; }
  .modal-actions { display: flex; gap: 8px; }
  .grid { display: grid; grid-template-columns: minmax(0, 1fr) 160px; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  .check { flex-direction: row; align-items: center; gap: 8px; }
  .check input { width: auto; }
  .created {
    padding: 10px 12px;
    border: 1px solid var(--ok);
    border-radius: 6px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    font-size: 0.85rem;
  }
  .secret-row { display: flex; gap: 8px; align-items: center; }
  .secret { flex: 1; min-width: 0; word-break: break-all; font-size: 0.8rem; }
  .list { border-top: 1px solid var(--border); padding-top: 10px; display: flex; flex-direction: column; gap: 8px; }
  .token { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
  .token .pill { margin-left: 6px; }
  .small { font-size: 0.78rem; margin-top: 2px; }
  @media (max-width: 520px) {
    .grid { grid-template-columns: 1fr; }
  }
</style>

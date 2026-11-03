<script>
  import { onMount } from 'svelte';
  import IconButton from '../IconButton.svelte';
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDateTime } from '../datetime.svelte.js';
  import { copyText } from '../clipboard.js';

  // DNS accounts, as NextDNS does them: each account has a client ID, and a
  // device set up with `<client id>.<domain>` as its DoT/DoQ host name (or
  // DoH at `/dns-query/<client id>`) is recognised as that account wherever
  // it connects from. Filtering groups can then target the account.
  const isAdmin = getStoredUser()?.role !== 'viewer';

  let accounts = $state([]);
  let settings = $state({ domain: '', require: false });
  let saved = $state({ domain: '', require: false });
  let dohPort = $state(443);
  let dohEnabled = $state(false);
  let dotEnabled = $state(false);
  let loaded = $state(false);
  let busy = $state(false);
  let error = $state(null);
  let notice = $state(null);
  let name = $state('');
  let clientId = $state('');
  let editing = $state(null);

  const domain = $derived(saved.domain.trim().replace(/\.$/, '').toLowerCase());
  const dirty = $derived(
    settings.domain.trim() !== saved.domain.trim() || !!settings.require !== !!saved.require,
  );

  onMount(load);

  async function load() {
    try {
      const data = await api.accounts();
      accounts = data.accounts || [];
      saved = { domain: data.settings?.domain || '', require: !!data.settings?.require };
      if (!loaded) settings = { ...saved };
      const config = await api.config().catch(() => null);
      if (config) {
        dohPort = config.doh?.port || 443;
        dohEnabled = !!config.doh?.enabled;
        dotEnabled = !!config.dot?.enabled;
      }
      error = null;
    } catch (e) {
      error = formatApiError(e);
    } finally {
      loaded = true;
    }
  }

  async function run(action, done) {
    busy = true;
    error = null;
    notice = null;
    try {
      await action();
      if (done) notice = done;
      await load();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      busy = false;
    }
  }

  function saveSettings(e) {
    e.preventDefault();
    const accountsSettings = {
      domain: settings.domain.trim().replace(/\.$/, '').toLowerCase(),
      require: !!settings.require,
    };
    run(async () => {
      await api.updateSettings({ accounts: accountsSettings });
      settings = { ...accountsSettings };
    }, 'Account settings saved.');
  }

  function create(e) {
    e.preventDefault();
    run(async () => {
      await api.createAccount({ name: name.trim(), client_id: clientId.trim() });
      name = '';
      clientId = '';
    });
  }

  function rename(account) {
    if (!editing?.value.trim()) return;
    run(async () => {
      await api.updateAccount(account.id, { name: editing.value.trim(), enabled: account.enabled });
      editing = null;
    });
  }

  function setEnabled(account, enabled) {
    run(() => api.updateAccount(account.id, { name: account.name, enabled }));
  }

  function newId(account) {
    if (!confirm(`Give '${account.name}' a new client ID? Its devices stop being recognised until they are set up with the new host name.`)) return;
    run(() => api.newAccountClientId(account.id), `'${account.name}' has a new client ID.`);
  }

  function remove(account) {
    if (!confirm(`Delete the DNS account '${account.name}'? Its devices are no longer recognised, and filtering groups stop naming it.`)) return;
    run(() => api.deleteAccount(account.id));
  }

  const dohUrl = (a) =>
    domain ? `https://${domain}${dohPort && dohPort !== 443 ? `:${dohPort}` : ''}${a.doh_path}` : '';

  async function copy(text) {
    try {
      await copyText(text);
      notice = `Copied ${text}`;
    } catch (e) {
      error = formatApiError(e);
    }
  }
</script>

<div class="card panel">
  <h3 style="margin: 0">How Devices Connect</h3>
  <p class="note">
    Give each device (or person) an account. The device then uses its own
    host name for encrypted DNS - <code>&lt;client id&gt;.{domain || 'dns.example.com'}</code> -
    and is recognised as that account from any network: on Android, enter it
    under <em>Settings → Private DNS</em>; on Apple devices, use it as the DoT
    server name in a configuration profile; DoH clients (browsers, Windows)
    use the account's DoH URL instead. Filtering groups can then target the
    account (Filtering Groups → Clients), and the Query Log shows it.
  </p>
  <p class="note">
    The listeners' certificate must cover both <code>{domain || 'dns.example.com'}</code>
    and <code>*.{domain || 'dns.example.com'}</code>: request one on the
    Certificates page with the DNS challenge, then pick it for DoT, DoH and DoQ
    in Settings → Encrypted DNS. Names are read from the TLS handshake, so
    plain DNS (port 53) and DNS over HTTP/3 cannot carry an account.
  </p>
  {#if loaded && !dotEnabled && !dohEnabled}
    <p class="warn">DoT and DoH are both off (Settings → Encrypted DNS): devices have nothing to connect to yet.</p>
  {/if}

  <form onsubmit={saveSettings}>
    <div class="grid">
      <label>
        <span>Account Domain</span>
        <input type="text" bind:value={settings.domain} placeholder="dns.example.com" disabled={!isAdmin} spellcheck="false" autocomplete="off" />
      </label>
    </div>
    <label class="check">
      <input type="checkbox" bind:checked={settings.require} disabled={!isAdmin || !settings.domain.trim()} />
      <span>Require an account: refuse DoT, DoH and DoQ queries that name no known, enabled account (plain DNS is not affected)</span>
    </label>
    {#if isAdmin}
      <div class="actions">
        <button type="submit" disabled={busy || !dirty}>Save</button>
      </div>
    {/if}
  </form>
</div>

<div class="card panel">
  <h3 style="margin: 0">DNS Accounts ({accounts.length})</h3>
  {#if error}<div class="form-error">{error}</div>{/if}
  {#if notice}<div class="notice">{notice}</div>{/if}

  {#if isAdmin}
    <form onsubmit={create}>
      <div class="grid two">
        <label>
          <span>Name</span>
          <input type="text" bind:value={name} placeholder="Kids' tablet" maxlength="64" />
        </label>
        <label>
          <span>Client ID (optional)</span>
          <input type="text" bind:value={clientId} placeholder="random" maxlength="63" spellcheck="false" autocomplete="off" />
        </label>
      </div>
      <div class="actions">
        <button type="submit" disabled={busy || !name.trim()}>Add Account</button>
      </div>
    </form>
  {/if}

  {#if !loaded}
    <p class="muted">Loading...</p>
  {:else if accounts.length === 0}
    <p class="muted">No DNS accounts yet.</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>DoT / DoQ Host Name</th>
            <th>DoH URL</th>
            <th>Last Seen</th>
            {#if isAdmin}<th class="num">Actions</th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each accounts as a (a.id)}
            <tr class:disabled={!a.enabled}>
              <td>
                {#if editing?.id === a.id}
                  <form class="row" style="gap: 6px" onsubmit={(e) => { e.preventDefault(); rename(a); }}>
                    <input bind:value={editing.value} maxlength="64" aria-label="Account name" />
                    <button type="submit" disabled={busy}>Save</button>
                    <button type="button" class="secondary" onclick={() => (editing = null)}>Cancel</button>
                  </form>
                {:else}
                  <strong>{a.name}</strong>
                  {#if !a.enabled}<span class="pill">Disabled</span>{/if}
                {/if}
              </td>
              <td>
                {#if a.hostname}
                  <button type="button" class="link" title="Copy" onclick={() => copy(a.hostname)}><code>{a.hostname}</code></button>
                {:else}
                  <span class="muted">Set the account domain</span> <code class="muted">({a.client_id})</code>
                {/if}
              </td>
              <td>
                {#if dohUrl(a)}
                  <button type="button" class="link" title="Copy" onclick={() => copy(dohUrl(a))}><code>{dohUrl(a)}</code></button>
                {:else}
                  <code class="muted">{a.doh_path}</code>
                {/if}
              </td>
              <td class="muted nowrap">{a.last_seen_at ? formatDateTime(a.last_seen_at) : 'Never'}</td>
              {#if isAdmin}
                <td class="num">
                  <div class="row" style="gap: 6px; justify-content: flex-end">
                    <IconButton icon="edit" label="Rename {a.name}" disabled={busy} onclick={() => (editing = { id: a.id, value: a.name })} />
                    {#if a.enabled}
                      <IconButton icon="disallow" label="Disable {a.name}: its devices are no longer recognised" disabled={busy} onclick={() => setEnabled(a, false)} />
                    {:else}
                      <IconButton icon="allow" label="Enable {a.name}" disabled={busy} onclick={() => setEnabled(a, true)} />
                    {/if}
                    <IconButton icon="key" label="New client ID for {a.name} (if the host name leaked)" disabled={busy} onclick={() => newId(a)} />
                    <IconButton icon="delete" variant="danger" label="Delete {a.name}" disabled={busy} onclick={() => remove(a)} />
                  </div>
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  <p class="muted help">
    A client ID identifies a device but is not a password: it travels
    unencrypted in the TLS handshake, so anyone on the device's network path
    can see it. Generated IDs are long enough not to be guessed; if one
    leaks, give the account a new one.
  </p>
</div>

<style>
  .panel { display: flex; flex-direction: column; gap: 12px; }
  .panel + .panel { margin-top: 16px; }
  .panel form { display: flex; flex-direction: column; gap: 10px; }
  .note { margin: 0; font-size: 0.85rem; color: var(--muted); line-height: 1.45; }
  .warn { margin: 0; font-size: 0.85rem; color: var(--warn, var(--danger)); }
  .notice { font-size: 0.85rem; color: var(--ok); }
  .form-error { color: var(--danger); font-size: 0.85rem; }
  .actions { display: flex; gap: 8px; }
  .grid { display: grid; grid-template-columns: minmax(0, 360px); gap: 10px; }
  .grid.two { grid-template-columns: minmax(0, 260px) minmax(0, 220px); }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  .check { flex-direction: row; align-items: center; gap: 8px; }
  .check input { width: auto; }
  .link { background: none; border: none; padding: 0; cursor: copy; text-align: left; color: inherit; }
  code { word-break: break-all; }
  .nowrap { white-space: nowrap; }
  tr.disabled td { opacity: 0.6; }
  @media (max-width: 520px) {
    .grid, .grid.two { grid-template-columns: 1fr; }
  }
</style>

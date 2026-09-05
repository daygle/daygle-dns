<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import { formatDate } from '../datetime.svelte.js';

  let users = $state([]);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state(null);
  let notice = $state(null);

  // New-user form.
  let showForm = $state(false);
  let newUsername = $state('');
  let newPassword = $state('');
  let newRole = $state('admin');
  let formError = $state(null);

  // Per-user reset-password dialog.
  let resetUser = $state(null);
  let resetPassword = $state('');
  let resetError = $state(null);

  const me = getStoredUser();

  async function load() {
    error = null;
    try {
      users = await api.users();
    } catch (e) {
      error = formatApiError(e);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    load();
  });

  async function createUser(e) {
    e.preventDefault();
    formError = null;
    if (!newUsername.trim() || newPassword.length < 8) {
      formError = 'Password must be at least 8 characters.';
      return;
    }
    busy = true;
    try {
      await api.createUser({ username: newUsername.trim(), password: newPassword, role: newRole });
      notice = `Account '${newUsername.trim()}' created.`;
      newUsername = '';
      newPassword = '';
      newRole = 'admin';
      showForm = false;
      await load();
    } catch (err) {
      formError = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  function openReset(user) {
    resetUser = user;
    resetPassword = '';
    resetError = null;
  }

  async function saveReset(e) {
    e.preventDefault();
    if (!resetPassword || resetPassword.length < 8) {
      resetError = 'Password must be at least 8 characters.';
      return;
    }
    busy = true;
    try {
      await api.updateUser(resetUser.username, { password: resetPassword });
      notice = `Password reset for '${resetUser.username}'. Their sessions were signed out.`;
      resetUser = null;
      resetPassword = '';
    } catch (err) {
      resetError = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  async function setRole(user, role) {
    if (user.role === role) return;
    busy = true;
    error = null;
    try {
      await api.updateUser(user.username, { role });
      notice = `Role for '${user.username}' set to ${role}.`;
      await load();
    } catch (err) {
      error = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  async function setEnabled(user, enabled) {
    busy = true;
    error = null;
    try {
      await api.updateUser(user.username, { enabled });
      notice = enabled
        ? `Account '${user.username}' enabled.`
        : `Account '${user.username}' disabled. Their sessions were signed out.`;
      await load();
    } catch (err) {
      error = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  async function remove(user) {
    if (!confirm(`Delete account '${user.username}'? Their sessions are signed out.`)) return;
    busy = true;
    error = null;
    try {
      await api.deleteUser(user.username);
      notice = `Account '${user.username}' deleted.`;
      await load();
    } catch (err) {
      error = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  // The last enabled admin cannot be changed; hide destructive controls for
  // it so the UI matches what the server will accept.
  function isLastAdmin(user) {
    const admins = users.filter((u) => u.role === 'admin' && u.enabled);
    return user.role === 'admin' && user.enabled && admins.length <= 1;
  }
</script>

<h1>Users</h1>
<p class="muted" style="max-width: 75ch">
  Console accounts for signing in to this dashboard. Accounts live in the
  server database (not the config file); every change signs out the affected
  account's sessions immediately.
</p>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

<div class="card">
  <div class="spread" style="margin-bottom: 10px">
    <h3 style="margin: 0">Accounts</h3>
    <button onclick={() => (showForm = !showForm)}>{showForm ? 'Close' : 'Add User'}</button>
  </div>

  {#if showForm}
    <form class="new-user card" style="background: var(--panel-2); margin-bottom: 14px" onsubmit={createUser}>
      <div class="form-grid">
        <label>
          <span>Username</span>
          <input type="text" bind:value={newUsername} placeholder="jane" autocomplete="off" />
        </label>
        <label>
          <span>Password</span>
          <input type="password" bind:value={newPassword} placeholder="At least 8 characters" autocomplete="new-password" />
        </label>
        <label>
          <span>Role</span>
          <select bind:value={newRole}>
            <option value="admin">Administrator</option>
            <option value="viewer">Read-Only</option>
          </select>
        </label>
      </div>
      {#if formError}<div class="form-error">{formError}</div>{/if}
      <div class="row" style="margin-top: 10px">
        <button type="submit" disabled={busy || !newUsername.trim() || !newPassword}>Create Account</button>
        <button type="button" class="secondary" onclick={() => (showForm = false)}>Cancel</button>
      </div>
    </form>
  {/if}

  {#if loading}
    <p class="muted">Loading…</p>
  {:else if users.length === 0}
    <p class="muted">No accounts yet.</p>
  {:else}
    <table>
      <thead>
        <tr><th>Username</th><th>Role</th><th>Status</th><th>Created</th><th></th></tr>
      </thead>
      <tbody>
        {#each users as user (user.username)}
          <tr>
            <td>
              {user.username}
              {#if me && user.username === me.username}<span class="muted"> (you)</span>{/if}
            </td>
            <td>
              <select
                disabled={busy || isLastAdmin(user)}
                title={isLastAdmin(user) ? 'The last enabled admin cannot be changed' : undefined}
                value={user.role}
                onchange={(e) => setRole(user, e.currentTarget.value)}
              >
                <option value="admin">Administrator</option>
                <option value="viewer">Read-Only</option>
              </select>
            </td>
            <td>
              <span class="pill" class:ok={user.enabled} class:err={!user.enabled}>
                {user.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </td>
            <td class="muted">{formatDate(user.created_at)}</td>
            <td class="row" style="justify-content: flex-end; gap: 6px; white-space: nowrap">
              <button class="secondary" style="padding: 4px 10px" onclick={() => openReset(user)}>Reset Password</button>
              {#if !isLastAdmin(user)}
                {#if user.enabled}
                  <button class="secondary" style="padding: 4px 10px" disabled={busy} onclick={() => setEnabled(user, false)}>Disable</button>
                {:else}
                  <button class="secondary" style="padding: 4px 10px" disabled={busy} onclick={() => setEnabled(user, true)}>Enable</button>
                {/if}
                <button class="danger" style="padding: 4px 10px" disabled={busy} onclick={() => remove(user)}>Delete</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

{#if resetUser}
  <div class="modal-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) resetUser = null; }}>
    <form class="card modal" onsubmit={saveReset}>
      <div class="spread" style="margin-bottom: 10px">
        <h3 style="margin: 0">Reset Password</h3>
        <button type="button" class="secondary" style="padding: 2px 10px" onclick={() => (resetUser = null)}>✕</button>
      </div>
      <p class="muted" style="margin-top: 0">
        Set a new password for <strong>{resetUser.username}</strong>. The change
        applies immediately and signs out their sessions.
      </p>
      <label>
        <span>New Password</span>
        <input type="password" bind:value={resetPassword} placeholder="At least 8 characters" autocomplete="new-password" />
      </label>
      {#if resetError}<div class="form-error">{resetError}</div>{/if}
      <div class="row" style="margin-top: 12px">
        <button type="submit" disabled={busy || !resetPassword}>Save Password</button>
        <button type="button" class="secondary" onclick={() => (resetUser = null)}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

<style>
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-size: 0.8rem; font-weight: 600; }
  select { min-width: 110px; }
  .row { display: flex; align-items: center; }
  .form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 140px;
    gap: 12px;
  }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  .form-error {
    margin-top: 10px;
    color: var(--danger);
    font-size: 0.85rem;
  }
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 50;
  }
  .modal { width: 400px; }
</style>

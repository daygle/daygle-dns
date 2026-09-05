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
  let newFirstName = $state('');
  let newLastName = $state('');
  let newEmail = $state('');
  let formError = $state(null);

  // Edit modal (click a row to open).
  let editUser = $state(null); // draft copy of the selected user
  let editOriginal = $state(null); // pristine copy for change detection
  let editError = $state(null);
  let editSaving = $state(false);
  // Reset-password section inside the edit modal.
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
      await api.createUser({
        username: newUsername.trim(),
        password: newPassword,
        role: newRole,
        first_name: newFirstName.trim(),
        last_name: newLastName.trim(),
        email: newEmail.trim(),
      });
      notice = `Account '${newUsername.trim()}' created.`;
      newUsername = '';
      newPassword = '';
      newRole = 'admin';
      newFirstName = '';
      newLastName = '';
      newEmail = '';
      showForm = false;
      await load();
    } catch (err) {
      formError = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  function openEdit(user) {
    editOriginal = structuredClone(user);
    editUser = structuredClone(user);
    editError = null;
    resetPassword = '';
    resetError = null;
  }

  async function saveEdit() {
    editError = null;
    const payload = {};
    if (editUser.first_name !== editOriginal.first_name) payload.first_name = editUser.first_name;
    if (editUser.last_name !== editOriginal.last_name) payload.last_name = editUser.last_name;
    if (editUser.email !== editOriginal.email) payload.email = editUser.email;
    if (editUser.role !== editOriginal.role) payload.role = editUser.role;
    if (editUser.enabled !== editOriginal.enabled) payload.enabled = editUser.enabled;
    if (Object.keys(payload).length === 0) {
      editUser = null;
      return;
    }
    editSaving = true;
    try {
      await api.updateUser(editUser.username, payload);
      notice = `Details for '${editUser.username}' updated.`;
      editUser = null;
      await load();
    } catch (err) {
      editError = formatApiError(err);
    } finally {
      editSaving = false;
    }
  }

  async function saveReset(e) {
    e.preventDefault();
    resetError = null;
    if (!resetPassword || resetPassword.length < 8) {
      resetError = 'Password must be at least 8 characters.';
      return;
    }
    editSaving = true;
    try {
      await api.updateUser(editUser.username, { password: resetPassword });
      notice = `Password reset for '${editUser.username}'. Their sessions were signed out.`;
      resetPassword = '';
      resetError = null;
      editUser = null;
    } catch (err) {
      resetError = formatApiError(err);
    } finally {
      editSaving = false;
    }
  }

  async function remove(user) {
    if (!confirm(`Delete account '${user.username}'? Their sessions are signed out.`)) return;
    busy = true;
    error = null;
    try {
      await api.deleteUser(user.username);
      notice = `Account '${user.username}' deleted.`;
      editUser = null;
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

  function displayName(user) {
    const first = (user.first_name || '').trim();
    const last = (user.last_name || '').trim();
    if (first && last) return `${first} ${last}`;
    if (first) return first;
    if (last) return last;
    return '—';
  }
</script>

<h1>Users</h1>
<p class="muted" style="max-width: 75ch">
  Console accounts for signing in to this dashboard. Accounts live in the
  server database (not the config file); every change signs out the affected
  account's sessions immediately. Click a row to edit the account.
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
        <label>
          <span>First Name</span>
          <input type="text" bind:value={newFirstName} placeholder="Jane" autocomplete="off" />
        </label>
        <label>
          <span>Last Name</span>
          <input type="text" bind:value={newLastName} placeholder="Doe" autocomplete="off" />
        </label>
        <label>
          <span>Email</span>
          <input type="email" bind:value={newEmail} placeholder="jane@example.com" autocomplete="off" />
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
        <tr><th>Name</th><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Created</th></tr>
      </thead>
      <tbody>
        {#each users as user (user.username)}
          <tr class="clickable" role="button" tabindex="0" onclick={() => openEdit(user)} onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openEdit(user); } }}>
            <td>{displayName(user)}</td>
            <td>
              {user.username}
              {#if me && user.username === me.username}<span class="muted"> (you)</span>{/if}
            </td>
            <td class="muted">{user.email || '—'}</td>
            <td>
              <span class="pill">{user.role === 'admin' ? 'Administrator' : 'Read-Only'}</span>
            </td>
            <td>
              <span class="pill" class:ok={user.enabled} class:err={!user.enabled}>
                {user.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </td>
            <td class="muted">{formatDate(user.created_at)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

{#if editUser}
  <div class="modal-backdrop" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) editUser = null; }}>
    <div class="card modal">
      <div class="spread" style="margin-bottom: 4px">
        <h3 style="margin: 0">Edit Account — {editUser.username}</h3>
        <button type="button" class="secondary" style="padding: 2px 10px" onclick={() => (editUser = null)}>✕</button>
      </div>

      <div class="modal-section">
        <h4>Profile</h4>
        <div class="form-grid modal-grid">
          <label>
            <span>First Name</span>
            <input type="text" bind:value={editUser.first_name} autocomplete="off" />
          </label>
          <label>
            <span>Last Name</span>
            <input type="text" bind:value={editUser.last_name} autocomplete="off" />
          </label>
        </div>
        <label>
          <span>Email</span>
          <input type="email" bind:value={editUser.email} autocomplete="off" />
        </label>
      </div>

      <div class="modal-section">
        <h4>Account</h4>
        <div class="form-grid modal-grid">
          <label>
            <span>Role</span>
            <select bind:value={editUser.role} disabled={editSaving || isLastAdmin(editUser)} title={isLastAdmin(editUser) ? 'The last enabled admin cannot be changed' : undefined}>
              <option value="admin">Administrator</option>
              <option value="viewer">Read-Only</option>
            </select>
          </label>
          <label class="checkbox-row">
            <input type="checkbox" bind:checked={editUser.enabled} disabled={editSaving || isLastAdmin(editUser)} />
            <span>Account enabled</span>
          </label>
        </div>
      </div>

      <form class="modal-section" onsubmit={saveReset}>
        <h4>Reset Password</h4>
        <p class="muted" style="margin-top: 0">
          Applies immediately and signs out this account's sessions.
        </p>
        <input type="password" bind:value={resetPassword} placeholder="New password (at least 8 characters)" autocomplete="new-password" />
        {#if resetError}<div class="form-error">{resetError}</div>{/if}
        <button type="submit" class="secondary" style="margin-top: 8px" disabled={editSaving || !resetPassword}>
          {editSaving ? 'Saving…' : 'Reset Password'}
        </button>
      </form>

      {#if editError}<div class="form-error">{editError}</div>{/if}

      <div class="row" style="margin-top: 4px; justify-content: space-between">
        <div class="row" style="gap: 8px">
          <button type="button" disabled={editSaving} onclick={saveEdit}>Save Changes</button>
          <button type="button" class="secondary" onclick={() => (editUser = null)}>Cancel</button>
        </div>
        {#if !isLastAdmin(editUser)}
          <button type="button" class="danger" disabled={editSaving} onclick={() => remove(editUser)}>Delete Account</button>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-size: 0.8rem; font-weight: 600; }
  tr.clickable { cursor: pointer; }
  tr.clickable:hover td { background: var(--panel-2); }
  .row { display: flex; align-items: center; }
  .form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 140px;
    gap: 12px;
  }
  .modal-grid { grid-template-columns: 1fr 1fr; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  .checkbox-row { flex-direction: row; align-items: center; gap: 8px; margin-top: 18px; }
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
  .modal { width: 460px; }
  .modal h4 {
    margin: 0 0 8px 0;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
  }
  .modal-section {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
  }
</style>
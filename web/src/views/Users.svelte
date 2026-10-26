<script>
  import { api, formatApiError, getStoredUser } from '../api.js';
  import PageHeader from '../PageHeader.svelte';
  import { icons } from '../icons.svelte.js';
  import { formatDateTime } from '../datetime.svelte.js';

  let users = $state([]);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state(null);
  let notice = $state(null);
  // Usernames listed in the config file's [[api.users]]: they are imported
  // again at startup whenever they are missing from the database.
  let configUsers = $state(new Set());

  // Add-user dialog (null when closed).
  let add = $state(null);
  let addError = $state(null);

  // Edit dialog: a draft copy of the selected user, and a pristine copy for
  // change detection.
  let editUser = $state(null);
  let editOriginal = $state(null);
  let editError = $state(null);
  let editSaving = $state(false);
  // Reset-password section inside the edit dialog.
  let resetPassword = $state('');
  let resetError = $state(null);
  let resetNotice = $state(null);

  const me = getStoredUser();
  const MIN_PASSWORD = 8;

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

  async function loadConfigUsers() {
    try {
      const cfg = await api.config();
      configUsers = new Set((cfg?.api?.users || []).map((u) => u.username));
    } catch (_) {
      /* the note is a nicety; the page works without it */
    }
  }

  $effect(() => {
    load();
    loadConfigUsers();
  });

  function isMe(user) {
    return !!me && user?.username === me.username;
  }

  function fromConfig(user) {
    return configUsers.has(user.username);
  }

  // Username rules match the server: 1-64 characters, no spaces.
  function usernameProblem(name) {
    if (!name) return 'Enter a username.';
    if (/\s/.test(name)) return 'Usernames cannot contain spaces.';
    if (name.length > 64) return 'Usernames can be at most 64 characters.';
    if (users.some((u) => u.username === name)) return `There is already an account named '${name}'.`;
    return null;
  }

  function openAdd() {
    notice = null;
    addError = null;
    add = { username: '', password: '', role: 'admin', first_name: '', last_name: '', email: '' };
  }

  function closeAdd() {
    if (!busy) add = null;
  }

  async function createUser(e) {
    e.preventDefault();
    addError = usernameProblem(add.username.trim());
    if (!addError && add.password.length < MIN_PASSWORD) {
      addError = `The password must be at least ${MIN_PASSWORD} characters.`;
    }
    if (addError) return;
    busy = true;
    try {
      const username = add.username.trim();
      await api.createUser({
        username,
        password: add.password,
        role: add.role,
        first_name: add.first_name.trim(),
        last_name: add.last_name.trim(),
        email: add.email.trim(),
      });
      notice = `Account '${username}' created. They can sign in now.`;
      add = null;
      await load();
    } catch (err) {
      addError = formatApiError(err);
    } finally {
      busy = false;
    }
  }

  function openEdit(user) {
    notice = null;
    // `user` is a $state proxy, which structuredClone cannot copy; take a
    // plain snapshot instead.
    editOriginal = $state.snapshot(user);
    editUser = $state.snapshot(user);
    editError = null;
    resetPassword = '';
    resetError = null;
    resetNotice = null;
  }

  function closeEdit() {
    if (!editSaving) editUser = null;
  }

  async function saveEdit() {
    editError = null;
    const payload = {};
    for (const key of ['first_name', 'last_name', 'email']) {
      if (editUser[key].trim() !== editOriginal[key]) payload[key] = editUser[key].trim();
    }
    if (editUser.role !== editOriginal.role) payload.role = editUser.role;
    if (editUser.enabled !== editOriginal.enabled) payload.enabled = editUser.enabled;
    if (Object.keys(payload).length === 0) {
      editUser = null;
      return;
    }
    editSaving = true;
    try {
      await api.updateUser(editUser.username, payload);
      const signedOut = 'role' in payload || 'enabled' in payload;
      notice = `Account '${editUser.username}' updated.${signedOut ? ' Its sessions were signed out so the change applies now.' : ''}`;
      editUser = null;
      await load();
    } catch (err) {
      editError = formatApiError(err);
    } finally {
      editSaving = false;
    }
  }

  // Stays in the dialog (with a confirmation) so unsaved profile edits are
  // not thrown away.
  async function saveReset(e) {
    e.preventDefault();
    resetError = null;
    resetNotice = null;
    if (resetPassword.length < MIN_PASSWORD) {
      resetError = `The password must be at least ${MIN_PASSWORD} characters.`;
      return;
    }
    editSaving = true;
    try {
      await api.updateUser(editUser.username, { password: resetPassword });
      resetNotice = `Password reset. ${editUser.username}'s sessions were signed out; give them the new password.`;
      resetPassword = '';
    } catch (err) {
      resetError = formatApiError(err);
    } finally {
      editSaving = false;
    }
  }

  // For an account that lost its authenticator app and recovery codes.
  async function resetTwoFactor() {
    if (!confirm(`Turn off two-factor login for '${editUser.username}'? They sign in with their password alone until they set it up again, and their sessions are signed out.`)) return;
    resetError = null;
    resetNotice = null;
    editSaving = true;
    try {
      await api.resetUserTwoFactor(editUser.username);
      editUser.two_factor = false;
      editOriginal.two_factor = false;
      resetNotice = `Two-factor login turned off for ${editUser.username}.`;
      await load();
    } catch (err) {
      resetError = formatApiError(err);
    } finally {
      editSaving = false;
    }
  }

  async function remove(user) {
    const again = fromConfig(user)
      ? `\n\nThis account is also listed in daygle-dns.toml, so it will be created again (with its old password) at the next restart unless you remove it there too.`
      : '';
    if (!confirm(`Delete account '${user.username}'? Their sessions are signed out.${again}`)) return;
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

  // The last enabled admin cannot be demoted or disabled; lock those
  // controls so the UI matches what the server will accept.
  function isLastAdmin(user) {
    const admins = users.filter((u) => u.role === 'admin' && u.enabled);
    return user.role === 'admin' && user.enabled && admins.length <= 1;
  }

  // Role and status are locked for the last admin and for your own account
  // (changing them would sign you out mid-edit, or lock you out).
  function lockReason(user) {
    if (isMe(user)) return 'You cannot change your own role or disable your own account. Ask another administrator.';
    if (isLastAdmin(editOriginal)) return 'This is the only enabled administrator, so its role and status cannot change.';
    return null;
  }

  function roleLabel(role) {
    return role === 'admin' ? 'Administrator' : 'Read-Only';
  }

  function displayName(user) {
    const name = `${(user.first_name || '').trim()} ${(user.last_name || '').trim()}`.trim();
    return name || '-';
  }
</script>

<PageHeader
  icon={icons.users}
  title="Users"
  tagline="Accounts that can sign in to this console. Administrators can change everything; Read-Only accounts can view the console but change nothing except their own password and preferences."
/>

{#if notice}
  <div class="card" style="border-color: var(--ok); margin-bottom: 14px">{notice}</div>
{/if}
{#if error}
  <div class="card" style="border-color: var(--danger); color: var(--danger); margin-bottom: 14px">{error}</div>
{/if}

<div class="card">
  <div class="spread" style="margin-bottom: 10px">
    <h3 style="margin: 0">Accounts ({users.length})</h3>
    <button onclick={openAdd}>Add User</button>
  </div>

  {#if loading}
    <p class="muted">Loading...</p>
  {:else if users.length === 0}
    <p class="muted">No accounts yet.</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Username</th><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Two-Factor</th><th>Created</th><th>Last Login</th><th class="num">Actions</th></tr>
        </thead>
        <tbody>
          {#each users as user (user.username)}
            <tr class="clickable" class:disabled={!user.enabled} onclick={() => openEdit(user)}>
              <td>
                <strong>{user.username}</strong>
                {#if isMe(user)}<span class="pill you">You</span>{/if}
                {#if fromConfig(user)}<span class="pill" title="Also listed in daygle-dns.toml">Config File</span>{/if}
              </td>
              <td>{displayName(user)}</td>
              <td class="muted">{user.email || '-'}</td>
              <td><span class="pill" class:admin={user.role === 'admin'}>{roleLabel(user.role)}</span></td>
              <td>
                <span class="pill" class:ok={user.enabled}>{user.enabled ? 'Enabled' : 'Disabled'}</span>
              </td>
              <td><span class="pill" class:ok={user.two_factor}>{user.two_factor ? 'On' : 'Off'}</span></td>
              <td class="muted nowrap" title={user.created_at || ''}>{formatDateTime(user.created_at)}</td>
              <td class="muted nowrap" title={user.last_login_at || ''}>{user.last_login_at ? formatDateTime(user.last_login_at) : 'Never'}</td>
              <td class="num">
                <button class="secondary" onclick={(e) => { e.stopPropagation(); openEdit(user); }}>Edit</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  <p class="muted help">
    Changing an account's role, disabling it or resetting its password signs
    out its sessions straight away. To change your own password, use the
    <strong>Account</strong> page (below your name in the sidebar).
  </p>
</div>

{#if add}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeAdd()}>
    <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="add-user-title">
      <form onsubmit={createUser}>
        <div class="spread modal-title">
          <h3 id="add-user-title" style="margin: 0">Add User</h3>
          <button type="button" class="secondary" style="padding: 2px 10px" onclick={closeAdd} aria-label="Close">✕</button>
        </div>
        {#if addError}<p class="dialog-error">{addError}</p>{/if}

        <div class="section-title">Sign-In</div>
        <div class="grid2">
          <label>
            <span>Username</span>
            <input type="text" bind:value={add.username} placeholder="jane" autocomplete="off" spellcheck="false" />
          </label>
          <label>
            <span>Password</span>
            <input type="password" bind:value={add.password} placeholder="At least {MIN_PASSWORD} characters" autocomplete="new-password" />
          </label>
        </div>
        <label class="full">
          <span>Role</span>
          <select bind:value={add.role}>
            <option value="admin">Administrator - can change everything</option>
            <option value="viewer">Read-Only - can view but not change</option>
          </select>
        </label>

        <div class="section-title">Profile (Optional)</div>
        <div class="grid2">
          <label>
            <span>First Name</span>
            <input type="text" bind:value={add.first_name} placeholder="Jane" autocomplete="off" />
          </label>
          <label>
            <span>Last Name</span>
            <input type="text" bind:value={add.last_name} placeholder="Doe" autocomplete="off" />
          </label>
        </div>
        <label class="full">
          <span>Email</span>
          <input type="email" bind:value={add.email} placeholder="jane@example.com" autocomplete="off" />
        </label>

        <div class="row actions">
          <button type="submit" disabled={busy || !add.username.trim() || !add.password}>{busy ? 'Creating...' : 'Create Account'}</button>
          <button type="button" class="secondary" onclick={closeAdd} disabled={busy}>Cancel</button>
        </div>
      </form>
    </div>
  </div>
{/if}

{#if editUser}
  {@const locked = lockReason(editUser)}
  <div class="modal-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeEdit()}>
    <div class="card modal" role="dialog" aria-modal="true" aria-labelledby="edit-user-title">
      <div class="spread modal-title">
        <h3 id="edit-user-title" style="margin: 0">Edit Account - {editUser.username}</h3>
        <button type="button" class="secondary" style="padding: 2px 10px" onclick={closeEdit} aria-label="Close">✕</button>
      </div>
      {#if editError}<p class="dialog-error">{editError}</p>{/if}

      <div class="section-title">Profile</div>
      <div class="grid2">
        <label>
          <span>First Name</span>
          <input type="text" bind:value={editUser.first_name} autocomplete="off" />
        </label>
        <label>
          <span>Last Name</span>
          <input type="text" bind:value={editUser.last_name} autocomplete="off" />
        </label>
      </div>
      <label class="full">
        <span>Email</span>
        <input type="email" bind:value={editUser.email} autocomplete="off" />
      </label>

      <div class="section-title">Access</div>
      <div class="grid2">
        <label>
          <span>Role</span>
          <select bind:value={editUser.role} disabled={editSaving || !!locked}>
            <option value="admin">Administrator</option>
            <option value="viewer">Read-Only</option>
          </select>
        </label>
        <label class="checkbox-row">
          <input type="checkbox" bind:checked={editUser.enabled} disabled={editSaving || !!locked} />
          <span>Account Enabled</span>
        </label>
      </div>
      {#if locked}
        <p class="muted help">{locked}</p>
      {:else}
        <p class="muted help">A disabled account keeps its settings but cannot sign in.</p>
      {/if}

      <div class="section-title">Reset Password</div>
      {#if isMe(editUser)}
        <p class="muted help">
          Use the Password tab of your <strong>Account</strong> page; it asks
          for your current password and keeps this session signed in.
        </p>
      {:else}
        <form class="reset" onsubmit={saveReset}>
          <input type="password" bind:value={resetPassword} placeholder="New password (at least {MIN_PASSWORD} characters)" autocomplete="new-password" aria-label="New password" />
          <button type="submit" class="secondary" disabled={editSaving || !resetPassword}>Reset Password</button>
        </form>
        {#if resetError}<p class="dialog-error" style="margin-top: 8px">{resetError}</p>{/if}
        {#if resetNotice}<p class="reset-ok">{resetNotice}</p>{/if}
        <p class="muted help">Applies immediately and signs out this account's sessions.</p>
      {/if}

      <div class="section-title">Two-Factor Login</div>
      {#if isMe(editUser)}
        <p class="muted help">
          Use the Two-Factor Login tab of your <strong>Account</strong> page.
        </p>
      {:else if editUser.two_factor}
        <div class="row" style="gap: 10px; align-items: center">
          <span class="pill ok">On</span>
          <button type="button" class="secondary" disabled={editSaving} onclick={resetTwoFactor}>Reset Two-Factor Login</button>
        </div>
        <p class="muted help">
          For someone who lost their phone and their recovery codes: they sign in
          with their password alone until they set it up again.
        </p>
      {:else}
        <p class="muted help">
          Off. Each person turns it on for their own account, on their
          <strong>Account</strong> page.
        </p>
      {/if}

      <div class="row actions" style="justify-content: space-between">
        <div class="row" style="gap: 8px">
          <button type="button" disabled={editSaving} onclick={saveEdit}>{editSaving ? 'Saving...' : 'Save Changes'}</button>
          <button type="button" class="secondary" onclick={closeEdit} disabled={editSaving}>Cancel</button>
        </div>
        {#if !isLastAdmin(editOriginal) && !isMe(editUser)}
          <button type="button" class="danger" disabled={editSaving || busy} onclick={() => remove(editUser)}>Delete Account</button>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  tr.clickable { cursor: pointer; }
  tr.clickable:hover td { background: var(--panel-2); }
  .nowrap { white-space: nowrap; }
  .pill.you { border-color: var(--accent); color: var(--accent); }
  .pill.admin { border-color: var(--accent); }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; }
  label span { color: var(--muted); }
  .full { margin-top: 10px; }
  .checkbox-row { flex-direction: row; align-items: center; gap: 8px; padding-top: 22px; }
  .checkbox-row input { width: auto; }
  .checkbox-row span { color: var(--text); }
  .reset { display: flex; gap: 8px; }
  .reset input { flex: 1; }
  .reset-ok { color: var(--ok); margin: 8px 0 0; font-size: 0.85rem; }
  .dialog-error { color: var(--danger); margin: 0 0 10px; }
  .modal-backdrop { position: fixed; inset: 0; background: rgb(0 0 0 / 0.65); display: grid; place-items: center; padding: 20px; z-index: 10; }
  .modal { width: min(560px, 100%); max-height: calc(100vh - 40px); overflow: auto; }
  .modal-title { margin-bottom: 12px; }
  .section-title {
    margin: 14px 0 8px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
  }
  .actions { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border); }
  @media (max-width: 640px) {
    .grid2 { grid-template-columns: 1fr; }
    .checkbox-row { padding-top: 0; }
  }
</style>
